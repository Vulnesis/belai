package harnessrun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/x/ansi"

	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/harness"
	"github.com/vulnetix/belai/internal/harnesstail"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/sessionsync"
	"github.com/vulnetix/belai/internal/vaultenv"
)

// Mirror is the session mirror (factorylink.SyncBackend): registration,
// entries, the inbox and its acks.
type Mirror interface {
	PutSessionControls(ctx context.Context, sessionID string, m sessionsync.SessionMeta) (int64, sessionsync.Controls, error)
	HeartbeatControls(ctx context.Context, sessionID string) (sessionsync.Controls, error)
	PostEntries(ctx context.Context, sessionID string, entries []sessionsync.Entry) (int64, error)
	EndWith(ctx context.Context, sessionID string, info sessionsync.EndInfo) error
	InboxBatchA2A(ctx context.Context, hostID, sessionID string, wait time.Duration, a2aAfter int64) (sessionsync.Inbox, error)
	Ack(ctx context.Context, promptID, status, reason, entryID string) error
	AckAnswer(ctx context.Context, answerID, status, reason, entryID string) error
	AckCommand(ctx context.Context, commandID, status, reason string, state json.RawMessage) error
}

// Origins of a typed prompt.
const (
	OriginDispatch = "dispatch"
	OriginWeb      = "web"
	OriginNotice   = "harness:a2a-notice"
)

// NoticeLine is what the session types when a peer message waits. It holds
// no peer text: the harness reads the message through its belai inbox tool.
const NoticeLine = "[belai] 1 peer message waiting. Call the belai inbox tool to read it."

// Config is one harness session.
type Config struct {
	SessionID, DispatchID string
	Harness               harness.Harness
	// Bin is the resolved absolute binary; Version its probed version line.
	Bin, Version string
	Cwd, Home    string
	Mode, Model  string
	// Resume is a native session id to resume.
	Resume string
	// Prompt is the first prompt (from the dispatch), "" for none.
	Prompt string
	Name   string
	HostID string
	Mirror Mirror
	// Controls: the daemon runs with --web-controls, so stop, interrupt and
	// keys are taken from the inbox.
	Controls bool
	// RemotePrompts is sync.remote_prompts.
	RemotePrompts bool
	// Admit classifies a prompt before it is typed: the dispatch prompt, a
	// remote prompt and an answer, through the host's security classifier and
	// posture, the same admission a belai session gives a cloud or Keleustes
	// prompt. It returns the verdict label, or an error that refuses the
	// prompt. Nil refuses every prompt (no classifier, fail closed). The
	// harness-composed notice line is not classified: it holds no remote text.
	Admit func(ctx context.Context, text string) (string, error)
	// Stopped is the factory kill switch.
	Stopped func() (bool, string)
	// Audit defaults to audit.Emit.
	Audit func(audit.Fact)
	// A2A is the session's A2A endpoint, nil when A2A is off.
	A2A A2A
	// KeyMode and Grant decide the vault key hand-off (keys.go).
	KeyMode string
	Grant   Grant
	// Exe is the belai binary the bridge and hook commands run.
	Exe string
	// Dir holds the per-session files (0700, removed at the end); Ledger
	// maps entry indexes to native offsets and is kept.
	Dir, Ledger string
	SQLite      string
	Start       Starter
	Timings     Timings
	// BaseEnv defaults to belai's scrubbed tool environment.
	BaseEnv []string
	Log     io.Writer
	// ConfirmWait bounds the wait for a typed prompt's native entry (15 s),
	// Poll the kill switch and tail polls (1 s).
	ConfirmWait, Poll time.Duration
	// OnStart, when set, is called once the session exists (to attach A2A).
	OnStart func(*Session)
	// TimingFile, when set, gets one startup sample per session (detection
	// reads it for the advert's p50/p95).
	TimingFile string
	// Screen, when set, streams the terminal to Keleustes (Screen.Stream).
	Screen ScreenOpener
}

func (c *Config) defaults() {
	if c.Audit == nil {
		c.Audit = audit.Emit
	}
	if c.Stopped == nil {
		c.Stopped = func() (bool, string) { return false, "" }
	}
	if c.Admit == nil {
		c.Admit = func(context.Context, string) (string, error) {
			return "", errors.New("no security classifier is available on this host")
		}
	}
	if c.Timings == (Timings{}) {
		c.Timings = DefaultTimings
	}
	if c.ConfirmWait == 0 {
		c.ConfirmWait = 15 * time.Second
	}
	if c.Poll == 0 {
		c.Poll = time.Second
	}
	if c.Log == nil {
		c.Log = io.Discard
	}
	if c.KeyMode == "" {
		c.KeyMode = KeysOwnLogin
	}
}

type queued struct {
	id, text, origin string
}

// Session is one running harness session.
type Session struct {
	c         Config
	l         *harness.Launch
	r         *Runner
	native    string
	sock      string
	located_  atomic.Value // the native id found by locate
	nativeSrc atomic.Bool
	located   chan struct{}
	locOnce   sync.Once
	wiring    Wiring
	handoff   Handoff

	mu      sync.Mutex
	next    int64
	pending []sessionsync.Entry
	ledger  *os.File

	prompts  chan queued
	busy     atomic.Bool
	typedAt  atomic.Int64
	turnEnd  chan struct{}
	userSeen chan string
	stopOnce sync.Once
	reason   atomic.Value
	inTok    atomic.Int64
	outTok   atomic.Int64
	bridge   *bridge
	dialogs  dialogWatch
	hard     hardening
	started  time.Time
	usageMu  sync.Mutex
	seenMsg  map[string]bool
	model    string
}

// Run runs the session until the harness exits, a stop arrives, the kill
// switch turns on or ctx ends. Every step is audited and mirrored.
func Run(ctx context.Context, c Config) error {
	c.defaults()
	s := &Session{c: c, l: c.Harness.Launch, started: time.Now(), prompts: make(chan queued, 64), turnEnd: make(chan struct{}, 1),
		userSeen: make(chan string, 16), located: make(chan struct{})}
	if !s.l.Launchable() {
		return s.refuse(ctx, "this harness has no verified launch profile")
	}
	if err := s.l.VersionOK(c.Version); err != nil {
		return s.refuse(ctx, err.Error())
	}
	if !ValidKeyMode(c.KeyMode) {
		return s.refuse(ctx, "unknown key mode")
	}
	if stopped, why := c.Stopped(); stopped {
		if c.Grant != nil {
			c.Grant.Drop()
		}
		return s.refuse(ctx, "factory stopped: "+why)
	}
	switch {
	case c.Resume != "":
		if !harness.NativeIDShape.MatchString(c.Resume) {
			return s.refuse(ctx, "the resume id has the wrong shape")
		}
		s.native = c.Resume
	case s.l.NativeID == harness.NativeUUID:
		id, err := NewUUID()
		if err != nil {
			return err
		}
		s.native = id
	}
	if err := s.openLedger(); err != nil {
		return err
	}
	defer s.ledger.Close()
	defer os.RemoveAll(c.Dir)

	sock, sockCleanup, err := sockPath(c.Dir)
	if err != nil {
		return err
	}
	defer sockCleanup()
	s.sock = sock
	w, err := Wire(s.l, c.Dir, c.Exe, sock, c.A2A != nil)
	if err != nil {
		fmt.Fprintln(c.Log, "rc-harness: A2A bridge not wired:", err)
		w, err = Wire(s.l, c.Dir, c.Exe, sock, false)
		if err != nil {
			return err
		}
	}
	s.wiring = w
	s.bridge = newBridge(s, c.A2A)
	if c.OnStart != nil {
		c.OnStart(s)
	}
	ln, err := s.bridge.listen(sock)
	if err != nil {
		return err
	}
	defer ln.Close()

	stopped, _ := c.Stopped()
	h, err := HandOff(c.KeyMode, c.Grant, s.l, stopped, time.Now())
	if err != nil {
		return s.refuse(ctx, err.Error())
	}
	s.handoff = h
	if c.Grant != nil {
		// The harness's env cannot be revoked: the session ends with the grant.
		if exp := c.Grant.Expires(); !exp.IsZero() && len(h.Env) > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(ctx, exp)
			defer cancel()
		}
	}

	if why := s.preContinuity(); why != "" {
		return s.refuse(ctx, why)
	}
	thread := "kls-" + c.SessionID[:min(8, len(c.SessionID))]
	argv, err := s.l.Build(harness.Values{Bin: c.Bin, NativeID: s.native, Model: c.Model, Cwd: c.Cwd, Sid: c.SessionID, ThreadName: thread,
		Mode: c.Mode, Resume: c.Resume != "", MCPFile: w.MCPFile, MCPJSON: w.MCPJSON, MCPCmd: w.MCPCmd, SettingsFile: w.SettingsFile})
	if err != nil {
		return s.refuse(ctx, err.Error())
	}
	env := Env(c.BaseEnv, c.Bin, sock, append(append([]string{}, w.Env...), h.Env...))

	if _, _, err := c.Mirror.PutSessionControls(ctx, c.SessionID, s.meta()); err != nil {
		fmt.Fprintln(c.Log, "rc-harness: register:", err)
	}
	s.own("system", "harness_start", s.startLine(), s.startMeta(argv))
	s.audit("started", "", map[string]string{"profile": c.Harness.ID, "reason": c.KeyMode})
	if len(h.Names) > 0 {
		s.own("system", "harness_keys", "vault keys handed to the harness: "+strings.Join(h.Names, ", "),
			map[string]any{"keyMode": c.KeyMode, "grantId": h.GrantID, "env": h.Names, "dropped": h.Dropped})
		s.audit("key_handoff", "", map[string]string{"reason": c.KeyMode, "id": h.GrantID, "list": strings.Join(h.Names, "+")})
	}

	s.hard.verifiedCh = make(chan struct{})
	s.hard.gitStart = gitState(c.Cwd)
	s.hard.spawn = time.Now()
	r, err := StartRunner(c.Start, Spawn{Argv: argv, Dir: c.Cwd, Env: env, Cols: 120, Rows: 40}, s.l, c.Timings)
	// The child holds its copy; this process forgets the values.
	for i := range h.Env {
		h.Env[i] = ""
	}
	if c.Grant != nil {
		c.Grant.Drop()
	}
	if err != nil {
		return s.refuse(ctx, "could not start the harness: "+err.Error())
	}
	s.r = r
	fmt.Fprintf(c.Log, "rc-harness: %s pid %d\n", c.Harness.ID, r.PID())

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.flushLoop(runCtx)
	go s.tail(runCtx)
	go s.inbox(runCtx)
	go s.killSwitch(runCtx)
	go s.heartbeat(runCtx)
	go s.typer(runCtx)
	go s.watchDialogs(runCtx)
	go s.watchFirstOutput(runCtx)
	if c.Screen != nil {
		go s.serveScreen(runCtx, c.Screen)
	}
	if c.Prompt != "" {
		s.prompts <- queued{text: c.Prompt, origin: OriginDispatch}
		s.audit("prompt_queued", "", map[string]string{"id": hash(c.Prompt), "from": OriginDispatch})
	}
	select {
	case <-r.Done():
		s.setReason("harness exited")
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			s.stop("vault grant expired")
		} else {
			s.stop("stopped")
		}
	}
	<-r.Done()
	cancel()
	return s.end()
}

func (s *Session) refuse(ctx context.Context, why string) error {
	s.audit("refused", why, nil)
	if s.c.Mirror != nil {
		_, _, _ = s.c.Mirror.PutSessionControls(ctx, s.c.SessionID, s.meta())
		if s.ledger != nil || s.openLedger() == nil {
			s.own("error", "harness_refused", why, nil)
			s.flush(ctx)
		}
		_ = s.c.Mirror.EndWith(context.WithoutCancel(ctx), s.c.SessionID, sessionsync.EndInfo{Reason: "refused", Error: why})
	}
	return errors.New(why)
}

func (s *Session) meta() sessionsync.SessionMeta {
	name := s.c.Name
	if name == "" {
		name = s.c.Harness.Name
	}
	return sessionsync.SessionMeta{HostID: s.c.HostID, Cwd: s.c.Cwd, Name: name, Model: s.c.Model, Provider: s.c.Harness.ID,
		Mode: s.c.Mode, DispatchID: s.c.DispatchID, RemotePrompts: s.c.RemotePrompts, RemoteAnswers: s.c.Controls, Controls: s.c.Controls,
		CreatedAt: time.Now().UnixMilli(), Harness: s.c.Harness.ID, HarnessVersion: s.c.Version,
		HarnessSessionID: s.nativeID(), TranscriptSource: s.transcriptSource()}
}

func (s *Session) nativeID() string {
	if s.native != "" {
		return s.native
	}
	id, _ := s.located_.Load().(string)
	return id
}

func (s *Session) transcriptSource() string {
	select {
	case <-s.located:
		if s.nativeSrc.Load() {
			return "native"
		}
		return "screen"
	default:
		return ""
	}
}

func (s *Session) startLine() string {
	v := s.c.Version
	if v == "" {
		v = "version unknown"
	}
	return fmt.Sprintf("%s (%s) started in its own terminal; %s rules apply", s.c.Harness.Name, v, s.c.Harness.Name)
}

// startMeta is the start's provenance: the harness, its version and binary,
// the argv with the model reduced to its shape, the key mode and names.
func (s *Session) startMeta(argv []string) map[string]any {
	red := make([]string, len(argv))
	for i, a := range argv {
		red[i] = a
		if s.c.Model != "" && a == s.c.Model {
			red[i] = "{model}"
		}
		if s.wiring.MCPJSON != "" && a == s.wiring.MCPJSON {
			red[i] = "{mcp_json}"
		}
	}
	return map[string]any{"harness": s.c.Harness.ID, "version": s.c.Version, "bin": s.c.Bin, "argv": red,
		"nativeId": s.native, "mode": s.c.Mode, "a2a": s.wiring.A2A, "keyMode": s.c.KeyMode, "keyNames": s.handoff.Names,
		"grantId": s.handoff.GrantID, "dispatchId": s.c.DispatchID, "resume": s.c.Resume}
}

func (s *Session) audit(status, reason string, data map[string]string) {
	d := map[string]string{"dispatch": "harness", "status": status, "kind": s.c.Harness.ID}
	if reason != "" {
		d["reason"] = sanitize.Line(reason, 200)
	}
	for k, v := range data {
		d[k] = v
	}
	s.c.Audit(audit.Fact{Kind: audit.HostDispatch, ActorKind: audit.ActorHarness, Actor: s.c.Harness.ID,
		SessionID: s.c.SessionID, Outcome: status, Data: d})
}

// ---- ledger and mirror --------------------------------------------------

func (s *Session) openLedger() error {
	if s.c.Ledger == "" {
		s.c.Ledger = filepath.Join(s.c.Dir+".ledger", "ledger.jsonl")
	}
	if err := os.MkdirAll(filepath.Dir(s.c.Ledger), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.c.Ledger, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	data, _ := io.ReadAll(f)
	s.next = int64(strings.Count(string(data), "\n"))
	s.ledger = f
	return nil
}

// add records one entry: its ledger line first (so indexes survive a
// restart), then the pending upload. Text is scrubbed of every concealed
// value before it leaves this process.
func (s *Session) add(typ, id, text string, at time.Time, meta map[string]any, ledger map[string]any) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.next
	s.next++
	ledger["i"] = i
	if b, err := json.Marshal(ledger); err == nil {
		_, _ = s.ledger.Write(append(b, '\n'))
	}
	mb, _ := json.Marshal(meta)
	if at.IsZero() {
		at = time.Now()
	}
	s.pending = append(s.pending, sessionsync.Entry{Seq: i, ID: id, Type: typ, Role: roleOf(typ),
		Content: vaultenv.Default.Scrub(text), Timestamp: at.UnixMilli(), Meta: vaultenv.Default.ScrubBytes(mb)})
	return i
}

func roleOf(typ string) string {
	switch typ {
	case "user", "assistant":
		return typ
	}
	return ""
}

// own is a harness-composed line (start, refusal, key, A2A, snapshot).
func (s *Session) own(typ, kind, text string, meta map[string]any) int64 {
	if meta == nil {
		meta = map[string]any{}
	}
	meta["harness"], meta["own"] = s.c.Harness.ID, kind
	return s.add(typ, kind, text, time.Time{}, meta, map[string]any{"src": "own", "type": kind, "text": sanitize.Line(text, 300)})
}

func (s *Session) native_(e harnesstail.Event) int64 {
	meta := map[string]any{"harness": s.c.Harness.ID, "native": map[string]any{"type": e.NativeType, "id": e.NativeID, "off": e.Off}}
	if e.Tool != "" {
		meta["tool"], meta["toolArgs"] = e.Tool, e.ToolArgs
	}
	if e.Subagent {
		meta["subagent"] = true
	}
	i := s.add(e.Role, e.NativeID, e.Text, e.At, meta, map[string]any{"src": "native", "off": e.Off, "len": e.Len})
	s.usage(e)
	return i
}

func (s *Session) flush(ctx context.Context) {
	s.mu.Lock()
	batch := s.pending
	s.pending = nil
	s.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	for attempt := 0; attempt < 3; attempt++ {
		if _, err := s.c.Mirror.PostEntries(ctx, s.c.SessionID, batch); err == nil {
			return
		} else if errors.Is(err, sessionsync.ErrNotFound) {
			_, _, _ = s.c.Mirror.PutSessionControls(ctx, s.c.SessionID, s.meta())
		}
		time.Sleep(200 * time.Millisecond)
	}
	s.mu.Lock()
	s.pending = append(batch, s.pending...)
	s.mu.Unlock()
}

func (s *Session) flushLoop(ctx context.Context) {
	t := time.NewTicker(300 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.flush(ctx)
		}
	}
}

func (s *Session) heartbeat(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = s.c.Mirror.HeartbeatControls(ctx, s.c.SessionID)
		}
	}
}

func (s *Session) end() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ex := s.r.Exit()
	if ex.Code != 0 || !s.nativeSrc.Load() {
		// The last screen says why it ended when no transcript does.
		s.own("system", "harness_snapshot", s.screenNow(), nil)
	}
	reason, _ := s.reason.Load().(string)
	if reason == "" {
		reason = "harness exited"
	}
	if od := s.dialogs.open(); od != nil {
		// A live ask cannot be answered once its harness is gone.
		s.own("ask_answer", "harness_dialog", "expired", map[string]any{"ask_id": od.askID, "decision": "expired", "dialog": od.d.ID})
	}
	verified := s.groupGone()
	adapterErr, empty := s.outcome()
	if adapterErr != "" && (reason == "harness exited" || reason == "stopped by the owner") {
		reason = adapterErr
	}
	if empty {
		s.own("system", "harness_empty", "the session left no reply and no change in the work tree", map[string]any{"warning": "empty_result"})
		s.audit("empty_result", "", nil)
	}
	s.hard.mu.Lock()
	timing := s.hard.timing
	timing.WallMS = time.Since(s.hard.spawn).Milliseconds()
	s.hard.mu.Unlock()
	if timing.StartupMS > 0 {
		AppendTiming(s.c.TimingFile, TimingSample{Harness: s.c.Harness.ID, StartupMS: timing.StartupMS, ReadyMS: timing.ReadyMS, At: time.Now().UnixMilli()})
	}
	term := "verified"
	if !verified {
		term = "unverified"
	}
	s.own("system", "harness_end", fmt.Sprintf("%s ended: %s (exit %d%s; termination %s)", s.c.Harness.Name, reason, ex.Code, sigText(ex.Signal), term),
		// Timing and the end facts travel on SessionEnd (EndInfo.Harness).
		map[string]any{"exit": ex, "reason": reason, "usage": map[string]int64{"input": s.inTok.Load(), "output": s.outTok.Load()}})
	s.audit("stopped", reason, map[string]string{"exit": strconv.Itoa(ex.Code), "state": term})
	s.flush(ctx)
	code := ex.Code
	return s.c.Mirror.EndWith(ctx, s.c.SessionID, sessionsync.EndInfo{Reason: reason, ExitCode: &code,
		Harness: &sessionsync.HarnessEnd{TerminationVerified: verified, EmptyResult: empty, AdapterError: adapterErr != "",
			StartupMS: timing.StartupMS, ReadyMS: timing.ReadyMS, FirstReplyMS: timing.FirstReplyMS, WallMS: timing.WallMS}})
}

func sigText(sig string) string {
	if sig == "" {
		return ""
	}
	return ", " + sig
}

func (s *Session) setReason(r string) { s.reason.CompareAndSwap(nil, r) }

// stop ends the harness with the profile's escalation, once.
func (s *Session) stop(reason string) {
	s.stopOnce.Do(func() {
		s.setReason(reason)
		s.audit("stop", reason, nil)
		go func() {
			steps := s.r.Stop()
			s.audit("stop_steps", reason, map[string]string{"list": strings.Join(steps, "+")})
		}()
	})
}

// ---- kill switch ---------------------------------------------------------

func (s *Session) killSwitch(ctx context.Context) {
	t := time.NewTicker(s.c.Poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if stopped, _ := s.c.Stopped(); stopped {
				s.own("system", "harness_kill", "factory stopped: the harness is being stopped", nil)
				s.stop("factory stopped")
				return
			}
		}
	}
}

// ---- tail ------------------------------------------------------------------

func (s *Session) tail(ctx context.Context) {
	t := s.l.Transcript
	if t == nil {
		s.own("system", "harness_screen", "this harness keeps no transcript belai reads; the screen is the record", nil)
		s.snapshots(ctx)
		return
	}
	// Harnesses write their store on the first prompt (Claude Code's file, a
	// Codex rollout), so the first prompt cannot wait for it: the source is
	// taken as native now and downgraded if the store never appears.
	{
		s.nativeSrc.Store(true)
		s.decided()
	}
	src, err := harnesstail.Locate(ctx, harnesstail.Spec{Transcript: *t, Home: s.c.Home, Cwd: s.c.Cwd, NativeID: s.native,
		Since: time.Now().Add(-2 * time.Second), SQLite: s.c.SQLite, Poll: min(s.c.Poll, 250*time.Millisecond)})
	if err != nil {
		s.nativeSrc.Store(false)
		if ctx.Err() == nil {
			s.own("system", "harness_screen", "the native transcript was not found; the screen is the record", nil)
			s.audit("downgrade", "screen", nil)
			s.snapshots(ctx)
		}
		return
	}
	s.located_.Store(src.SessionID)
	if src.SessionID != "" && t.Locate != "" {
		// A located store names its session itself: evidence for a resume.
		go s.checkContinuity(src.SessionID)
	}
	s.nativeSrc.Store(true)
	s.decided()
	s.reregister(ctx)
	s.own("system", "harness_native", "transcript: "+filepath.Base(src.Path), map[string]any{"nativeId": src.SessionID, "path": src.Path, "dialect": t.Dialect})
	_ = harnesstail.Follow(ctx, src, 0, s.c.SQLite, min(s.c.Poll, 300*time.Millisecond), func(e harnesstail.Event) {
		i := s.native_(e)
		s.noteNative(e)
		if e.Role == "user" {
			select {
			case s.userSeen <- strconv.FormatInt(i, 10) + "\x00" + e.Text:
			default:
			}
		}
		if e.TurnEnd {
			s.idle()
			s.maybeQuestion()
		}
	})
}

// snapshots records the screen as plain text each time a turn ends, for a
// harness with no readable transcript.
func (s *Session) snapshots(ctx context.Context) {
	s.decided()
	s.reregister(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.turnEnd:
			s.own("system", "harness_snapshot", s.screenNow(), nil)
		}
	}
}

// screenText is an approximate plain-text view of the screen's last lines.
func screenText(b []byte, lines int) string {
	if len(b) > 32<<10 {
		b = b[len(b)-32<<10:]
	}
	// TUIs move the cursor right instead of writing spaces.
	text := ansi.Strip(cursorRight.ReplaceAllStringFunc(string(b), func(m string) string {
		n, _ := strconv.Atoi(m[2 : len(m)-1])
		return strings.Repeat(" ", min(max(n, 1), 300))
	}))
	var out []string
	for _, l := range strings.Split(strings.ReplaceAll(text, "\r", "\n"), "\n") {
		if l = strings.TrimRight(l, " \t"); l != "" {
			out = append(out, l)
		}
	}
	if len(out) > lines {
		out = out[len(out)-lines:]
	}
	return sanitize.Text(strings.Join(out, "\n"))
}

func (s *Session) idle() {
	if s.busy.CompareAndSwap(true, false) {
		s.own("turn_state", "turn_state", "", map[string]any{"state": "ended"})
		select {
		case s.turnEnd <- struct{}{}:
		default:
		}
	}
}

// ---- prompts ---------------------------------------------------------------

// waitIdle waits until the harness takes input: no turn running, or the
// screen still for the profile's quiet time.
func (s *Session) waitIdle(ctx context.Context) error {
	quiet := time.Duration(s.l.QuietMS) * time.Millisecond
	if quiet == 0 {
		quiet = 1500 * time.Millisecond
	}
	for {
		s.scanDialogs()
		if s.dialogs.open() != nil || s.settling() {
			// A first-run screen waits on the owner; nothing is typed into it.
		} else if !s.busy.Load() {
			if s.r.Quiet() >= 300*time.Millisecond {
				return nil
			}
		} else if time.Since(time.UnixMilli(s.typedAt.Load())) > 2*time.Second && s.r.Quiet() >= quiet {
			s.idle()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.r.Done():
			return errors.New("the harness has exited")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (s *Session) typer(ctx context.Context) {
	if err := s.r.Ready(ctx); err != nil {
		s.own("error", "harness_ready", "the harness did not become ready: "+err.Error(), nil)
	}
	s.noteReady()
	for {
		select {
		case <-ctx.Done():
			return
		case q := <-s.prompts:
			s.typeOne(ctx, q)
		}
	}
}

func (s *Session) ack(id, status, reason, entry string) {
	if id != "" {
		_ = s.c.Mirror.Ack(context.Background(), id, status, reason, entry)
	}
}

func hash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:8])
}

func (s *Session) typeOne(ctx context.Context, q queued) {
	if stopped, why := s.c.Stopped(); stopped {
		s.ack(q.id, sessionsync.AckRefused, "factory stopped: "+why, "")
		s.audit("prompt_refused", "factory stopped", map[string]string{"id": q.id})
		return
	}
	select {
	case <-s.located:
	case <-ctx.Done():
		return
	}
	if err := s.waitIdle(ctx); err != nil {
		return
	}
	// Drain stale confirmations.
	for len(s.userSeen) > 0 {
		<-s.userSeen
	}
	text := strings.TrimSpace(Neutralise(q.text))
	verdict, ok := s.admit(ctx, q, text)
	if !ok {
		return
	}
	s.typedAt.Store(time.Now().UnixMilli())
	s.busy.Store(true)
	s.own("turn_state", "turn_state", "", map[string]any{"state": "started"})
	if err := s.r.Type(text); err != nil {
		s.busy.Store(false)
		s.ack(q.id, sessionsync.AckRefused, err.Error(), "")
		s.own("error", "harness_prompt", "prompt not typed: "+err.Error(), map[string]any{"origin": q.origin, "promptId": q.id})
		s.audit("prompt_refused", err.Error(), map[string]string{"id": hash(text)})
		return
	}
	s.audit("prompt_typed", "", map[string]string{"id": hash(text), "from": q.origin, "decision": verdict})
	s.noteTyped()
	if !s.nativeSrc.Load() {
		// Nothing to confirm against: the screen is the only record.
		i := s.own("user", "harness_prompt", text, map[string]any{"origin": q.origin, "promptId": q.id, "screen": true})
		s.ack(q.id, sessionsync.AckAccepted, "", strconv.FormatInt(i, 10))
		return
	}
	deadline := time.After(s.c.ConfirmWait)
	for {
		select {
		case <-ctx.Done():
			return
		case <-deadline:
			s.continuityMissed()
			s.ack(q.id, sessionsync.AckRefused, "harness did not take the prompt", "")
			s.own("error", "harness_prompt", "harness did not take the prompt", map[string]any{"origin": q.origin, "promptId": q.id})
			s.audit("prompt_failed", "not confirmed", map[string]string{"id": hash(text)})
			return
		case seen := <-s.userSeen:
			idx, native, _ := strings.Cut(seen, "\x00")
			if !matchPrompt(text, native) {
				continue
			}
			s.ack(q.id, sessionsync.AckAccepted, "", idx)
			s.own("system", "harness_prompt", "typed into the harness ("+q.origin+")",
				map[string]any{"origin": q.origin, "promptId": q.id, "entry": idx})
			return
		}
	}
}

// admit runs the classifier on the text about to be typed. A refusal is
// acked, recorded as an own error line and audited with the text's hash
// only. The notice line is harness text and skips it.
func (s *Session) admit(ctx context.Context, q queued, text string) (string, bool) {
	if q.origin == OriginNotice && text == NoticeLine {
		return "harness", true
	}
	verdict, err := s.c.Admit(ctx, text)
	if err == nil {
		return sanitize.Ident(verdict, 32), true
	}
	if ctx.Err() != nil {
		return "", false
	}
	why := "refused by the security classifier: " + sanitize.Line(err.Error(), 160)
	s.ack(q.id, sessionsync.AckRefused, why, "")
	s.own("error", "harness_prompt", why, map[string]any{"origin": q.origin, "promptId": q.id})
	s.audit("prompt_refused", "classifier", map[string]string{"id": hash(text), "from": q.origin})
	return "", false
}

// Notify queues the peer-message notice line (no peer text).
func (s *Session) notify() {
	if stopped, _ := s.c.Stopped(); stopped {
		return
	}
	select {
	case s.prompts <- queued{text: NoticeLine, origin: OriginNotice}:
	default:
	}
}

// ---- inbox -----------------------------------------------------------------

func (s *Session) inbox(ctx context.Context) {
	for ctx.Err() == nil {
		in, err := s.c.Mirror.InboxBatchA2A(ctx, s.c.HostID, s.c.SessionID, 20*time.Second, -1)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		for _, p := range in.Prompts {
			s.prompt(p)
		}
		for _, a := range in.Answers {
			s.answer(ctx, a)
		}
		for _, c := range in.Commands {
			s.command(ctx, c)
		}
	}
}

func (s *Session) prompt(p sessionsync.RemotePrompt) {
	if !s.c.RemotePrompts {
		s.ack(p.ID, sessionsync.AckRefused, "this host takes no remote prompts (sync.remote_prompts)", "")
		return
	}
	if stopped, why := s.c.Stopped(); stopped {
		s.ack(p.ID, sessionsync.AckRefused, "factory stopped: "+why, "")
		s.audit("prompt_refused", "factory stopped", map[string]string{"id": p.ID})
		return
	}
	text := sessionsync.CleanPrompt(p.Content)
	if _, err := PromptBytes(text, true, s.l.Input); err != nil {
		s.ack(p.ID, sessionsync.AckRefused, err.Error(), "")
		s.audit("prompt_refused", err.Error(), map[string]string{"id": p.ID})
		return
	}
	s.closeQuestion("superseded by a prompt")
	select {
	case s.prompts <- queued{id: p.ID, text: text, origin: OriginWeb}:
		s.audit("prompt_queued", "", map[string]string{"id": p.ID, "from": OriginWeb})
	default:
		s.ack(p.ID, sessionsync.AckRefused, "too many prompts are waiting", "")
	}
}

func (s *Session) command(ctx context.Context, c sessionsync.RemoteCommand) {
	refuse := func(why string) {
		_ = s.c.Mirror.AckCommand(ctx, c.ID, sessionsync.AckRefused, why, nil)
		s.audit("command_refused", why, map[string]string{"id": c.ID})
	}
	if !s.c.Controls {
		refuse("this host runs without --web-controls")
		return
	}
	accept := func(what string) {
		_ = s.c.Mirror.AckCommand(ctx, c.ID, sessionsync.AckAccepted, "", nil)
		s.own("system", "harness_control", what, map[string]any{"commandId": c.ID})
	}
	switch {
	case c.Signal == sessionsync.SignalStop:
		accept("stop")
		s.stop("stopped by the owner")
	case c.Signal == sessionsync.SignalInterrupt:
		if err := s.r.Interrupt(); err != nil {
			refuse(err.Error())
			return
		}
		accept("interrupt")
		s.audit("interrupt", "", nil)
	case c.Key != "":
		if stopped, _ := s.c.Stopped(); stopped {
			refuse("factory stopped")
			return
		}
		if err := s.r.Key(c.Key); err != nil {
			refuse(err.Error())
			return
		}
		accept("key " + sanitize.Ident(c.Key, 16))
		s.audit("key", "", map[string]string{"tool": sanitize.Ident(c.Key, 16)})
	default:
		refuse("a harness session takes stop, interrupt and its own keys only")
	}
}

// Screen attaches a viewer to the harness's terminal (the Screen stream).
func (s *Session) Screen(view func([]byte)) ([]byte, int64, func()) {
	s.audit("screen_attached", "", nil)
	return s.r.Attach(view)
}

// decided marks the transcript source as known (native or screen).
func (s *Session) decided() { s.locOnce.Do(func() { close(s.located) }) }

// reregister upserts the session again once its native id and transcript
// source are known.
func (s *Session) reregister(ctx context.Context) {
	if _, _, err := s.c.Mirror.PutSessionControls(ctx, s.c.SessionID, s.meta()); err != nil {
		fmt.Fprintln(s.c.Log, "rc-harness: register:", err)
	}
}

var cursorRight = regexp.MustCompile(`\x1b\[[0-9]*C`)
