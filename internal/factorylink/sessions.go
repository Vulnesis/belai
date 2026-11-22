package factorylink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sessionctl"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// SyncBackend mirrors sessions to Keleustes and takes their inboxes from it:
// the sessionsync.Backend over the Sessions service. The Syncer keeps the
// tail, the gates and the order of acks after uploads, so a Keleustes
// session behaves exactly as a website one; this type only maps the calls.
//
// Inbox items are remote, untrusted content. They are handed to the Syncer
// as sessionsync.RemotePrompt, RemoteAnswer and RemoteCommand values, which
// the host admits through the same CleanPrompt, classifier and sessionctl
// paths as a website prompt, answer or control. Nothing here interprets them
// beyond choosing which of the three they are.
type SyncBackend struct {
	c *Client
	// kind is the SessionUpsert kind ("tui", "rc", ...).
	kind string

	mu     sync.Mutex
	meta   map[string]*nodev1.SessionUpsert // last upsert per session
	track  map[string]*tracked              // what the uploaded lines say, per session
	subs   map[string]*inboxSub             // open inbox streams
	owners map[string]string                // inbox item id -> session id
	closed bool
}

var _ sessionsync.Backend = (*SyncBackend)(nil)

// NewSyncBackend builds a backend on c. kind names what runs the sessions
// it mirrors ("tui", "rc", "worker", "acp", "headless").
func NewSyncBackend(c *Client, kind string) *SyncBackend {
	return &SyncBackend{c: c, kind: kind, meta: map[string]*nodev1.SessionUpsert{}, track: map[string]*tracked{},
		subs: map[string]*inboxSub{}, owners: map[string]string{}}
}

// Close stops every inbox stream and drops the connection.
func (b *SyncBackend) Close() error {
	b.mu.Lock()
	b.closed = true
	for id, s := range b.subs {
		s.cancel()
		delete(b.subs, id)
	}
	b.mu.Unlock()
	return b.c.Close()
}

// PutHost does nothing: the host advert travels on the node link.
func (b *SyncBackend) PutHost(context.Context, string, sessionsync.Host) error { return nil }

// PutSessionControls upserts the session and reads the server's high-water
// index with an empty Append. The only control Keleustes holds for a session
// is the factory's A2A blackout, returned with every registration.
func (b *SyncBackend) PutSessionControls(ctx context.Context, sessionID string, m sessionsync.SessionMeta) (int64, sessionsync.Controls, error) {
	now := time.Now().UnixMilli()
	b.mu.Lock()
	prev := b.meta[sessionID]
	b.mu.Unlock()
	up := upsertFor(sessionID, b.kind, m, now)
	if prev != nil {
		up.StartedAtMs = prev.GetStartedAtMs()
	}
	b.mu.Lock()
	b.trackOf(sessionID).apply(up)
	b.mu.Unlock()
	if err := b.c.Upsert(ctx, up); err != nil {
		return 0, sessionsync.Controls{}, mapErr(err)
	}
	b.mu.Lock()
	b.meta[sessionID] = up
	b.mu.Unlock()
	next, err := b.c.Append(ctx, sessionID, nil)
	if err != nil {
		return 0, sessionsync.Controls{}, mapErr(err)
	}
	return int64(next) - 1, b.controls(), nil
}

// controls is the factory state a session follows.
func (b *SyncBackend) controls() sessionsync.Controls {
	blackout := b.c.Profile().Control().A2ABlackout
	return sessionsync.Controls{A2ABlackout: &blackout}
}

// trackOf returns the session's tracked state; b.mu must be held.
func (b *SyncBackend) trackOf(sessionID string) *tracked {
	t := b.track[sessionID]
	if t == nil {
		t = newTracked()
		b.track[sessionID] = t
	}
	return t
}

// HeartbeatControls re-sends the session's last upsert with a fresh
// updated time, so Keleustes sees it live.
func (b *SyncBackend) HeartbeatControls(ctx context.Context, sessionID string) (sessionsync.Controls, error) {
	b.mu.Lock()
	prev := b.meta[sessionID]
	var up *nodev1.SessionUpsert
	if prev != nil {
		up = proto.Clone(prev).(*nodev1.SessionUpsert)
		up.UpdatedAtMs = time.Now().UnixMilli()
	}
	b.mu.Unlock()
	if up == nil {
		return sessionsync.Controls{}, sessionsync.ErrNotFound
	}
	return b.controls(), mapErr(b.c.Upsert(ctx, up))
}

// PostEntries appends lines by index and returns the highest the server
// holds.
func (b *SyncBackend) PostEntries(ctx context.Context, sessionID string, entries []sessionsync.Entry) (int64, error) {
	out := make([]*nodev1.Entry, 0, len(entries))
	for _, e := range entries {
		out = append(out, ToEntry(e))
	}
	next, err := b.c.Append(ctx, sessionID, out)
	if err != nil {
		return 0, mapErr(err)
	}
	b.publish(ctx, sessionID, entries)
	return int64(next) - 1, nil
}

// EndWith ends the session and closes its inbox stream.
func (b *SyncBackend) EndWith(ctx context.Context, sessionID string, info sessionsync.EndInfo) error {
	reason := info.Reason
	if info.Error != "" {
		e := info.Error
		if r := []rune(e); len(r) > 500 {
			e = string(r[:499]) + "…"
		}
		reason = strings.TrimPrefix(reason+": "+e, ": ")
	}
	b.mu.Lock()
	var turns uint32
	var planSHA string
	if t := b.track[sessionID]; t != nil {
		turns, planSHA = t.turns, t.planSHA
	}
	delete(b.meta, sessionID)
	delete(b.track, sessionID)
	if s := b.subs[sessionID]; s != nil {
		s.cancel()
		delete(b.subs, sessionID)
	}
	b.mu.Unlock()
	end := &nodev1.SessionEnd{SessionId: sessionID, EndedAtMs: time.Now().UnixMilli(), Reason: reason,
		Usage: rollupUsage(info.Rollup), Turns: turns, PlanSha256: planSHA}
	if info.Rollup != nil && info.Rollup.ToolCalls > 0 {
		end.ToolCalls = uint32(info.Rollup.ToolCalls)
	}
	if h := info.Harness; h != nil {
		end.TerminationVerified, end.EmptyResult, end.AdapterError = h.TerminationVerified, h.EmptyResult, h.AdapterError
		end.Timing = &nodev1.HarnessTiming{StartupMs: h.StartupMS, ReadyMs: h.ReadyMS, FirstReplyMs: h.FirstReplyMS, WallMs: h.WallMS}
	}
	return mapErr(b.c.End(ctx, end))
}

// InboxBatchA2A waits up to wait for the session's inbox items. Keleustes
// relays no A2A through the session inbox, so a2aAfter is ignored.
func (b *SyncBackend) InboxBatchA2A(ctx context.Context, _, sessionID string, wait time.Duration, _ int64) (sessionsync.Inbox, error) {
	var in sessionsync.Inbox
	s, err := b.sub(sessionID)
	if err != nil {
		return in, err
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	var items []*nodev1.InboxItem
	select {
	case <-ctx.Done():
		return in, ctx.Err()
	case <-t.C:
		return in, s.takeErr()
	case it := <-s.items:
		items = append(items, it)
	}
drain:
	for len(items) < 64 {
		select {
		case it := <-s.items:
			items = append(items, it)
		default:
			break drain
		}
	}
	now := time.Now().UnixMilli()
	for _, it := range items {
		id := it.GetId()
		if id == "" {
			id = "seq-" + strconv.FormatUint(it.GetSeq(), 10)
		}
		b.mu.Lock()
		b.owners[id] = sessionID
		b.mu.Unlock()
		refuse := func(why string) { go b.settle(id, "refused", why) }
		if it.GetSessionId() != "" && it.GetSessionId() != sessionID {
			refuse("the item is addressed to another session")
			continue
		}
		switch body := it.GetBody().(type) {
		case *nodev1.InboxItem_Prompt:
			// A stopped factory takes no new work: the prompt is refused
			// (and so not delivered again), saying why.
			if c := b.c.Profile().Control(); c.Stopped {
				refuse(stoppedReason(c))
				continue
			}
			in.Prompts = append(in.Prompts, sessionsync.RemotePrompt{ID: id, SessionID: sessionID, Content: body.Prompt.GetText(), CreatedAt: now})
		case *nodev1.InboxItem_Answer:
			b.mu.Lock()
			askKind := b.trackOf(sessionID).kinds[body.Answer.GetQuestionId()]
			b.mu.Unlock()
			kind, payload := structuredAnswer(askKind, body.Answer)
			in.Answers = append(in.Answers, sessionsync.RemoteAnswer{ID: id, SessionID: sessionID,
				AskID: body.Answer.GetQuestionId(), Kind: kind, Payload: payload, CreatedAt: now})
		case *nodev1.InboxItem_Command:
			c, ok := ToCommand(body.Command)
			if !ok {
				refuse("this host does not take that command")
				continue
			}
			// A console action that starts work is refused while the factory
			// is stopped; undo and rewind only put things back.
			if ctl := b.c.Profile().Control(); ctl.Stopped && c.Action != "" && c.Action != "undo" && c.Action != "rewind" {
				refuse(stoppedReason(ctl))
				continue
			}
			c.ID, c.SessionID, c.CreatedAt = id, sessionID, now
			in.Commands = append(in.Commands, c)
		default:
			refuse("the item carries nothing this host understands")
		}
	}
	return in, nil
}

// Ack reports a prompt's outcome. A queued prompt is not acked: Keleustes
// keeps it undelivered, so a host that exits before running it gets it again.
func (b *SyncBackend) Ack(ctx context.Context, promptID, st, reason, entryID string) error {
	return b.ack(ctx, promptID, st, reason, entryID)
}

// AckAnswer reports an answer's outcome.
func (b *SyncBackend) AckAnswer(ctx context.Context, answerID, st, reason, entryID string) error {
	return b.ack(ctx, answerID, st, reason, entryID)
}

// AckCommand reports a command's outcome; the session's new control state
// rides in the detail when there is one.
func (b *SyncBackend) AckCommand(ctx context.Context, commandID, st, reason string, state json.RawMessage) error {
	detail := reason
	if st == sessionsync.AckAccepted && len(state) > 0 {
		detail = string(state)
	}
	return b.ack(ctx, commandID, st, reason, detail)
}

// DraftResult does nothing: Keleustes sends no agent drafts.
func (b *SyncBackend) DraftResult(context.Context, string, string, string, any) error { return nil }

func (b *SyncBackend) ack(ctx context.Context, id, st, reason, detail string) error {
	var s string
	switch st {
	case sessionsync.AckQueued:
		return nil
	case sessionsync.AckAccepted:
		s = "done"
	case sessionsync.AckRefused:
		s, detail = "refused", reason
	default:
		s, detail = "failed", reason
	}
	b.mu.Lock()
	sid := b.owners[id]
	b.mu.Unlock()
	if sid == "" {
		return sessionsync.ErrNotFound
	}
	err := b.c.Ack(ctx, &nodev1.InboxAck{SessionId: sid, ItemId: id, Status: s, Detail: detail})
	if err == nil {
		b.mu.Lock()
		delete(b.owners, id)
		b.mu.Unlock()
	}
	return mapErr(err)
}

func (b *SyncBackend) settle(id, st, detail string) {
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()
	b.mu.Lock()
	sid := b.owners[id]
	delete(b.owners, id)
	b.mu.Unlock()
	_ = b.c.Ack(ctx, &nodev1.InboxAck{SessionId: sid, ItemId: id, Status: st, Detail: detail})
}

// sub returns the open inbox stream for sessionID, opening it (and closing
// any other: a syncer polls one live session at a time).
func (b *SyncBackend) sub(sessionID string) (*inboxSub, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, errors.New("keleustes backend closed")
	}
	if s := b.subs[sessionID]; s != nil {
		return s, nil
	}
	for id, s := range b.subs {
		s.cancel()
		delete(b.subs, id)
	}
	s := newInboxSub(b.c, sessionID)
	b.subs[sessionID] = s
	return s, nil
}

// inboxSub keeps one session's Inbox stream open, resuming after the last
// item it received when the stream drops.
type inboxSub struct {
	items  chan *nodev1.InboxItem
	cancel context.CancelFunc

	mu  sync.Mutex
	err error
}

// inboxRetry is the stream's reconnect backoff range.
var inboxRetry = [2]time.Duration{time.Second, 30 * time.Second}

func newInboxSub(c *Client, sessionID string) *inboxSub {
	ctx, cancel := context.WithCancel(context.Background())
	s := &inboxSub{items: make(chan *nodev1.InboxItem, 64), cancel: cancel}
	go s.run(ctx, c, sessionID)
	return s
}

func (s *inboxSub) setErr(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

// takeErr returns the stream's last failure, once.
func (s *inboxSub) takeErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.err
	s.err = nil
	return err
}

func (s *inboxSub) run(ctx context.Context, c *Client, sessionID string) {
	var after uint64
	backoff := inboxRetry[0]
	for ctx.Err() == nil {
		st, err := c.Inbox(ctx, sessionID, after)
		if err == nil {
			for {
				it, rerr := st.Recv()
				if rerr != nil {
					err = rerr
					break
				}
				backoff = inboxRetry[0]
				if it.GetSeq() > after {
					after = it.GetSeq()
				}
				select {
				case s.items <- it:
				case <-ctx.Done():
					return
				}
			}
		}
		if ctx.Err() != nil {
			return
		}
		s.setErr(fmt.Errorf("keleustes inbox: %w", mapErr(err)))
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		backoff = min(2*backoff, inboxRetry[1])
	}
}

// upsertFor maps the syncer's registration onto SessionUpsert.
func upsertFor(sessionID, kind string, m sessionsync.SessionMeta, now int64) *nodev1.SessionUpsert {
	up := &nodev1.SessionUpsert{
		SessionId: sessionID, Title: m.Name, Cwd: m.Cwd, Provider: m.Provider, Model: m.Model,
		Kind: kind, State: "live", StartedAtMs: now, UpdatedAtMs: now, Mode: m.Mode,
		Agent: m.ActiveProfile, DispatchId: m.DispatchID,
	}
	up.Accepts = acceptsFor(m)
	up.Git = gitFacts(m.Git)
	up.Harness, up.HarnessVersion = m.Harness, m.HarnessVersion
	up.HarnessSessionId, up.TranscriptSource = m.HarnessSessionID, m.TranscriptSource
	if len(m.Git) > 0 {
		var g struct {
			Branch string `json:"branch"`
			Remote string `json:"remote"`
			Host   string `json:"host"`
		}
		if json.Unmarshal(m.Git, &g) == nil {
			up.Branch = g.Branch
			up.Repo = g.Remote
			if g.Host != "" && g.Remote != "" {
				up.Repo = g.Host + "/" + g.Remote
			}
		}
	}
	return up
}

// ToEntry maps one transcript line onto the protocol's Entry: the line index
// as the entry index, a coarse role from the line's type, its text, and the
// rest (type, ids, meta) as meta_json, so nothing on disk is lost.
func ToEntry(e sessionsync.Entry) *nodev1.Entry {
	meta := map[string]any{"type": e.Type, "id": e.ID}
	if e.ParentID != "" {
		meta["parentId"] = e.ParentID
	}
	if e.SubagentID != "" {
		meta["subagentId"] = e.SubagentID
	}
	if e.Role != "" {
		meta["role"] = e.Role
	}
	if len(e.Meta) > 0 && json.Valid(e.Meta) {
		meta["meta"] = e.Meta
	}
	mj, _ := json.Marshal(meta)
	idx := e.Seq
	if idx < 0 {
		idx = 0
	}
	return &nodev1.Entry{Index: uint64(idx), Role: roleFor(e.Type), Text: e.Content, AtMs: e.Timestamp, MetaJson: string(mj)}
}

// roleFor reduces a line type to the protocol's roles.
func roleFor(typ string) string {
	switch {
	case typ == "user":
		return "user"
	case typ == "assistant":
		return "assistant"
	case typ == "tool_result":
		return "tool_result"
	case typ == "tool" || strings.HasPrefix(typ, "tool_"):
		return "tool"
	case strings.HasPrefix(typ, "a2a"):
		return "a2a"
	case strings.HasPrefix(typ, "shell"):
		return "shell"
	case typ == "error" || typ == "invalid":
		return "error"
	}
	return "system"
}

// answerPayload reads an Answer's text. Keleustes sends the same answer
// shape the website does, as JSON: {"kind": "...", "payload": {...}}, or
// the payload itself with its kind beside the other fields. Anything else
// (plain text) is passed on as a JSON string with no kind, which every ask
// refuses as not fitting; the host's validation of the open ask decides.
func answerPayload(text string) (string, json.RawMessage) {
	raw := json.RawMessage(text)
	if !json.Valid(raw) {
		b, _ := json.Marshal(text)
		return "", b
	}
	var head struct {
		Kind    string          `json:"kind"`
		Payload json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(raw, &head) != nil {
		return "", raw
	}
	if len(head.Payload) > 0 && string(head.Payload) != "null" {
		return head.Kind, head.Payload
	}
	return head.Kind, raw
}

// ToCommand maps a Keleustes Command onto the website's RemoteCommand
// fields. The names are a closed set; every value is still untrusted and is
// checked where it is applied (sessionctl for a control line or key, git for
// a branch, the shell runner's permission rules for a line, the host's own
// command files for a custom command). Anything else is refused.
//
//	stop                end the session (a running turn is stopped first)
//	interrupt           stop the running turn; the session waits for a prompt
//	<control> args...   a session control: "mode plan" becomes "/mode plan"
//	key <key>           a control key ("f4")
//	checkout <branch>   switch the session's branch
//	shell <line...>     one shell line (hosts run with --web-shell)
//	command <name> args a custom slash command by name
//	compact|relay|commit [words]  console session actions (rc/actions.go)
//	undo | rewind <id>  put files back to the last or a named checkpoint
//	btw|rename <words>  a side question; a new session title
func ToCommand(c *nodev1.Command) (sessionsync.RemoteCommand, bool) {
	var out sessionsync.RemoteCommand
	name := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(c.GetName()), "/"))
	args := c.GetArgs()
	switch name {
	case "":
		return out, false
	case sessionsync.SignalStop, sessionsync.SignalInterrupt:
		if len(args) != 0 {
			return out, false
		}
		out.Signal = name
	case "key":
		if len(args) != 1 {
			return out, false
		}
		out.Key = args[0]
	case "checkout":
		if len(args) != 1 {
			return out, false
		}
		out.Checkout = args[0]
	case "shell":
		if len(args) == 0 {
			return out, false
		}
		out.Shell = strings.Join(args, " ")
	case "command":
		if len(args) == 0 {
			return out, false
		}
		out.Command = strings.TrimPrefix(args[0], "/")
		out.Args = strings.Join(args[1:], " ")
	case "compact", "relay", "commit":
		out.Action, out.ActionArg = name, strings.Join(args, " ")
	case "undo":
		if len(args) != 0 {
			return out, false
		}
		out.Action = name
	case "rewind":
		if len(args) != 1 {
			return out, false
		}
		out.Action, out.ActionArg = name, strings.Join(args, " ")
	case "btw", "rename":
		if len(args) == 0 {
			return out, false
		}
		out.Action, out.ActionArg = name, strings.Join(args, " ")
	default:
		line := "/" + name
		if len(args) > 0 {
			line += " " + strings.Join(args, " ")
		}
		if !sessionctl.IsCommand(line) {
			return out, false
		}
		out.Line = line
	}
	return out, true
}

// mapErr turns gRPC statuses into the sentinels the Syncer reads: NotFound
// re-registers, a refused certificate reads as a refused credential, and a
// server that cannot store a batch reads as a rejected one so one bad line
// is split out.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.NotFound:
		return sessionsync.ErrNotFound
	case codes.Unauthenticated, codes.PermissionDenied:
		return fmt.Errorf("%w: %s", sessionsync.ErrUnauthorized, st.Message())
	case codes.FailedPrecondition, codes.AlreadyExists:
		return fmt.Errorf("%w: %s", sessionsync.ErrConflict, st.Message())
	case codes.InvalidArgument:
		return &sessionsync.StatusError{Method: "grpc", Path: st.Message(), Status: http.StatusBadRequest}
	case codes.ResourceExhausted:
		return &sessionsync.StatusError{Method: "grpc", Path: st.Message(), Status: http.StatusRequestEntityTooLarge}
	case codes.Internal, codes.DataLoss:
		return &sessionsync.StatusError{Method: "grpc", Path: st.Message(), Status: http.StatusInternalServerError}
	}
	return err
}

// ActiveBackend returns a session-sync backend for this host's active,
// unrevoked Keleustes profile, or ErrNoProfile when there is none. A host
// with one mirrors its sessions to Keleustes instead of the Vulnetix website
// (docs/keleustes.md#sessions).
func ActiveBackend(home, kind string) (*SyncBackend, error) {
	p, err := Active(home)
	if err != nil {
		return nil, err
	}
	if p.Revoked != "" {
		return nil, ErrNoProfile
	}
	c, err := NewClient(p)
	if err != nil {
		return nil, err
	}
	return NewSyncBackend(c, kind), nil
}

// Profile is the server the backend mirrors to.
func (b *SyncBackend) Profile() *Profile { return b.c.Profile() }

// stoppedReason is the refusal for work offered while the factory is stopped.
func stoppedReason(c Control) string {
	if c.Reason != "" {
		return "the Keleustes factory is stopped: " + c.Reason
	}
	return "the Keleustes factory is stopped"
}

// StoppedReason is stoppedReason for callers outside the package.
func StoppedReason(c Control) string { return stoppedReason(c) }

// publish folds uploaded lines into the session's tracked state and, when
// its state, ask or usage changed, re-sends the registration. It is best
// effort: a failed upsert is repeated by the next heartbeat, which carries
// the same state.
func (b *SyncBackend) publish(ctx context.Context, sessionID string, entries []sessionsync.Entry) {
	b.mu.Lock()
	t := b.trackOf(sessionID)
	changed := false
	for _, e := range entries {
		if t.observe(e) {
			changed = true
		}
	}
	prev := b.meta[sessionID]
	if !changed || prev == nil {
		b.mu.Unlock()
		return
	}
	up := proto.Clone(prev).(*nodev1.SessionUpsert)
	up.UpdatedAtMs = time.Now().UnixMilli()
	t.apply(up)
	b.meta[sessionID] = up
	b.mu.Unlock()
	_ = b.c.Upsert(ctx, up)
}
