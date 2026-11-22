package harnessrun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vulnetix/belai/internal/harness"
	"github.com/vulnetix/belai/internal/harnesstail"
	"github.com/vulnetix/belai/internal/proc"
)

// ErrContinuity is the closed refusal of a resume that could not be shown to
// continue the recorded native session.
const ErrContinuity = "continuity_unverified"

// AdapterError is the end reason prefix of a session whose harness never
// gave a final answer to a typed prompt.
const AdapterError = "adapter_error"

// Timing is what the runner measures itself (never what a harness reports):
// spawn to first output, spawn to ready, spawn to the first native reply, and
// the session's wall time.
type Timing struct {
	StartupMS    int64 `json:"startupMs"`
	ReadyMS      int64 `json:"readyMs,omitempty"`
	FirstReplyMS int64 `json:"firstReplyMs,omitempty"`
	WallMS       int64 `json:"wallMs"`
}

// TimingSample is one line of the node's timing file, read by detection for
// the advert's p50/p95.
type TimingSample struct {
	Harness   string `json:"harness"`
	StartupMS int64  `json:"startupMs"`
	ReadyMS   int64  `json:"readyMs,omitempty"`
	At        int64  `json:"at"`
}

// hardening is the per-session state the checks below keep.
type hardening struct {
	mu          sync.Mutex
	spawn       time.Time
	timing      Timing
	replies     int // native assistant replies with text
	typed       int // prompts typed
	lastTyped   time.Time
	lastEnd     time.Time // last native turn end
	verified    bool      // continuity shown for a resume
	verifiedCh  chan struct{}
	gitStart    string
	lastReply   string
	lastReplyAt time.Time
	question    string // open question ask id
	questions   int
}

// AppendTiming adds one sample to the node's timing file (0600).
func AppendTiming(path string, s TimingSample) {
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	b, _ := json.Marshal(s)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(append(b, '\n'))
	_ = f.Close()
}

// gitState is a hash of the work tree's state (HEAD and status), or "" outside
// a repository. It runs git with no shell, a scrubbed environment and a time
// bound; it reads, never writes.
func gitState(dir string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	run := func(args ...string) []byte {
		cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(proc.ScrubbedEnv(), "GIT_OPTIONAL_LOCKS=0")
		out, err := cmd.Output()
		if err != nil {
			return nil
		}
		return out
	}
	head := run("rev-parse", "HEAD")
	if head == nil {
		return ""
	}
	sum := sha256.Sum256(append(head, run("status", "--porcelain=v1", "--untracked-files=normal")...))
	return hex.EncodeToString(sum[:8])
}

// watchFirstOutput records the first output and readiness of the harness.
func (s *Session) watchFirstOutput(ctx context.Context) {
	for ctx.Err() == nil {
		if ms := s.r.firstOut.Load(); ms != 0 {
			h := &s.hard
			h.mu.Lock()
			h.timing.StartupMS = ms - h.spawn.UnixMilli()
			st := h.timing.StartupMS
			h.mu.Unlock()
			s.own("system", "harness_first_output", "first output", map[string]any{"startupMs": st})
			s.audit("first_output", "", map[string]string{"count": formatInt(st)})
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-s.r.Done():
			return
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func formatInt(n int64) string { return strconv.FormatInt(n, 10) }

// noteReady records spawn to ready.
func (s *Session) noteReady() {
	h := &s.hard
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.timing.ReadyMS == 0 {
		h.timing.ReadyMS = time.Since(h.spawn).Milliseconds()
	}
}

// noteNative tracks replies and turn ends from native records, and checks a
// resume's continuity on the first record that names its session.
func (s *Session) noteNative(e harnesstail.Event) {
	h := &s.hard
	h.mu.Lock()
	if e.Role == "assistant" && strings.TrimSpace(e.Text) != "" && !e.At.Before(h.spawn.Add(-2*time.Second)) {
		h.replies++
		h.lastReply, h.lastReplyAt = e.Text, time.Now()
		if h.timing.FirstReplyMS == 0 {
			h.timing.FirstReplyMS = time.Since(h.spawn).Milliseconds()
		}
	}
	if e.TurnEnd && !e.At.Before(h.spawn.Add(-2*time.Second)) {
		h.lastEnd = time.Now()
	}
	h.mu.Unlock()
	if e.SessionID != "" && !e.At.Before(h.spawn.Add(-2*time.Second)) {
		s.checkContinuity(e.SessionID)
	}
}

func (s *Session) noteTyped() {
	h := &s.hard
	h.mu.Lock()
	h.typed++
	h.lastTyped = time.Now()
	h.mu.Unlock()
}

// wantsContinuity reports whether this start is a resume that must be shown
// to continue the recorded native session before anything is typed.
func (s *Session) wantsContinuity() bool {
	return s.c.Resume != "" && len(s.l.Continuity) > 0
}

// preContinuity refuses a resume whose recorded native file is not there
// (the harness would silently start a new session).
func (s *Session) preContinuity() string {
	if !s.wantsContinuity() || s.l.Transcript == nil || !strings.Contains(s.l.Transcript.Path, "{native_id}") {
		return ""
	}
	pat := harnesstail.Expand(s.l.Transcript.Path, s.c.Home, s.c.Cwd, s.c.Resume)
	if m, _ := filepath.Glob(pat); len(m) == 0 {
		return ErrContinuity + ": no native session " + s.c.Resume + " in this directory"
	}
	return ""
}

// checkContinuity compares the native session the harness is writing with
// the one the resume named; a mismatch stops the session.
func (s *Session) checkContinuity(native string) {
	if !s.wantsContinuity() {
		return
	}
	h := &s.hard
	h.mu.Lock()
	if h.verified {
		h.mu.Unlock()
		return
	}
	ok := native == s.c.Resume
	if ok {
		h.verified = true
		close(h.verifiedCh)
	}
	h.mu.Unlock()
	if ok {
		s.own("system", "harness_continuity", "continuity verified: "+harness.ContinuitySessionID,
			map[string]any{"method": harness.ContinuitySessionID, "nativeId": native})
		s.audit("continuity_verified", "", map[string]string{"id": native})
		return
	}
	why := ErrContinuity + ": the harness is writing session " + native + ", not " + s.c.Resume
	s.own("error", "harness_continuity", why, map[string]any{"method": harness.ContinuitySessionID, "nativeId": native, "want": s.c.Resume})
	s.audit("continuity_refused", why, map[string]string{"id": native})
	s.stop(ErrContinuity)
}

// outcome is the end's verdict beyond the exit: an adapter error when a
// typed prompt got no final answer, an empty-result warning when the
// session left no reply and no change in the tree.
func (s *Session) outcome() (adapterErr string, empty bool) {
	h := &s.hard
	h.mu.Lock()
	defer h.mu.Unlock()
	if s.nativeSrc.Load() && h.typed > 0 && (h.lastEnd.IsZero() || h.lastEnd.Before(h.lastTyped)) {
		adapterErr = AdapterError + ": no final assistant turn after the last prompt"
	}
	changed := h.gitStart != "" && gitState(s.c.Cwd) != h.gitStart
	empty = h.replies == 0 && !changed
	return adapterErr, empty
}

// groupGone reports whether the harness's process group has no process left.
func (s *Session) groupGone() bool {
	if g, ok := s.r.term.(interface{ GroupGone() bool }); ok {
		return g.GroupGone()
	}
	return true
}

// continuityMissed stops a resume whose typed prompt never showed up in the
// recorded native session (the harness wrote it somewhere else).
func (s *Session) continuityMissed() {
	if !s.wantsContinuity() {
		return
	}
	s.hard.mu.Lock()
	v := s.hard.verified
	s.hard.mu.Unlock()
	if v {
		return
	}
	why := ErrContinuity + ": the prompt did not reach native session " + s.c.Resume
	s.own("error", "harness_continuity", why, nil)
	s.audit("continuity_refused", why, nil)
	s.stop(ErrContinuity)
}
