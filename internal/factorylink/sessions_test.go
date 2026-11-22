package factorylink

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sessionsync"
	"github.com/vulnetix/belai/internal/webask"
)

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func recvAck(t *testing.T, f *fakeKeleustes) *nodev1.InboxAck {
	t.Helper()
	select {
	case a := <-f.acks:
		return a
	case <-time.After(10 * time.Second):
		t.Fatal("no inbox ack")
		return nil
	}
}

// The Syncer mirrors a session file to Keleustes through SyncBackend, resumes
// after what the server already holds, and delivers the inbox with the same
// gates as the website's.
func TestSyncBackendMirrorsAndDeliversInbox(t *testing.T) {
	f := newFakeKeleustes(t)
	const sid = "11111111-2222-3333-4444-555555555555"
	// The server already holds the first two lines (a restarted host).
	f.entries[sid] = []*nodev1.Entry{{Index: 0}, {Index: 1}}

	path := filepath.Join(t.TempDir(), sid+".jsonl")
	lines := []string{
		`{"id":"a","type":"session_meta","content":"{\"cwd\":\"/w\",\"mode\":\"agent\"}","timestamp":1}`,
		`{"id":"b","type":"user","role":"user","content":"hello","timestamp":2}`,
		`{"id":"c","type":"assistant","role":"assistant","content":"hi","timestamp":3,"meta":{"model":"m1","provider":"p1"}}`,
		`{"id":"d","type":"tool_result","content":"out","timestamp":4}`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	be, err := ActiveBackend(f.home, "tui")
	if err != nil {
		t.Fatal(err)
	}
	defer be.Close()
	s := sessionsync.New(sessionsync.Options{
		Backend: be, HostID: "host-1", RemotePrompts: true,
		TickEvery: 20 * time.Millisecond, InboxWait: 200 * time.Millisecond,
	})
	s.Start(context.Background())
	s.Activate(sessionsync.SessionInfo{ID: sid, Path: path, Name: "demo"})

	waitFor(t, "all four lines", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.entries[sid]) == 4
	})
	f.mu.Lock()
	for _, i := range f.appended {
		if i < 2 {
			t.Errorf("re-sent line %d the server already held", i)
		}
	}
	got := f.entries[sid]
	if got[2].GetRole() != "assistant" || got[2].GetText() != "hi" || got[2].GetAtMs() != 3 ||
		!strings.Contains(got[2].GetMetaJson(), `"model":"m1"`) || got[3].GetRole() != "tool_result" {
		t.Errorf("entries = %v", got[2:])
	}
	up := f.upserts[0]
	if up.GetSessionId() != sid || up.GetKind() != "tui" || up.GetState() != "live" || up.GetTitle() != "demo" || up.GetCwd() != "/w" {
		t.Errorf("upsert = %v", up)
	}
	f.mu.Unlock()

	box := f.box(sid)
	box <- &nodev1.InboxItem{Seq: 1, Id: "p1", SessionId: sid, Body: &nodev1.InboxItem_Prompt{Prompt: &nodev1.Prompt{Text: "do it"}}}
	select {
	case p := <-s.Prompts():
		if p.ID != "p1" || p.SessionID != sid || p.Content != "do it" {
			t.Errorf("prompt = %+v", p)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("prompt not delivered")
	}
	s.Ack("p1", sessionsync.AckQueued, "", "")
	s.Ack("p1", sessionsync.AckAccepted, "", "entry-9")
	if a := recvAck(t, f); a.GetItemId() != "p1" || a.GetStatus() != "done" || a.GetDetail() != "entry-9" || a.GetSessionId() != sid {
		t.Errorf("prompt ack = %v (a queued ack must send nothing)", a)
	}

	// Answers and controls are off on this syncer: both are refused, as
	// they are for the website; an unknown command never reaches the host.
	box <- &nodev1.InboxItem{Seq: 2, Id: "a1", SessionId: sid, Body: &nodev1.InboxItem_Answer{Answer: &nodev1.Answer{QuestionId: "q", Text: `{"kind":"permission","payload":{"decision":"allow_once"}}`}}}
	box <- &nodev1.InboxItem{Seq: 3, Id: "c1", SessionId: sid, Body: &nodev1.InboxItem_Command{Command: &nodev1.Command{Name: "mode", Args: []string{"plan"}}}}
	box <- &nodev1.InboxItem{Seq: 4, Id: "c2", SessionId: sid, Body: &nodev1.InboxItem_Command{Command: &nodev1.Command{Name: "quit"}}}
	box <- &nodev1.InboxItem{Seq: 5, Id: "x1", SessionId: "other", Body: &nodev1.InboxItem_Prompt{Prompt: &nodev1.Prompt{Text: "not yours"}}}
	refused := map[string]bool{}
	for i := 0; i < 4; i++ {
		a := recvAck(t, f)
		if a.GetStatus() != "refused" || a.GetDetail() == "" {
			t.Errorf("ack = %v, want refused with a reason", a)
		}
		refused[a.GetItemId()] = true
	}
	for _, id := range []string{"a1", "c1", "c2", "x1"} {
		if !refused[id] {
			t.Errorf("%s not refused", id)
		}
	}
	select {
	case p := <-s.Prompts():
		t.Errorf("another session's prompt delivered: %+v", p)
	default:
	}

	s.Close(3 * time.Second)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.ends) != 1 || f.ends[0].GetSessionId() != sid {
		t.Errorf("ends = %v", f.ends)
	}
	if f.afters[0] != 0 {
		t.Errorf("inbox opened after %d", f.afters[0])
	}
}

// A dispatch on the link reaches the rc daemon's hook, is acked, and its
// outcome goes back through Jobs.Complete; a job is refused.
func TestRCServesDispatchAndCompletes(t *testing.T) {
	f := newFakeKeleustes(t)
	r, err := NewRC(f.home, f.p)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan *nodev1.Dispatch, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = r.Serve(ctx, RCHooks{
			Advert: func() HostOptions { return HostOptions{TrustedDirs: []string{"/w"}, MaxSessions: 3} },
			Dispatch: func(ctx context.Context, d *nodev1.Dispatch) {
				got <- d
				_ = r.Complete(ctx, &nodev1.JobResult{JobId: d.GetId(), Status: "ok", SessionId: "s-1"})
			},
		})
		close(done)
	}()
	defer func() { cancel(); <-done }()
	f.frames <- &nodev1.ServerFrame{Seq: 1, Body: &nodev1.ServerFrame_Dispatch{Dispatch: &nodev1.Dispatch{Id: "d1", Kind: "session", Cwd: "/w", Prompt: "go"}}}
	f.frames <- &nodev1.ServerFrame{Seq: 2, Body: &nodev1.ServerFrame_Job{Job: &nodev1.Job{Id: "j1", Kind: "github"}}}
	select {
	case d := <-got:
		if d.GetId() != "d1" || d.GetPrompt() != "go" {
			t.Errorf("dispatch = %v", d)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("dispatch not delivered")
	}
	results := map[string]*nodev1.JobResult{}
	for len(results) < 2 {
		select {
		case res := <-f.results:
			results[res.GetJobId()] = res
		case <-time.After(10 * time.Second):
			t.Fatalf("results = %v", results)
		}
	}
	if res := results["d1"]; res.GetStatus() != "ok" || res.GetSessionId() != "s-1" {
		t.Errorf("d1 = %v", res)
	}
	if res := results["j1"]; res.GetStatus() != "refused" {
		t.Errorf("j1 = %v", res)
	}
	waitFor(t, "frames acked", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.linkAck >= 2
	})
	f.mu.Lock()
	adv := f.adverts[0]
	f.mu.Unlock()
	if !adv.GetCapabilities().GetRemoteControl() || adv.GetCapabilities().GetMaxSessions() != 3 || len(adv.GetTrustedDirs()) != 1 {
		t.Errorf("advert = %v", adv)
	}
}

// A watcher (the TUI) that owns the link refuses dispatches rather than
// dropping them, and hands the link to `belai rc` when it starts.
func TestWatcherRefusesAndHandsLinkToRC(t *testing.T) {
	prev := takeoverInterval
	takeoverInterval = 50 * time.Millisecond
	t.Cleanup(func() { takeoverInterval = prev })
	f := newFakeKeleustes(t)
	ctx := context.Background()

	watcher := NewNode(f.p, nil, nil)
	watcher.Start(ctx)
	defer watcher.Stop(time.Second)
	waitNode(t, watcher, func(s NodeStatus) bool { return s.Owner && s.State == StateOnline })
	f.frames <- &nodev1.ServerFrame{Seq: 1, Body: &nodev1.ServerFrame_Dispatch{Dispatch: &nodev1.Dispatch{Id: "d1"}}}
	select {
	case res := <-f.results:
		if res.GetJobId() != "d1" || res.GetStatus() != "refused" || res.GetError() == "" {
			t.Errorf("watcher outcome = %v", res)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("watcher neither refused nor reported the dispatch")
	}

	got := make(chan string, 1)
	rc := NewDispatchNode(f.p, nil, func(_ context.Context, fr *nodev1.ServerFrame) error {
		if d := fr.GetDispatch(); d != nil {
			got <- d.GetId()
		}
		return nil
	})
	rc.Start(ctx)
	defer rc.Stop(time.Second)
	waitNode(t, rc, func(s NodeStatus) bool { return s.Owner && s.State == StateOnline })
	waitNode(t, watcher, func(s NodeStatus) bool { return !s.Owner })
	f.frames <- &nodev1.ServerFrame{Seq: 2, Body: &nodev1.ServerFrame_Dispatch{Dispatch: &nodev1.Dispatch{Id: "d2"}}}
	select {
	case id := <-got:
		if id != "d2" {
			t.Errorf("rc got %q", id)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("rc did not get the dispatch")
	}
	// While the claim stands the watcher does not take the link back.
	time.Sleep(200 * time.Millisecond)
	if watcher.Status().Owner {
		t.Error("watcher took the link back from rc")
	}
}

func TestToCommand(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want sessionsync.RemoteCommand
		ok   bool
	}{
		{"mode", []string{"plan"}, sessionsync.RemoteCommand{Line: "/mode plan"}, true},
		{"/caveman", []string{"on"}, sessionsync.RemoteCommand{Line: "/caveman on"}, true},
		{"key", []string{"f4"}, sessionsync.RemoteCommand{Key: "f4"}, true},
		{"checkout", []string{"main"}, sessionsync.RemoteCommand{Checkout: "main"}, true},
		{"shell", []string{"go", "test"}, sessionsync.RemoteCommand{Shell: "go test"}, true},
		{"command", []string{"/review", "a", "b"}, sessionsync.RemoteCommand{Command: "review", Args: "a b"}, true},
		{"quit", nil, sessionsync.RemoteCommand{}, false},
		{"stop", nil, sessionsync.RemoteCommand{Signal: "stop"}, true},
		{"Interrupt", nil, sessionsync.RemoteCommand{Signal: "interrupt"}, true},
		{"stop", []string{"now"}, sessionsync.RemoteCommand{}, false},
		{"key", nil, sessionsync.RemoteCommand{}, false},
		{"", nil, sessionsync.RemoteCommand{}, false},
	}
	for _, c := range cases {
		got, ok := ToCommand(&nodev1.Command{Name: c.name, Args: c.args})
		if ok != c.ok || got != c.want {
			t.Errorf("%s %v = %+v %v, want %+v %v", c.name, c.args, got, ok, c.want, c.ok)
		}
	}
}

func TestAnswerPayload(t *testing.T) {
	kind, p := answerPayload(`{"kind":"clarify","payload":{"answers":["a"]}}`)
	if kind != "clarify" || string(p) != `{"answers":["a"]}` {
		t.Errorf("wrapped = %q %s", kind, p)
	}
	kind, p = answerPayload(`{"kind":"permission","decision":"deny"}`)
	if kind != "permission" || !json.Valid(p) {
		t.Errorf("flat = %q %s", kind, p)
	}
	kind, p = answerPayload("yes please")
	if kind != "" || string(p) != `"yes please"` {
		t.Errorf("text = %q %s", kind, p)
	}
}

func TestToEntryRoles(t *testing.T) {
	for typ, want := range map[string]string{
		"user": "user", "assistant": "assistant", "tool_start": "tool", "tool": "tool",
		"tool_result": "tool_result", "a2a_message": "a2a", "shell": "shell", "invalid": "error",
		"turn_state": "system", "ask": "system",
	} {
		e := ToEntry(sessionsync.Entry{Seq: 7, ID: "x", Type: typ, Content: "c"})
		if e.GetRole() != want || e.GetIndex() != 7 || e.GetText() != "c" || !strings.Contains(e.GetMetaJson(), `"type":"`+typ+`"`) {
			t.Errorf("%s = %v", typ, e)
		}
	}
}

// WP-A: the upsert carries usage, state and the open ask read from the lines
// the harness wrote; a Keleustes decision becomes webask's answer JSON, which
// the host's validator still checks; the end carries the rollup.
func TestSyncBackendPublishesAskUsageAndStructuredAnswers(t *testing.T) {
	f := newFakeKeleustes(t)
	const sid = "21111111-2222-3333-4444-555555555555"
	path := filepath.Join(t.TempDir(), sid+".jsonl")
	lines := []string{
		`{"id":"a","type":"session_meta","content":"{\"cwd\":\"/w\",\"mode\":\"agent\"}","timestamp":1}`,
		`{"id":"b","type":"turn_state","timestamp":2,"meta":{"state":"started"}}`,
		`{"id":"c","type":"assistant","role":"assistant","content":"hi","timestamp":3,"meta":{"model":"m1","provider":"p1","prompt_tokens":30,"completion_tokens":4,"cache_read_tokens":0,"cost_micro_usd":2500}}`,
		`{"id":"ask-1","type":"ask","role":"system","content":"permission: Bash rm -rf build","timestamp":4,"meta":{"ask_id":"ask-1","kind":"permission","tool":"Bash","options":["allow_once","deny"]}}`,
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	be, err := ActiveBackend(f.home, "rc")
	if err != nil {
		t.Fatal(err)
	}
	defer be.Close()
	s := sessionsync.New(sessionsync.Options{
		Backend: be, HostID: "host-1", RemotePrompts: true, RemoteAnswers: true,
		TickEvery: 20 * time.Millisecond, InboxWait: 200 * time.Millisecond,
	})
	s.Start(context.Background())
	s.Activate(sessionsync.SessionInfo{ID: sid, Path: path, Name: "demo"})

	var last *nodev1.SessionUpsert
	waitFor(t, "an upsert with the ask", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		if n := len(f.upserts); n > 0 {
			last = f.upserts[n-1]
		}
		return last != nil && last.GetPendingAsk() != nil
	})
	ask := last.GetPendingAsk()
	if last.GetState() != "waiting" || ask.GetId() != "ask-1" || ask.GetKind() != "permission" ||
		ask.GetTool() != "Bash" || len(ask.GetOptions()) != 2 || last.GetPendingQuestionId() != "ask-1" {
		t.Errorf("upsert = %v", last)
	}
	if len(last.GetUsage()) != 1 || last.GetUsage()[0].GetInputTokens() != 30 || last.GetInputTokens() != 30 ||
		last.GetUsage()[0].GetCostUsd() != 0.0025 {
		t.Errorf("usage = %v", last.GetUsage())
	}
	if a := last.GetAccepts(); !a.GetAnswers() || !a.GetPrompts() || a.GetControls() {
		t.Errorf("accepts = %v", a)
	}

	box := f.box(sid)
	box <- &nodev1.InboxItem{Seq: 1, Id: "ans-1", SessionId: sid, Body: &nodev1.InboxItem_Answer{Answer: &nodev1.Answer{QuestionId: "ask-1", Decision: "allow_once"}}}
	box <- &nodev1.InboxItem{Seq: 2, Id: "ans-2", SessionId: sid, Body: &nodev1.InboxItem_Answer{Answer: &nodev1.Answer{QuestionId: "ask-1", Decision: "allow_forever"}}}
	for _, want := range []string{"allow_once", ""} {
		select {
		case a := <-s.Answers():
			if a.AskID != "ask-1" || a.Kind != "permission" {
				t.Fatalf("answer = %+v", a)
			}
			got, err := webask.ParseDecision(a.Payload)
			if got != want || (want == "" && err == nil) {
				t.Errorf("decision = %q, %v; want %q", got, err, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("answer not delivered")
		}
	}

	// The ask is answered on the host and the turn ends: the ask clears.
	more := `{"id":"answer-ask-1","type":"ask_answer","role":"system","timestamp":5,"meta":{"ask_id":"ask-1","kind":"permission","source":"web"}}` + "\n" +
		`{"id":"e","type":"turn_state","timestamp":6,"meta":{"state":"completed","duration_ms":4}}` + "\n"
	fh, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = fh.WriteString(more)
	fh.Close()
	s.Nudge()
	waitFor(t, "the ask cleared", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		u := f.upserts[len(f.upserts)-1]
		return u.GetPendingAsk() == nil && u.GetState() == "idle"
	})
	s.Close(3 * time.Second)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.ends) != 1 || len(f.ends[0].GetUsage()) != 1 || f.ends[0].GetUsage()[0].GetOutputTokens() != 4 || f.ends[0].GetTurns() != 1 {
		t.Errorf("end = %v", f.ends)
	}
}

// WP-B: the rc daemon's link owner sends its live workers and spend as a
// HostStatus frame, and again when they change.
func TestRCSendsHostStatus(t *testing.T) {
	f := newFakeKeleustes(t)
	r, err := NewRC(f.home, f.p)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	cost := int64(100)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = r.Serve(ctx, RCHooks{
			Status: func() *nodev1.HostStatus {
				mu.Lock()
				defer mu.Unlock()
				return HostStatusOf(1, []sessionsync.RCWorker{{ID: "w-1", Profile: "belai:patcher", State: "working", CostMicroUSD: cost}}, nil)
			},
		})
		close(done)
	}()
	defer func() { cancel(); <-done }()
	waitFor(t, "a status", func() bool {
		f.mu.Lock()
		defer f.mu.Unlock()
		return len(f.statuses) > 0
	})
	f.mu.Lock()
	s := f.statuses[0]
	f.mu.Unlock()
	if s.GetRunningSessions() != 1 || len(s.GetWorkers()) != 1 || s.GetWorkers()[0].GetCostMicroUsd() != 100 || s.GetAtMs() == 0 {
		t.Errorf("status = %v", s)
	}
}

// A harness session's end facts reach Keleustes on SessionEnd (OP-2).
func TestEndWithCarriesHarnessFacts(t *testing.T) {
	f := newFakeKeleustes(t)
	be, err := ActiveBackend(f.home, "tui")
	if err != nil {
		t.Fatal(err)
	}
	const sid = "11111111-2222-3333-4444-666666666666"
	if err := be.EndWith(t.Context(), sid, sessionsync.EndInfo{Reason: sessionsync.EndCompleted,
		Harness: &sessionsync.HarnessEnd{TerminationVerified: true, EmptyResult: true, StartupMS: 120, WallMS: 9000}}); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.ends) != 1 {
		t.Fatalf("ends = %v", f.ends)
	}
	e := f.ends[0]
	if !e.GetTerminationVerified() || !e.GetEmptyResult() || e.GetAdapterError() || e.GetTiming().GetStartupMs() != 120 || e.GetTiming().GetWallMs() != 9000 {
		t.Errorf("end = %v", e)
	}
}
