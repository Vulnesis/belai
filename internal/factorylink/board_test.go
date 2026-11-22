package factorylink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vulnetix/belai/internal/a2a"
	"github.com/vulnetix/belai/internal/clijobs"
	"github.com/vulnetix/belai/internal/credentials"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/kanban"
	"github.com/vulnetix/belai/internal/repomemory"
	"github.com/vulnetix/belai/internal/sessionsync"
)

var _ kanban.Remote = (*KanbanRemote)(nil)

// The board syncs through the Board service with the same kanban.Syncer the
// website uses: a local card is pushed with its belai part in meta_json, the
// server's key comes back on the pull, a console edit reaches the host, and a
// stale push is settled by the next pull.
func TestKanbanSyncThroughKeleustes(t *testing.T) {
	f := newFakeKeleustes(t)
	c, err := NewClient(f.p)
	if err != nil {
		t.Fatal(err)
	}
	remote := NewKanbanRemote(c)
	defer remote.Close()
	store := kanban.Open(filepath.Join(t.TempDir(), "board.bkan"))
	prov := kanban.Provenance{Project: "api", Remote: "acme/api", HostID: "3f9a2c00-0000-4000-8000-000000000001"}
	it, _, err := store.Add(kanban.ItemInput{Title: "Fix the flaky test", List: kanban.Blocked, Labels: []string{"ci"}, Priority: 2}, prov)
	if err != nil {
		t.Fatal(err)
	}
	s := kanban.NewSyncer(store, remote, kanban.SyncOptions{})
	ctx := context.Background()
	s.Sync(ctx)
	if st := s.Status(); st.LastError != "" {
		t.Fatalf("sync: %s", st.LastError)
	}
	card := f.card(it.ID)
	if card == nil || card.GetStatus() != "todo" || card.GetPriority() != 2 || card.GetRepo() != "acme/api" ||
		len(card.GetLabels()) != 1 || !strings.Contains(card.GetMetaJson(), `"list":"blocked"`) {
		t.Fatalf("card = %v", card)
	}
	got, _ := store.Get(it.ID)
	if got.Key != card.GetKey() || got.Key == "" || got.List != kanban.Blocked || got.Dirty {
		t.Fatalf("after the pull: key %q list %s dirty %v", got.Key, got.List, got.Dirty)
	}

	// The console moves the card and keeps something of its own in meta.
	f.editCard(it.ID, func(k *nodev1.KanbanItem) {
		k.Status = "doing"
		k.UpdatedAtMs = time.Now().UnixMilli() + 1000
		var m map[string]json.RawMessage
		_ = json.Unmarshal([]byte(k.MetaJson), &m)
		m["runId"] = json.RawMessage(`"run-7"`)
		b, _ := json.Marshal(m)
		k.MetaJson = string(b)
	})
	s.Sync(ctx)
	got, _ = store.Get(it.ID)
	if got.List != kanban.InProgress {
		t.Fatalf("the console's move did not arrive: %s", got.List)
	}

	// A local edit pushes the server's own meta back untouched.
	title := "Fix the flaky test for good"
	if _, err := store.Update(it.ID, kanban.Patch{Title: &title}, ""); err != nil {
		t.Fatal(err)
	}
	s.Sync(ctx)
	card = f.card(it.ID)
	if card.GetTitle() != title || !strings.Contains(card.GetMetaJson(), `"runId":"run-7"`) || card.GetStatus() != "doing" {
		t.Fatalf("pushed card = %v", card)
	}

	// A stale push: the console edits the card again while this host edits it.
	f.editCard(it.ID, func(k *nodev1.KanbanItem) { k.Body = "console body"; k.UpdatedAtMs = 1 })
	title2 := "Newer local title"
	if _, err := store.Update(it.ID, kanban.Patch{Title: &title2}, ""); err != nil {
		t.Fatal(err)
	}
	// The push conflicts (the host's version is stale); the next pull hands
	// the server copy to the merge, the newer local edit survives with the
	// server's version, and the push after that is accepted.
	s.Sync(ctx)
	s.Sync(ctx)
	card = f.card(it.ID)
	got, _ = store.Get(it.ID)
	if card.GetTitle() != title2 || got.Dirty || got.ServerVersion != card.GetVersion() {
		t.Fatalf("after the conflict: server %q v%d, local dirty %v v%d", card.GetTitle(), card.GetVersion(), got.Dirty, got.ServerVersion)
	}
}

func TestKanbanStatusMapping(t *testing.T) {
	for _, c := range []struct{ list, status string }{
		{"backlog", "backlog"}, {"in_progress", "doing"}, {"review", "review"}, {"done", "done"}, {"blocked", "todo"},
	} {
		pb := ToKanbanItem(sessionsync.KanbanItem{ID: "x", Title: "t", List: c.list})
		if pb.GetStatus() != c.status {
			t.Errorf("%s pushed as %s, want %s", c.list, pb.GetStatus(), c.status)
		}
		back := FromKanbanItem(pb)
		if back.List != c.list {
			t.Errorf("%s came back as %s", c.list, back.List)
		}
	}
	// A triage card stays triage while belai keeps it in review.
	w := FromKanbanItem(&nodev1.KanbanItem{Id: "y", Title: "t", Status: "triage", Key: "K-1"})
	if w.List != "review" || w.Key != "K-1" {
		t.Fatalf("triage = %+v", w)
	}
	if pb := ToKanbanItem(w); pb.GetStatus() != "triage" || strings.Contains(pb.GetMetaJson(), metaPulledStatus) {
		t.Errorf("pushed back as %s, meta %s", pb.GetStatus(), pb.GetMetaJson())
	}
	w.List = "done"
	if pb := ToKanbanItem(w); pb.GetStatus() != "done" {
		t.Errorf("moved triage pushed as %s", pb.GetStatus())
	}
	if p := ToKanbanItem(sessionsync.KanbanItem{Agent: &sessionsync.KanbanAgent{Priority: 9}}).GetPriority(); p != 3 {
		t.Errorf("priority clamped to %d", p)
	}
}

// Repository memory replicates with the website's MemoryReplicator over the
// Board service, in its own marks file.
func TestMemoryReplicatesThroughKeleustes(t *testing.T) {
	f := newFakeKeleustes(t)
	c, _ := NewClient(f.p)
	mem := NewMemoryRemote(c)
	defer mem.Close()
	root := t.TempDir()
	st, err := repomemory.OpenScope(root, repomemory.ScopeRepo, "acme/api")
	if err != nil {
		t.Fatal(err)
	}
	n, err := st.Append("tests run with just check", []string{"build"}, repomemory.Stamp{})
	if err != nil {
		t.Fatal(err)
	}
	// A console note in a repository scope, one in a profile scope, and one
	// in a scope belai has no home for.
	now := time.Now().UnixMilli()
	f.addNote(&nodev1.MemoryNote{Id: "0190aaaa-bbbb-7ccc-8ddd-000000000001", Scope: "acme/api", Text: "deploys on friday are banned", CreatedAtMs: now, UpdatedAtMs: now})
	f.addNote(&nodev1.MemoryNote{Id: "0190aaaa-bbbb-7ccc-8ddd-000000000002", Scope: "profile:reviewer", Text: "check the changelog", CreatedAtMs: now, UpdatedAtMs: now})
	f.addNote(&nodev1.MemoryNote{Id: "0190aaaa-bbbb-7ccc-8ddd-000000000003", Scope: "global", Text: "be kind", CreatedAtMs: now, UpdatedAtMs: now})

	r := sessionsync.NewMemoryReplicator(mem, "3f9a2c00-0000-4000-8000-000000000001", root)
	r.UseStateFile(mem.StateName())
	if err := r.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.board.mu.Lock()
	pushed := f.board.notes[n.NoteID]
	f.board.mu.Unlock()
	if pushed == nil || pushed.GetScope() != "acme/api" || pushed.GetText() != "tests run with just check" {
		t.Fatalf("pushed = %v", pushed)
	}
	var texts []string
	for _, sc := range []struct{ scope, key string }{{repomemory.ScopeRepo, "acme/api"}, {repomemory.ScopeProfile, "reviewer"}} {
		s, _ := repomemory.OpenScope(root, sc.scope, sc.key)
		notes, _ := s.All()
		for _, n := range notes {
			texts = append(texts, n.Text)
		}
	}
	joined := strings.Join(texts, "|")
	if !strings.Contains(joined, "deploys on friday are banned") || !strings.Contains(joined, "check the changelog") || strings.Contains(joined, "be kind") {
		t.Errorf("pulled notes = %q", joined)
	}
	// The website's marks are untouched.
	if _, err := os.Stat(filepath.Join(root, "replica.json")); err == nil {
		t.Error("the website's marks file was written")
	}
	if _, err := os.Stat(filepath.Join(root, mem.StateName())); err != nil {
		t.Errorf("no Keleustes marks file: %v", err)
	}
}

// A2A goes out from "<nodeId>:<sessionId>" with the belai envelope in
// meta_json, comes in through the relay with the sender's node as its host,
// and stops on the blackout.
func TestA2ARelaysThroughKeleustes(t *testing.T) {
	f := newFakeKeleustes(t)
	home := f.home
	c, _ := NewClient(f.p)
	r := NewA2ARelay(c)
	r.stateEvery = 50 * time.Millisecond
	defer r.Close()
	hostID, _ := sessionsync.HostID(home)
	sess := "11111111-2222-4333-8444-555555555555"
	dir := a2a.Dir(home)
	node, err := a2a.Open(a2a.Options{Dir: dir, HostID: hostID, SessionID: sess})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	relay := a2a.NewRelay(r, hostID, node.Bus(), node.Audit(), func() string { return sess })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go relay.Run(ctx)
	go r.Receive(ctx, relay, func() string { return sess })

	// Outbound.
	env := a2a.Envelope{MessageID: a2a.NewMessageID(time.Now()), Kind: a2a.KindBroadcast, TS: time.Now().UnixMilli(),
		Agent: a2a.AgentCard{HostID: hostID, SessionID: sess}, Work: a2a.Work{Repo: "acme/api", Branch: "main"}}
	if !relay.Outbound(env) {
		t.Fatal("outbound withheld")
	}
	waitFor(t, "the broadcast", func() bool { return len(f.sentA2A()) == 1 })
	sent := f.sentA2A()[0]
	if sent.GetFrom() != "node-1:"+sess || sent.GetTo() != "" || !strings.Contains(sent.GetMetaJson(), env.MessageID) {
		t.Fatalf("sent = %v", sent)
	}

	// Inbound: a message from another node to this session, by its Keleustes id.
	other := "0190bbbb-cccc-7ddd-8eee-ffff00000001"
	otherSess := "99999999-8888-4777-8666-555555555555"
	in := a2a.Envelope{MessageID: a2a.NewMessageID(time.Now()), Kind: a2a.KindMessage, TS: time.Now().UnixMilli(),
		Agent: a2a.AgentCard{HostID: "aaaaaaaa-0000-4000-8000-000000000000", SessionID: otherSess},
		To:    "node-1:" + sess, Parts: []a2a.Part{{Text: "are you editing src/a.go?"}}}
	raw, _ := json.Marshal(in)
	f.injectA2A(&nodev1.A2AEnvelope{Id: in.MessageID, From: other + ":" + otherSess, To: "node-1:" + sess, Text: "are you editing src/a.go?", MetaJson: string(raw), AtMs: in.TS})
	busFile := func() string {
		var all []byte
		_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				b, _ := os.ReadFile(p)
				all = append(all, b...)
			}
			return nil
		})
		return string(all)
	}
	waitFor(t, "the inbound message on the bus", func() bool { return strings.Contains(busFile(), in.MessageID) })
	bus := busFile()
	if !strings.Contains(bus, `"hostId":"`+other+`"`) || !strings.Contains(bus, `"to":"`+hostID+":"+sess+`"`) {
		t.Errorf("the bus holds the message without the Keleustes sender or the local addressee: %s", bus)
	}

	// The blackout: State says so, the relay stops, and a send is withheld.
	f.setControl(&nodev1.FactoryControl{A2ABlackout: true, Reason: "incident"}, 0)
	waitFor(t, "the blackout", relay.Blackout)
	if a2a.Blackout(dir) != true {
		t.Error("the host's blackout file was not set")
	}
	if relay.Outbound(env) {
		t.Error("an envelope went out during the blackout")
	}
	if f.p.Control().Reason != "incident" {
		t.Errorf("control = %+v", f.p.Control())
	}
}

// Welcome and Control frames are recorded for the host: a stopped factory
// refuses remote prompts, and the blackout reaches the A2A blackout file.
func TestLinkRecordsFactoryControl(t *testing.T) {
	f := newFakeKeleustes(t)
	f.welcome = &nodev1.FactoryControl{Stopped: true, Reason: "freeze"}
	var seen []Control
	var seenMu = make(chan Control, 8)
	l := NewLink(f.p, nil, func(context.Context, *nodev1.ServerFrame) error { return nil })
	l.OnControl(func(c Control) { seenMu <- c })
	l.Start(context.Background())
	defer l.Stop(time.Second)
	select {
	case c := <-seenMu:
		seen = append(seen, c)
	case <-time.After(10 * time.Second):
		t.Fatal("no control from the welcome")
	}
	if !seen[0].Stopped || f.p.Control().Reason != "freeze" {
		t.Fatalf("control = %+v / %+v", seen[0], f.p.Control())
	}
	if stopped, why := FactoryStopped(f.home); !stopped || why != "freeze" {
		t.Errorf("FactoryStopped = %v %q", stopped, why)
	}

	// A prompt is refused while stopped; a command still arrives.
	c, _ := NewClient(f.p)
	be := NewSyncBackend(c, "rc")
	defer be.Close()
	f.box("s1") <- &nodev1.InboxItem{Seq: 1, Id: "p1", SessionId: "s1", Body: &nodev1.InboxItem_Prompt{Prompt: &nodev1.Prompt{Text: "go"}}}
	f.box("s1") <- &nodev1.InboxItem{Seq: 2, Id: "c1", SessionId: "s1", Body: &nodev1.InboxItem_Command{Command: &nodev1.Command{Name: "stop"}}}
	var in sessionsync.Inbox
	waitFor(t, "the inbox", func() bool {
		got, _ := be.InboxBatchA2A(context.Background(), "", "s1", 200*time.Millisecond, -1)
		in.Prompts = append(in.Prompts, got.Prompts...)
		in.Commands = append(in.Commands, got.Commands...)
		return len(in.Commands) > 0
	})
	if len(in.Prompts) != 0 || in.Commands[0].Signal != "stop" {
		t.Fatalf("inbox = %+v", in)
	}
	select {
	case a := <-f.acks:
		if a.GetItemId() != "p1" || a.GetStatus() != "refused" || !strings.Contains(a.GetDetail(), "stopped: freeze") {
			t.Errorf("ack = %v", a)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stopped prompt was not refused")
	}
	// A console action that starts work is refused while stopped; undo, which
	// only puts files back, still arrives.
	f.box("s1") <- &nodev1.InboxItem{Seq: 3, Id: "a1", SessionId: "s1", Body: &nodev1.InboxItem_Command{Command: &nodev1.Command{Name: "compact"}}}
	f.box("s1") <- &nodev1.InboxItem{Seq: 4, Id: "a2", SessionId: "s1", Body: &nodev1.InboxItem_Command{Command: &nodev1.Command{Name: "undo"}}}
	in = sessionsync.Inbox{}
	waitFor(t, "the action inbox", func() bool {
		got, _ := be.InboxBatchA2A(context.Background(), "", "s1", 200*time.Millisecond, -1)
		in.Commands = append(in.Commands, got.Commands...)
		return len(in.Commands) > 0
	})
	if len(in.Commands) != 1 || in.Commands[0].Action != "undo" {
		t.Fatalf("actions while stopped = %+v", in.Commands)
	}
	select {
	case a := <-f.acks:
		if a.GetItemId() != "a1" || a.GetStatus() != "refused" || !strings.Contains(a.GetDetail(), "stopped: freeze") {
			t.Errorf("ack = %v", a)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stopped action was not refused")
	}

	// A Control frame resumes the factory and turns the blackout on.
	f.setControl(&nodev1.FactoryControl{A2ABlackout: true}, 1)
	select {
	case c := <-seenMu:
		if c.Stopped || !c.A2ABlackout {
			t.Errorf("control = %+v", c)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no control frame")
	}
	waitFor(t, "the ack of the control frame", func() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.linkAck >= 1 })
	if !a2a.Blackout(a2a.Dir(f.home)) || f.p.Control().Stopped {
		t.Errorf("after the frame: blackout file %v, control %+v", a2a.Blackout(a2a.Dir(f.home)), f.p.Control())
	}
}

const testKey = "sk-ant-keleustes-grant-ABCDEFGH12345678"

func testVaultGrant(exp time.Time) *nodev1.VaultGrant {
	return &nodev1.VaultGrant{GrantId: "grant-1", ExpiresAtMs: exp.UnixMilli(), Secrets: []*nodev1.VaultSecret{
		{Provider: "anthropic", Env: "ANTHROPIC_API_KEY", Value: testKey},
		{Provider: "Bad Provider", Env: "X", Value: "nope-nope-nope"},
		{Provider: "openai", Env: "lower-case", Value: "nope-nope-nope"},
	}}
}

// A grant never shows its values, whatever formats it, and round-trips the
// pipe only through Encode and ReadGrant.
func TestGrantNeverShowsItsValues(t *testing.T) {
	g := GrantFrom(testVaultGrant(time.Now().Add(time.Hour)), time.Now())
	if g == nil || len(g.Secrets(time.Now())) != 1 {
		t.Fatalf("grant = %v", g)
	}
	js, _ := json.Marshal(struct{ G *Grant }{g})
	for _, s := range []string{g.String(), fmt.Sprint(g), fmt.Sprintf("%v %+v %#v", g, g, g), string(js),
		fmt.Sprint(g.Secrets(time.Now())), fmt.Sprintf("%#v", g.Secrets(time.Now()))} {
		if strings.Contains(s, testKey) {
			t.Errorf("formatted grant shows its key: %s", s)
		}
	}
	read, err := ReadGrant(bytes.NewReader(g.Encode()), time.Now())
	if err != nil || read.Secrets(time.Now())[0].Value != testKey || read.ID() != "grant-1" {
		t.Fatalf("round trip = %v, %v", read, err)
	}
	if GrantFrom(testVaultGrant(time.Now().Add(-time.Second)), time.Now()) != nil {
		t.Error("an expired grant was taken")
	}
	if _, err := ReadGrant(bytes.NewReader(g.Encode()), time.Now().Add(2*time.Hour)); err == nil {
		t.Error("an expired grant was read")
	}
	g.Drop()
	if g.Live(time.Now()) || len(g.Secrets(time.Now())) != 0 || len(g.Encode()) > 0 && bytes.Contains(g.Encode(), []byte(testKey)) {
		t.Error("a dropped grant still holds its key")
	}
}

// A grant feeds one resolver's provider key and nothing else: not the
// process environment, not a base URL, not another provider's field.
func TestGrantFeedsOnlyItsResolver(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BELAI_HOME", home)
	t.Setenv("HOME", home)
	t.Setenv("ANTHROPIC_API_KEY", "")
	r, err := credentials.NewResolver(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	other, _ := credentials.NewResolver(t.TempDir())
	g := GrantFrom(&nodev1.VaultGrant{GrantId: "g", Secrets: []*nodev1.VaultSecret{
		{Provider: "anthropic", Env: "ANTHROPIC_API_KEY", Value: testKey},
		{Provider: "cloudflare-ai-gateway", Env: "CF_AIG_URL", Value: "https://evil.example/steal"},
		{Provider: "anthropic", Env: "BELAI_PROVIDER", Value: "should-not-apply-anywhere"},
	}}, time.Now())
	names := g.Apply(r)
	if strings.Join(names, ",") != "ANTHROPIC_API_KEY,CF_AIG_TOKEN" {
		// The anthropic key answers its field; the gateway value can only
		// answer the gateway's one secret field (its token), never its URL.
		t.Errorf("answered = %v", names)
	}
	if v, _, ok := r.Lookup("anthropic", "api_key"); !ok || v != testKey {
		t.Errorf("anthropic key = %q %v", v, ok)
	}
	if v, _, ok := r.Lookup("cloudflare-ai-gateway", "base_url"); ok && strings.Contains(v, "evil") {
		t.Error("a grant set a base URL")
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" || os.Getenv("BELAI_PROVIDER") != "" {
		t.Error("a grant reached the process environment")
	}
	if _, _, ok := other.Lookup("anthropic", "api_key"); ok {
		t.Error("a grant reached another resolver")
	}
	g.Drop()
	if _, _, ok := r.Lookup("anthropic", "api_key"); ok {
		t.Error("a dropped grant still answers")
	}
	// Nothing was written under the home.
	_ = filepath.Walk(home, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if b, _ := os.ReadFile(p); bytes.Contains(b, []byte(testKey)) {
				t.Errorf("the grant was written to %s", p)
			}
		}
		return nil
	})
}

// A CLI job's result rides to Keleustes on the card as belai.agent.cliResult,
// where the engine's scan step reads it (with notEvaluable for exit 3).
func TestCliResultReachesTheCard(t *testing.T) {
	doc, ok := clijobs.Clean(`{"job":"sca","exitCode":3,"counts":{"critical":0,"high":0,"medium":0,"low":0},"findings":[],"signals":[],"artifacts":[]}`)
	if !ok {
		t.Fatal("result did not clean")
	}
	k := ToKanbanItem(sessionsync.KanbanItem{ID: "c1", List: "done", Title: "sca",
		Agent: &sessionsync.KanbanAgent{CliResult: json.RawMessage(doc)}})
	var meta struct {
		Belai struct {
			Agent struct {
				CliResult struct {
					Job          string `json:"job"`
					NotEvaluable bool   `json:"notEvaluable"`
				} `json:"cliResult"`
			} `json:"agent"`
		} `json:"belai"`
	}
	if err := json.Unmarshal([]byte(k.GetMetaJson()), &meta); err != nil {
		t.Fatal(err)
	}
	if r := meta.Belai.Agent.CliResult; r.Job != "sca" || !r.NotEvaluable {
		t.Errorf("meta = %s", k.GetMetaJson())
	}
}
