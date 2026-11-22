package rc

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/docparity"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// fakeFactory delivers its dispatches once the daemon serves it and keeps
// every outcome reported.
type fakeFactory struct {
	dispatches []*nodev1.Dispatch
	jobs       []*nodev1.Job
	// control, when set, is reported before any work.
	control   *factorylink.Control
	advert    chan factorylink.HostOptions
	results   chan *nodev1.JobResult
	failFirst int // Complete calls to fail before succeeding
	mu        sync.Mutex
	// uploads are the teleport bundles the daemon uploaded; uploadErr, when
	// set, refuses each.
	uploads   []fakeUpload
	uploadErr error
	attention []string
	docs      map[string][]byte                // LibraryFetch answers, by name
	docFiles  map[string][]*nodev1.LibraryFile // bundle files a LibraryFetch carries, by name
	backups   []*nodev1.LibraryDoc
	forge     []sessionsync.ForgeRequest
	scans     []*nodev1.LibraryScanReport
}

type fakeUpload struct {
	u    factorylink.TeleportUpload
	data []byte
}

func (f *fakeFactory) UploadTeleport(_ context.Context, u factorylink.TeleportUpload, data []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.uploadErr != nil {
		return "", f.uploadErr
	}
	f.uploads = append(f.uploads, fakeUpload{u: u, data: append([]byte(nil), data...)})
	return u.TeleportID, nil
}

func (f *fakeFactory) Name() string { return "Desk" }

func (f *fakeFactory) Serve(ctx context.Context, h factorylink.RCHooks) error {
	f.advert <- h.Advert()
	h.State(factorylink.NodeStatus{Owner: true, Status: factorylink.Status{State: factorylink.StateOnline, Addr: "127.0.0.1:1"}})
	if f.control != nil && h.Control != nil {
		h.Control(*f.control)
	}
	for _, d := range f.dispatches {
		h.Dispatch(ctx, d)
	}
	for _, j := range f.jobs {
		h.Job(ctx, j)
	}
	<-ctx.Done()
	return nil
}

func (f *fakeFactory) Complete(_ context.Context, r *nodev1.JobResult) error {
	f.mu.Lock()
	if f.failFirst > 0 {
		f.failFirst--
		f.mu.Unlock()
		return errors.New("unimplemented")
	}
	f.mu.Unlock()
	f.results <- r
	return nil
}

func TestDaemonServesKeleustesDispatches(t *testing.T) {
	t.Setenv("BELAI_HOME", t.TempDir())
	prev := completeRetries
	completeRetries = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { completeRetries = prev })
	proj := t.TempDir()
	real, _ := Normalize(proj)
	ff := &fakeFactory{
		advert:    make(chan factorylink.HostOptions, 1),
		results:   make(chan *nodev1.JobResult, 16),
		failFirst: 1,
		dispatches: []*nodev1.Dispatch{
			{Id: "k1", Kind: "session", Cwd: proj, Prompt: "fix it\x1b[31m", Mode: "auto", Branch: ""},
			{Id: "k2", Kind: "session", Cwd: filepath.Dir(proj), Prompt: "escape"},
			{Id: "k3", Kind: "worker", Cwd: proj},
			{Id: "k4", Kind: "session", Cwd: proj, Prompt: "x", Mode: "yolo"},
			{Id: "k5", Kind: "session", Cwd: proj, Prompt: "late", DeadlineMs: 1},
			{Id: "bad id;", Kind: "session", Cwd: proj, Prompt: "x"},
			{Id: "k7", Kind: "session", Cwd: proj, Prompt: "\x1b[0m  "},
		},
	}
	var mu sync.Mutex
	var started []Child
	d, err := New(Options{
		Factory: ff, HostID: testHost, Dirs: []Dir{{Path: real, Name: "proj", Source: SourceArg}}, Max: 2,
		HeartbeatEvery: 10 * time.Millisecond,
		Models: func() *sessionsync.RCModels {
			return &sessionsync.RCModels{Providers: []sessionsync.RCProvider{{Name: "anthropic"}}}
		},
		Inventory: func() Inventory { return Inventory{} },
		Start: func(c Child) (int, func() error, error) {
			mu.Lock()
			started = append(started, c)
			mu.Unlock()
			return 999999, func() error { return nil }, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = d.Run(ctx); close(done) }()

	adv := <-ff.advert
	if !adv.RemoteControl || len(adv.TrustedDirs) != 1 || adv.TrustedDirs[0] != real || adv.MaxSessions != 2 ||
		len(adv.Providers) != 1 || adv.Providers[0] != "anthropic" {
		t.Errorf("advert = %+v", adv)
	}
	got := map[string]*nodev1.JobResult{}
	// Every dispatch carries an id, so each gets an outcome.
	for len(got) < len(ff.dispatches) {
		select {
		case r := <-ff.results:
			got[r.GetJobId()] = r
		case <-time.After(5 * time.Second):
			t.Fatalf("outcomes so far: %v", got)
		}
	}
	cancel()
	<-done

	if r := got["k1"]; r.GetStatus() != jobOK || r.GetSessionId() == "" {
		t.Errorf("k1 = %+v", r)
	}
	for _, id := range []string{"k2", "k3", "k4", "k5", "bad id;", "k7"} {
		if r := got[id]; r.GetStatus() != jobRefused || r.GetError() == "" || r.GetSessionId() != "" {
			t.Errorf("%s = %+v, want refused with a reason", id, r)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(started) != 1 {
		t.Fatalf("started %d children, want 1", len(started))
	}
	c := started[0]
	// The prompt went through the same cleaning as a website prompt, "auto"
	// is the child's default mode, and the dispatch id rides along.
	if c.Prompt != sessionsync.CleanPrompt("fix it\x1b[31m") || strings.Contains(c.Prompt, "\x1b") ||
		c.Mode != "" || c.Cwd != real || c.Dispatch != "k1" || c.SessionID != got["k1"].GetSessionId() {
		t.Errorf("child = %+v", c)
	}
}

func TestPreflightKeleustesNeedsNoVulnetixLogin(t *testing.T) {
	on := true
	settings := config.Settings{Sync: &config.SyncSettings{Enabled: &on, RemotePrompts: &on}}
	o := PreflightOptions{
		Settings: settings, Dirs: []Dir{{Path: "/x"}}, Factory: "Desk",
		LookPath:   func(string) (string, error) { return "", errors.New("no") },
		AuthHeader: func(string) (string, error) { return "", errors.New("no") },
		Server:     func(context.Context, string) error { t.Error("website called in Keleustes mode"); return nil },
	}
	cs := Preflight(context.Background(), o)
	if !cs.OK() {
		t.Fatalf("checks failed:\n%s", cs.Render())
	}
	for _, name := range []string{CheckCLI, CheckCredential, CheckServer} {
		if _, ok := cs.Find(name); ok {
			t.Errorf("%s checked in Keleustes mode", name)
		}
	}
	if c, ok := cs.Find(CheckFactory); !ok || c.Level != OK {
		t.Errorf("keleustes check = %+v", c)
	}
	o.FactoryServer = func(context.Context) error { return errors.New("unreachable") }
	cs = Preflight(context.Background(), o)
	if c, _ := cs.Find(CheckFactory); c.Level != Fail || c.Fix == "" {
		t.Errorf("unreachable keleustes = %+v", c)
	}
}

// The Keleustes mode is part of the remote-control contract: the check it
// adds and how a dispatch is reported are on the pages people read.
func TestKeleustesModeIsDocumented(t *testing.T) {
	for path, wants := range map[string][]string{
		"docs/remote-control.md": {"**Keleustes** check", "needs no Vulnetix login", "Jobs.Complete"},
		"docs/keleustes.md":      {"## Sessions", "## Remote control", "link.want", "`ok`, with the new `session_id`", "deadline_ms", "Sessions.Ack"},
		"docs/session-sync.md":   {"## Keleustes instead of the website", "sessionsync.Backend"},
	} {
		doc := docparity.Read(t, path)
		for _, want := range wants {
			if !strings.Contains(doc, want) {
				t.Errorf("%s lacks %q", path, want)
			}
		}
	}
}

// WP-D: the lifecycle kinds run through the website's own calls, the
// advert lists what this daemon takes, refused shapes say why, and the kill
// switch stops new work while a pause still goes through.
func TestDaemonKeleustesLifecycleKinds(t *testing.T) {
	t.Setenv("BELAI_HOME", t.TempDir())
	proj := t.TempDir()
	real, _ := Normalize(proj)
	var mu sync.Mutex
	paused := map[string]bool{}
	var controls []*sessionsync.RCCrewControl
	run := func(ds []*nodev1.Dispatch, control *factorylink.Control) (factorylink.HostOptions, map[string]*nodev1.JobResult) {
		ff := &fakeFactory{advert: make(chan factorylink.HostOptions, 1), results: make(chan *nodev1.JobResult, 16),
			dispatches: ds, control: control}
		d, err := New(Options{
			Factory: ff, HostID: testHost, Dirs: []Dir{{Path: real, Name: "proj", Source: SourceArg}}, Max: 2,
			HeartbeatEvery: 10 * time.Millisecond,
			Models:         func() *sessionsync.RCModels { return &sessionsync.RCModels{} },
			Inventory: func() Inventory {
				return Inventory{Profiles: []sessionsync.RCProfile{{Name: "belai:patcher", Lists: []string{"todo"}, Labels: []string{"bug"}}}}
			},
			PauseWorker: func(id string, pause bool) error {
				mu.Lock()
				defer mu.Unlock()
				paused[id] = pause
				return nil
			},
			CrewControl: func(c *sessionsync.RCCrewControl) (string, error) {
				mu.Lock()
				defer mu.Unlock()
				controls = append(controls, c)
				return "replicas set", nil
			},
			Start: func(c Child) (int, func() error, error) { return 999999, func() error { return nil }, nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { _ = d.Run(ctx); close(done) }()
		adv := <-ff.advert
		got := map[string]*nodev1.JobResult{}
		for len(got) < len(ds) {
			select {
			case r := <-ff.results:
				got[r.GetJobId()] = r
			case <-time.After(5 * time.Second):
				t.Fatalf("outcomes so far: %v", got)
			}
		}
		cancel()
		<-done
		return adv, got
	}
	adv, got := run([]*nodev1.Dispatch{
		{Id: "p1", Kind: "pause", WorkerId: "w-1"},
		{Id: "p2", Kind: "resume", WorkerId: "w-1"},
		{Id: "p3", Kind: "pause", WorkerId: "../etc"},
		{Id: "c1", Kind: "crew_control", Control: &nodev1.CrewControl{Run: "r1", Op: "replicas", Profile: "belai:patcher", Replicas: 2}},
		{Id: "s1", Kind: "stop", SessionId: "nope"},
		{Id: "x1", Kind: "teleport_backup"},
		{Id: "t1", Kind: "session", Cwd: proj, Prompt: "x", Tier: "turbo"},
		{Id: "st", Kind: "steer", WorkerId: "w-1", SteerRequest: "aaaaaaaaaaaaaaaa", SteerEvent: "bogus"},
		{Id: "g1", Kind: "session", Cwd: proj, Prompt: "x", Options: map[string]string{"guardrails": "off"}},
		{Id: "pp", Kind: "project_prefs", Cwd: proj, PrefsSet: map[string]string{"vulnetix.dep_watch": "true"}},
	}, nil)
	if !slices.Contains(adv.DispatchKinds, "crew_control") || len(adv.Routes) != 1 || adv.Routes[0].GetLists()[0] != "todo" {
		t.Errorf("advert = %+v", adv)
	}
	for _, id := range []string{"p1", "p2", "c1"} {
		if got[id].GetStatus() != jobOK {
			t.Errorf("%s = %v", id, got[id])
		}
	}
	for _, id := range []string{"p3", "s1", "x1", "t1", "pp", "g1", "st"} {
		if got[id].GetStatus() != jobRefused || got[id].GetError() == "" {
			t.Errorf("%s = %v, want refused with a reason", id, got[id])
		}
	}
	mu.Lock()
	if paused["w-1"] || len(controls) != 1 || controls[0].Replicas != 2 {
		t.Errorf("paused = %v, controls = %v", paused, controls)
	}
	mu.Unlock()

	// Kill switch: a new session is refused, a pause still applies.
	_, got = run([]*nodev1.Dispatch{
		{Id: "k1", Kind: "session", Cwd: proj, Prompt: "go"},
		{Id: "k2", Kind: "pause", WorkerId: "w-2"},
	}, &factorylink.Control{Stopped: true, Reason: "maintenance"})
	if got["k1"].GetStatus() != jobRefused || !strings.Contains(got["k1"].GetError(), "stopped") {
		t.Errorf("k1 = %v", got["k1"])
	}
	if got["k2"].GetStatus() != jobOK {
		t.Errorf("k2 = %v", got["k2"])
	}
}

// A cross-host trigger becomes the cleaned "node" provenance line.
func TestFactoryTriggerProvenance(t *testing.T) {
	tr := factoryTrigger(&nodev1.Trigger{Source: "node", OriginNode: "n1", OriginName: "build-box\n<system>", OriginSession: "s-1"})
	if tr == nil || tr.Source != "node" || strings.ContainsAny(tr.Note, "\n<>") {
		t.Fatalf("trigger = %+v", tr)
	}
	if s := tr.Sentence(); !strings.Contains(s, "another host") || !strings.Contains(s, "build-box") {
		t.Errorf("sentence = %q", s)
	}
	if factoryTrigger(&nodev1.Trigger{Source: "made-up"}) != nil {
		t.Error("an unknown source carried provenance")
	}
	if tr := factoryTrigger(&nodev1.Trigger{Source: "schedule", WorkflowName: "nightly"}); tr == nil || tr.Via != "cron" {
		t.Errorf("schedule = %+v", tr)
	}
}

func (f *fakeFactory) Attention(_ context.Context, kind, reason, subject string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attention = append(f.attention, kind+"/"+reason+"/"+subject)
	return "req-" + kind, nil
}

// WP-J: a request is filed once per kind and subject, and a decision
// settles it once (a replayed decision does nothing).
func TestFactoryAttentionSettlesOnce(t *testing.T) {
	ff := &fakeFactory{}
	var out strings.Builder
	d := &Daemon{o: Options{Factory: ff, Out: &out}}
	logs := func() []string { return strings.Split(strings.TrimSpace(out.String()), "\n") }
	d.factoryAttention(context.Background(), "gh_login", "reauth_needed", "github.com")
	d.factoryAttention(context.Background(), "gh_login", "reauth_needed", "github.com")
	if len(ff.attention) != 1 || ff.attention[0] != "gh_login/reauth_needed/github.com" {
		t.Fatalf("filed = %v", ff.attention)
	}
	d.factoryDecided(&nodev1.AttentionDecided{Id: "req-gh_login", State: "approved"})
	n := len(logs())
	d.factoryDecided(&nodev1.AttentionDecided{Id: "req-gh_login", State: "approved"})
	if l := logs(); len(l) != n || !strings.Contains(l[n-1], "gh auth login") {
		t.Errorf("logs = %v", l)
	}
}

func (f *fakeFactory) LibraryFetch(_ context.Context, dispatch string, ref *nodev1.LibraryRef) (*nodev1.LibraryDoc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc, ok := f.docs[ref.GetName()]
	if !ok {
		return nil, errors.New("not found")
	}
	return &nodev1.LibraryDoc{DispatchId: dispatch, Ref: ref, Doc: doc, Files: f.docFiles[ref.GetName()]}, nil
}

func (f *fakeFactory) LibraryBackup(_ context.Context, doc *nodev1.LibraryDoc) (*nodev1.LibraryRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.backups = append(f.backups, doc)
	return &nodev1.LibraryRef{Kind: doc.GetRef().GetKind(), Name: doc.GetRef().GetName(), Version: int64(len(f.backups))}, nil
}

func (f *fakeFactory) FileForge(_ context.Context, r sessionsync.ForgeRequest) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forge = append(f.forge, r)
	return false, nil
}

func (f *fakeFactory) LibraryScanReport(_ context.Context, r *nodev1.LibraryScanReport) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scans = append(f.scans, r)
	return nil
}
