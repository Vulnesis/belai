package rc

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/vulnetix/belai/internal/budget"
	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/fleet"
	"github.com/vulnetix/belai/internal/knowledge"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// p6Daemon is a daemon over one offered directory with the fleet registry,
// the indexers and the draft hook replaced.
func p6Daemon(t *testing.T, o Options) (*Daemon, string) {
	t.Helper()
	t.Setenv("BELAI_HOME", t.TempDir())
	proj := t.TempDir()
	real, _ := Normalize(proj)
	o.Factory = &fakeFactory{advert: make(chan factorylink.HostOptions, 1), results: make(chan *nodev1.JobResult, 4)}
	o.HostID = testHost
	o.Dirs = []Dir{{Path: real, Name: "proj", Source: SourceTrusted}}
	o.Models = func() *sessionsync.RCModels { return &sessionsync.RCModels{} }
	o.Inventory = func() Inventory { return Inventory{} }
	d, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return d, real
}

func liveWorker(t *testing.T, reg *fleet.Registry, id, session, run string) {
	t.Helper()
	if err := reg.Save(fleet.Record{ID: id, Profile: "belai:patcher", PID: os.Getpid(), State: fleet.StateWorking,
		Session: session, Run: run, Started: time.Now().UnixMilli()}); err != nil {
		t.Fatal(err)
	}
}

func TestBudgetUpdateAppliesToMatchingLiveWorkers(t *testing.T) {
	reg := fleet.NewRegistry(t.TempDir(), nil)
	d, _ := p6Daemon(t, Options{Fleet: func() (*fleet.Registry, error) { return reg, nil }})
	liveWorker(t, reg, "w-a", "s-1", "r-1")
	liveWorker(t, reg, "w-b", "s-2", "r-2")
	push := func(p *nodev1.BudgetPush, f func(*nodev1.Dispatch)) (string, string) {
		fd := &nodev1.Dispatch{Id: "b1", Kind: "budget_update", BudgetPush: p}
		if f != nil {
			f(fd)
		}
		_, rep, why, _ := d.factoryStart(context.Background(), fd, nil)
		return rep, why
	}
	// Pause narrows to a session; resume to a run.
	if rep, why := push(&nodev1.BudgetPush{Action: "pause", BudgetId: "bud-1", SessionIds: []string{"S-1"}}, nil); why != "" || !strings.Contains(rep, "1 worker") {
		t.Fatalf("pause: %q %q", rep, why)
	}
	if !reg.Paused("w-a") || reg.Paused("w-b") {
		t.Fatal("pause reached the wrong workers")
	}
	if _, why := push(&nodev1.BudgetPush{Action: "resume"}, func(fd *nodev1.Dispatch) { fd.RunId = "r-1" }); why != "" || reg.Paused("w-a") {
		t.Fatalf("resume: %q", why)
	}
	// Downgrade: the fast model in each worker's control (all match).
	if rep, why := push(&nodev1.BudgetPush{Action: "downgrade", Tier: "fast"}, func(fd *nodev1.Dispatch) { fd.Provider, fd.Model = "openai", "gpt-mini" }); why != "" || !strings.Contains(rep, "2 workers") {
		t.Fatalf("downgrade: %q %q", rep, why)
	}
	if c, _ := reg.Control("w-b"); c.Target != (fleet.Target{Provider: "openai", Model: "gpt-mini"}) || c.By != "factory" {
		t.Fatalf("control = %+v", c)
	}
	// Limits: lowered only, and a second push cannot raise them.
	lim := func(tok uint32) func(*nodev1.Dispatch) {
		return func(fd *nodev1.Dispatch) {
			fd.WorkerId, fd.Budget = "w-a", &nodev1.WorkerBudget{MaxTokens: tok, PriceInputPerMtok: 3}
		}
	}
	if _, why := push(&nodev1.BudgetPush{Action: "limits"}, lim(500)); why != "" {
		t.Fatal(why)
	}
	if _, why := push(&nodev1.BudgetPush{Action: "limits"}, lim(9000)); why != "" {
		t.Fatal(why)
	}
	if c, _ := reg.Control("w-a"); c.Limits == nil || c.Limits.MaxTokensPerItem != 500 || c.Limits.Price != nil {
		t.Fatalf("limits = %+v", c.Limits)
	}
	// Refusals: every field is checked.
	for name, tc := range map[string]struct {
		p *nodev1.BudgetPush
		f func(*nodev1.Dispatch)
	}{
		"no push":       {nil, nil},
		"action":        {&nodev1.BudgetPush{Action: "spend"}, nil},
		"tier":          {&nodev1.BudgetPush{Action: "downgrade", Tier: "turbo"}, func(fd *nodev1.Dispatch) { fd.Model = "m" }},
		"no model":      {&nodev1.BudgetPush{Action: "downgrade", Tier: "fast"}, nil},
		"worker id":     {&nodev1.BudgetPush{Action: "pause"}, func(fd *nodev1.Dispatch) { fd.WorkerId = "../x" }},
		"session id":    {&nodev1.BudgetPush{Action: "pause", SessionIds: []string{"a b"}}, nil},
		"budget id":     {&nodev1.BudgetPush{Action: "pause", BudgetId: "x;rm"}, nil},
		"empty limits":  {&nodev1.BudgetPush{Action: "limits"}, nil},
		"tier on pause": {&nodev1.BudgetPush{Action: "pause", Tier: "fast"}, nil},
	} {
		if _, why := push(tc.p, tc.f); why == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	// The kill switch refuses a push.
	d.setFactoryControl(factorylink.Control{Stopped: true, Reason: "maintenance"})
	if _, why := push(&nodev1.BudgetPush{Action: "pause"}, nil); !strings.Contains(why, "stopped") {
		t.Fatalf("under the kill switch: %q", why)
	}
}

func TestKnowledgeReindexChecksItsTargetAndReadvertises(t *testing.T) {
	var ran []string
	d, root := p6Daemon(t, Options{IndexProject: func(_ context.Context, _ string, r string) (string, error) {
		ran = append(ran, r)
		return " (2 documents)", nil
	}})
	start := func(opts map[string]string) (string, string) {
		_, rep, why, _ := d.factoryStart(context.Background(), &nodev1.Dispatch{Id: "k1", Kind: "knowledge_reindex", Options: opts}, nil)
		return rep, why
	}
	pk, _ := knowledge.ProjectKey(root)
	if _, why := start(map[string]string{"scope": "project", "key": pk}); why != "" {
		t.Fatalf("by project key: %q", why)
	}
	if _, why := start(map[string]string{"scope": "project", "key": strings.Repeat("0", 64)}); why == "" {
		t.Fatal("an unknown project key was reindexed")
	}
	<-d.readvertCh()
	ran = nil
	rep, why := start(map[string]string{"scope": "project", "root": root})
	if why != "" || !strings.Contains(rep, "2 documents") || len(ran) != 1 || ran[0] != root {
		t.Fatalf("reindex: %q %q %v", rep, why, ran)
	}
	select {
	case <-d.readvertCh():
	default:
		t.Fatal("a reindex did not ask for the advert again")
	}
	for name, opts := range map[string]map[string]string{
		"other root":    {"scope": "project", "root": "/etc"},
		"no scope":      {"root": root},
		"bad profile":   {"scope": "profile", "key": "not-an-id"},
		"unknown prof":  {"scope": "profile", "key": "0190b0a4-8d9e-7b3c-9f00-0000000000aa"},
		"session key":   {"scope": "project", "root": root, "guardrails": "off"},
		"unknown scope": {"scope": "repo", "root": root},
	} {
		if _, why := start(opts); why == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	// The reindex keys are not session options for any other kind.
	if why := checkFactoryOptions(dispatchOptions(&nodev1.Dispatch{Kind: "session", Options: map[string]string{"scope": "project"}}), false); why == "" {
		t.Fatal("a session took a reindex key")
	}
	d.setFactoryControl(factorylink.Control{Stopped: true})
	if _, why := start(map[string]string{"scope": "project", "root": root}); why == "" {
		t.Fatal("a reindex ran under the kill switch")
	}
}

func TestKnowledgeSearchAnswersFromTheIndexOnly(t *testing.T) {
	d, root := p6Daemon(t, Options{})
	ix := indexWith(t, knowledge.Address(knowledge.ProjectScope, "docs/runbook.md"))
	dir, err := config.ProjectKnowledgeDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ix.Save(dir); err != nil {
		t.Fatal(err)
	}
	run, why := d.runKnowledgeSearchJob(`{"query":"deploy key","scope":"project","limit":500}`)
	if why != "" {
		t.Fatal(why)
	}
	out, why, err := run(context.Background())
	if err != nil || why != "" {
		t.Fatal(why, err)
	}
	var res nodev1.KnowledgeSearchResult
	if err := protojson.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Hits) != 1 || !knowledge.IsAddress(res.Hits[0].GetAddress()) || len(res.Hits[0].GetSnippet()) > maxKnowledgeSnippet ||
		res.Hits[0].GetSha256() != strings.Repeat("a", 64) || !strings.HasPrefix(res.Hits[0].GetIndex(), "project:") {
		t.Fatalf("hits = %v", res.Hits)
	}
	if strings.Contains(string(out), "/home/u/docs") {
		t.Fatalf("a host path left the host: %s", out)
	}
	for _, bad := range []string{`{"query":""}`, `{"query":"x","scope":"repo"}`, `not json`, `{"query":"` + strings.Repeat("x", 9000) + `"}`} {
		if _, why := d.runKnowledgeSearchJob(bad); why == "" {
			t.Errorf("accepted %.40s", bad)
		}
	}
	if s := snippet(strings.Repeat("é", 400)); len(s) > maxKnowledgeSnippet {
		t.Fatalf("snippet is %d bytes", len(s))
	}
}

func TestInitDraftJobResolvesAnOfferedRepoAndWritesNothing(t *testing.T) {
	var gotDir string
	d, root := p6Daemon(t, Options{InitDraft: func(_ context.Context, dir, provider, model string, _ *factorylink.Grant) (InitDraft, string, error) {
		gotDir = dir
		return InitDraft{Path: "AGENTS.md", Markdown: "# Agents\n\x1b[31mbuild with make\n", SHA256: strings.Repeat("c", 64)}, "", nil
	}})
	payload, _ := json.Marshal(map[string]string{"cwd": root, "model": "m-1"})
	run, why := d.runInitDraftJob(string(payload), nil)
	if why != "" {
		t.Fatal(why)
	}
	out, why, err := run(context.Background())
	if err != nil || why != "" || gotDir != root {
		t.Fatal(why, err, gotDir)
	}
	var res nodev1.InitDraftResult
	if err := protojson.Unmarshal(out, &res); err != nil || res.GetPath() != "AGENTS.md" || strings.Contains(res.GetMarkdown(), "\x1b") {
		t.Fatalf("result %v (%v)", &res, err)
	}
	if ents, _ := os.ReadDir(root); len(ents) != 0 {
		t.Fatalf("the draft wrote into the repository: %v", ents)
	}
	for _, bad := range []string{`{"cwd":"/etc"}`, `{}`, `{"repo":"not a repo"}`, `{"cwd":"` + root + `","model":"bad model!"}`, `{"repo":"acme/none"}`} {
		if _, why := d.runInitDraftJob(bad, nil); why == "" {
			t.Errorf("accepted %s", bad)
		}
	}
	if _, why := (&Daemon{}).runInitDraftJob(string(payload), nil); why == "" {
		t.Fatal("a host with no draft hook took the job")
	}
	if _, _, err := initDraftResult(InitDraft{Path: "../x", Markdown: "x", SHA256: strings.Repeat("c", 64)}); err == nil {
		t.Fatal("a draft for another path was encoded")
	}
}

func TestPlanLimitsRideTheHostStatus(t *testing.T) {
	now := time.Now()
	d, _ := p6Daemon(t, Options{PlanLimits: func() []budget.PlanLimit {
		return []budget.PlanLimit{
			{Provider: "anthropic", Window: budget.WindowFiveHour, Used: 0.5, Reset: now.Add(150 * time.Minute)},
			{Provider: "anthropic", Window: budget.WindowMinRequests, Used: 0.1, Reset: now.Add(30 * time.Second)},
			{Provider: "anthropic", Window: budget.WindowMinInput, Used: 0.1, Reset: now.Add(30 * time.Second)},
		}
	}})
	st := d.withPlanLimits(&nodev1.HostStatus{})
	if len(st.PlanLimits) != 2 || st.PlanLimits[0].GetWindow() != "5h" || st.PlanLimits[1].GetWindow() != "rpm" {
		t.Fatalf("plan limits = %v", st.PlanLimits)
	}
	if p := st.PlanLimits[0]; p.GetPace() < 0.9 || p.GetPace() > 1.1 || p.GetRunwayMs() <= 0 || p.GetSource() != "exact" {
		t.Fatalf("5h = %v", p)
	}
}

func TestReadLimitsIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/usage.json"
	if got := budget.ReadLimits(path, time.Now()); got != nil {
		t.Fatalf("no ledger: %v", got)
	}
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := budget.ReadLimits(path, time.Now()); got != nil {
		t.Fatalf("corrupt ledger: %v", got)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("a corrupt ledger was moved by a read-only reader")
	}
}
