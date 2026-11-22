package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/testutil"
)

// Keleustes features with real binaries (keleustes docs/gaps/builtin-agents.md,
// library-search.md, sf-parity.md, belai-counterparts.md): a headless
// Keleustes, `belai connect` + `belai rc`, and the mock provider. Screen
// actions that have no command line verb (workflows, defaults, budgets, the
// vault, library search, project overrides) go through `kls_e2e`, an example
// binary in the keleustes repo that opens the same data directory and calls
// the library functions the screens call; the running app picks its events
// up through its event tail, so the app's engine, gateway and audit fold do
// the work. They run when KELEUSTES_BIN is set; KLS_E2E_BIN names the
// driver (default: examples/kls_e2e beside KELEUSTES_BIN,
// `cargo build -p kls-app --example kls_e2e`).

// drv runs the kls_e2e driver against a Keleustes data directory.
type drv struct {
	t         *testing.T
	bin, data string
}

func driver(t *testing.T, k *keleustes) *drv {
	t.Helper()
	bin := os.Getenv("KLS_E2E_BIN")
	if bin == "" {
		bin = filepath.Join(filepath.Dir(k.bin), "examples", "kls_e2e")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("no kls_e2e driver at %s (cargo build -p kls-app --example kls_e2e)", bin)
	}
	return &drv{t: t, bin: bin, data: k.data}
}

func (d *drv) try(args ...string) (string, error) {
	cmd := exec.Command(d.bin, append([]string{"--data", d.data}, args...)...)
	cmd.Env = append(os.Environ(), "RUST_LOG=warn")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		return strings.TrimSpace(out.String() + "\n" + errb.String()), err
	}
	return strings.TrimSpace(out.String()), nil
}

func (d *drv) run(args ...string) string {
	d.t.Helper()
	out, err := d.try(args...)
	if err != nil {
		d.t.Fatalf("kls_e2e %v: %v\n%s", args, err, out)
	}
	return out
}

// json decodes the last stdout line of a driver command into v.
func (d *drv) json(v any, args ...string) {
	d.t.Helper()
	out := d.run(args...)
	lines := strings.Split(out, "\n")
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), v); err != nil {
		d.t.Fatalf("kls_e2e %v: %v\n%s", args, err, out)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// eventually polls ok every 500ms until it holds, failing with what after d.
func eventually(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

type ledgerEntry struct {
	Seq       int64           `json:"seq"`
	Kind      string          `json:"kind"`
	Actor     string          `json:"actor"`
	ActorKind string          `json:"actor_kind"`
	Msg       string          `json:"msg"`
	Origin    string          `json:"origin"`
	Subject   json.RawMessage `json:"subject"`
	Payload   json.RawMessage `json:"payload"`
}

// ledger returns entries of kind ("" any) whose text matches text.
func (d *drv) ledger(kind, text string) []ledgerEntry {
	d.t.Helper()
	var es []ledgerEntry
	d.json(&es, "ledger", kind, text)
	return es
}

// waitLedger waits for an entry of kind matching text and every needle.
func (d *drv) waitLedger(kind, text string, needles ...string) ledgerEntry {
	d.t.Helper()
	var hit ledgerEntry
	eventually(d.t, 30*time.Second, fmt.Sprintf("ledger %s %q %v", kind, text, needles), func() bool {
		for _, e := range d.ledger(kind, text) {
			all := mustJSON(e)
			ok := true
			for _, n := range needles {
				ok = ok && strings.Contains(all, n)
			}
			if ok {
				hit = e
				return true
			}
		}
		return false
	})
	return hit
}

type runView struct {
	Status  string          `json:"status"`
	Reason  string          `json:"reason"`
	Trigger string          `json:"trigger"`
	Event   json.RawMessage `json:"event"`
	Steps   []struct {
		NodeID  string         `json:"nodeId"`
		Type    string         `json:"type"`
		Status  string         `json:"status"`
		Route   string         `json:"route"`
		Details map[string]any `json:"details"`
	} `json:"steps"`
}

func (d *drv) runView(id string) runView {
	d.t.Helper()
	var r runView
	d.json(&r, "run", id)
	return r
}

// waitRun waits for run id to reach one of the statuses.
func (d *drv) waitRun(id string, timeout time.Duration, statuses ...string) runView {
	d.t.Helper()
	var r runView
	deadline := time.Now().Add(timeout)
	for {
		r = d.runView(id)
		for _, s := range statuses {
			if r.Status == s {
				return r
			}
		}
		if time.Now().After(deadline) {
			d.t.Fatalf("run %s: want %v, have %s (%s)\nsteps: %s", id, statuses, r.Status, r.Reason, mustJSON(r.Steps))
		}
		time.Sleep(time.Second)
	}
}

func (d *drv) workflow(graph string) string {
	d.t.Helper()
	var w struct{ ID string }
	d.json(&w, "workflow", graph)
	return w.ID
}

func (d *drv) start(wf string, repo ...string) string {
	d.t.Helper()
	var r struct {
		RunID string `json:"runId"`
	}
	d.json(&r, append([]string{"start", wf}, repo...)...)
	return r.RunID
}

type nodeView struct {
	ID     string   `json:"id"`
	Agents []string `json:"agents"`
	// Routes are the worker profiles (HostAdvert.agent_routes).
	Routes []string `json:"routes"`
	Crews  []string `json:"crews"`
}

// waitNode waits until the node named label has advertised its agents.
func (d *drv) waitNode(label string) nodeView {
	d.t.Helper()
	var n nodeView
	eventually(d.t, 90*time.Second, label+" advertised its agents", func() bool {
		out, err := d.try("node", label)
		return err == nil && json.Unmarshal([]byte(out), &n) == nil && len(n.Agents) > 0
	})
	return n
}

// featureHost is one belai host joined to Keleustes running `belai rc`
// with the flags given; kill ends rc at once (no goodbye).
type featureHost struct {
	rcHost
	env  []string
	cmd  *exec.Cmd
	rlog string
}

func startFeatureRC(t *testing.T, k *keleustes, label, modelURL string, flags ...string) *featureHost {
	t.Helper()
	h := &featureHost{rcHost: rcHost{label: label, home: t.TempDir(), project: t.TempDir()}}
	if err := os.WriteFile(filepath.Join(h.project, "README.md"), []byte("demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A checkout: built-in workers isolate their work in a worktree.
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"remote", "add", "origin", "https://github.com/acme/api.git"},
		{"-c", "user.email=e2e@example.com", "-c", "user.name=e2e", "add", "-A"},
		{"-c", "user.email=e2e@example.com", "-c", "user.name=e2e", "commit", "--no-gpg-sign", "-q", "-m", "init"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = h.project
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Skipf("git %v: %v %s", args, err, out)
		}
	}
	h.env = belaiEnv(modelURL, h.home, "BELAI_PROVIDER=openai", "DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent/keleustes-e2e")
	connect := exec.Command(belaiBin, "connect", k.kel("token", "new", "--label", label))
	connect.Env = h.env
	if out, err := connect.CombinedOutput(); err != nil || !strings.Contains(string(out), "joined Keleustes") {
		t.Fatalf("belai connect: %v\n%s", err, out)
	}
	h.cmd = exec.Command(belaiBin, append([]string{"rc", "--dir", h.project, "--max", "2", "--web-controls"}, flags...)...)
	h.cmd.Env, h.cmd.Dir = h.env, h.project
	h.rlog = filepath.Join(t.TempDir(), label+"-rc.log")
	rlog, _ := os.Create(h.rlog)
	h.cmd.Stdout, h.cmd.Stderr = rlog, rlog
	if err := h.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if h.cmd.ProcessState == nil {
			_ = h.cmd.Process.Signal(os.Interrupt)
			done := make(chan struct{})
			go func() { _ = h.cmd.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				_ = h.cmd.Process.Kill()
				<-done
			}
		}
		if t.Failed() {
			b, _ := os.ReadFile(h.rlog)
			t.Logf("belai rc %s log:\n%s", label, tail(string(b), 6000))
		}
	})
	return h
}

func (h *featureHost) kill() {
	_ = h.cmd.Process.Kill()
	_ = h.cmd.Wait()
}

// featuresModel is newKeleustesModel plus SystemOne: a typed decision
// question is answered "yes" with p 0.95 (every choice question key).
func featuresModel(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := testutil.DecodeChat(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		var system, user string
		for _, m := range req.Messages {
			switch m.Role {
			case "system":
				system = m.Content
			case "user":
				user = m.Content
			}
		}
		reply := "mock reply"
		switch {
		case strings.Contains(system, "typed decision questions"):
			answers := map[string]map[string]float64{}
			for _, line := range strings.Split(user, "\n") {
				if k, _, ok := strings.Cut(strings.TrimPrefix(line, "- "), " (choice)"); ok && strings.HasPrefix(line, "- ") {
					answers[k] = map[string]float64{"yes": 0.95, "no": 0.05}
				}
			}
			reply = mustJSON(answers)
		case strings.Contains(system, "goal-progress evaluator"):
			reply = "GOAL_COMPLETE"
		case strings.Contains(system, "security classifier"):
			reply = securitySentinelFor(user)
		case strings.Contains(system, "operating-mode classifier"):
			reply = modeSentinelFor(user)
		case strings.Contains(system, "clarification questionnaire"):
			reply = `{"groups":[]}`
		case strings.Contains(system, "classifier"):
			reply = "SAFE"
		}
		if req.Stream {
			testutil.WriteChatStream(w, reply)
			return
		}
		testutil.WriteChatWithUsage(w, reply, 50, 5)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// TestKeleustesFeaturesBuiltins: the built-in catalogue, a worker step's
// routing card claimed by the belai worker, a SystemOne decision answered by
// the node's systemone model job, a seeded default triggered by a synthetic
// pull request event, the kill switch refusing new runs (audited) and the
// A2A blackout refusing a crew member's A2A.
func TestKeleustesFeaturesBuiltins(t *testing.T) {
	k := startKeleustes(t)
	d := driver(t, k)
	model := featuresModel(t)
	h := startFeatureRC(t, k, "f-builtins", model.URL)

	// 1. The catalogue: 58 profiles, 6 crews, each advertised by the node.
	var cat struct {
		Profiles     int      `json:"profiles"`
		Crews        int      `json:"crews"`
		ProfileNames []string `json:"profileNames"`
		CrewNames    []string `json:"crewNames"`
	}
	d.json(&cat, "catalogue")
	if cat.Profiles != 58 || cat.Crews != 6 {
		t.Errorf("catalogue = %d profiles, %d crews; want 58 and 6", cat.Profiles, cat.Crews)
	}
	n := d.waitNode(h.label)
	var missing []string
	for _, p := range cat.ProfileNames {
		if !contains(n.Agents, p) && !contains(n.Routes, p) {
			missing = append(missing, p)
		}
	}
	for _, c := range cat.CrewNames {
		if !contains(n.Crews, c) {
			missing = append(missing, "crew "+c)
		}
	}
	if len(missing) > 0 {
		t.Errorf("the node does not advertise %v (agents %d, crews %v)", missing, len(n.Agents), n.Crews)
	}
	t.Logf("catalogue %d/%d; node %s advertises %d session agents, %d worker routes, crews %v", cat.Profiles, cat.Crews, n.ID, len(n.Agents), len(n.Routes), n.Crews)

	// 2. A worker step files a routing card; the node's worker claims it
	// and finishes it against the mock provider.
	wf := d.workflow(mustJSON(map[string]any{
		"nodes": []any{
			map[string]any{"id": "t", "type": "trigger", "title": "Go", "config": map[string]any{"kind": "manual"}},
			map[string]any{"id": "b", "type": "crew", "title": "Scout", "config": map[string]any{
				"dispatch": "worker", "agent": "belai:ci-explainer", "brief": "Explain the failing check in this project.", "cwd": h.project}},
		},
		"edges": []any{map[string]any{"from": "t", "to": "b"}},
	}))
	rid := d.start(wf, "acme/api")
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("cards: %s", d.run("cards"))
			_ = filepath.WalkDir(h.home, func(p string, de fs.DirEntry, err error) error {
				if err == nil && !de.IsDir() && (strings.HasSuffix(p, ".log") || strings.HasSuffix(p, ".jsonl")) {
					b, _ := os.ReadFile(p)
					t.Logf("%s:\n%s", strings.TrimPrefix(p, h.home), tail(string(b), 1500))
				}
				return nil
			})
		}
	})
	r := d.waitRun(rid, 150*time.Second, "succeeded", "failed", "cancelled")
	var cardID string
	for _, s := range r.Steps {
		if s.NodeID == "b" {
			cardID, _ = s.Details["routeCardId"].(string)
		}
	}
	if r.Status != "succeeded" || cardID == "" {
		t.Fatalf("worker run = %s (%s), route card %q\nsteps %s", r.Status, r.Reason, cardID, mustJSON(r.Steps))
	}
	var cards []struct {
		ID, Status, Assignee string
		Labels               []string
	}
	d.json(&cards, "cards")
	for _, c := range cards {
		if c.ID == cardID {
			t.Logf("routing card %s: status %s labels %v assignee %q", c.ID, c.Status, c.Labels, c.Assignee)
			if c.Status != "done" {
				t.Errorf("routing card status %s, want done", c.Status)
			}
		}
	}
	d.waitLedger("", "route.file", rid)
	d.waitLedger("", "dispatch", rid)

	// 3. SystemOne: the decision is the node's systemone model job.
	wf = d.workflow(mustJSON(map[string]any{
		"nodes": []any{
			map[string]any{"id": "t", "type": "trigger", "title": "Go", "config": map[string]any{"kind": "manual"}},
			map[string]any{"id": "d", "type": "decision", "title": "Decide", "config": map[string]any{
				"question": "Is it a security fix?", "outcomes": []any{map[string]any{"value": "yes"}, map[string]any{"value": "no"}}, "threshold": 0.7}},
			map[string]any{"id": "y", "type": "notify", "title": "Yes", "config": map[string]any{"message": "y"}},
			map[string]any{"id": "n", "type": "notify", "title": "No", "config": map[string]any{"message": "n"}},
		},
		"edges": []any{
			map[string]any{"from": "t", "to": "d"},
			map[string]any{"from": "d", "to": "y", "outcome": "yes"},
			map[string]any{"from": "d", "to": "n", "outcome": "no"},
		},
	}))
	rid = d.start(wf)
	r = d.waitRun(rid, 2*time.Minute, "succeeded", "failed", "waiting_approval")
	route := ""
	for _, s := range r.Steps {
		if s.NodeID == "d" {
			route = s.Route
		}
	}
	if r.Status != "succeeded" || route != "yes" {
		t.Fatalf("decision run = %s (%s) route %q\nsteps %s", r.Status, r.Reason, route, mustJSON(r.Steps))
	}
	e := d.waitLedger("decision", "", rid)
	t.Logf("decision audited: actor %s %s", e.Actor, e.Msg)
	if !strings.HasPrefix(e.Actor, "systemone") {
		t.Errorf("decision actor %q, want systemone:<model>", e.Actor)
	}

	// 4. A seeded default triggers from a synthetic pull request event.
	d.run("managed-repo", "acme/api", "suggest")
	d.run("setting", "defaults.enabled", "true")
	var seed struct{ Created, Enabled int }
	d.json(&seed, "seed-defaults")
	var wfs []struct {
		ID, Name, SystemKey string
		Enabled             bool
	}
	d.json(&wfs, "workflows")
	var prReview string
	for _, w := range wfs {
		if strings.Contains(w.SystemKey, "pr-review") && w.Enabled {
			prReview = w.ID
		}
	}
	if seed.Created == 0 || prReview == "" {
		t.Fatalf("seed = %+v; workflows %s", seed, mustJSON(wfs))
	}
	pull := func(num int) {
		d.run("emit", "github.pull.opened", fmt.Sprintf("acme/api#%d", num), mustJSON(map[string]any{
			"repo": "acme/api", "number": num, "base": "main", "head": "feature/x", "action": "opened",
			"author": "ana", "draft": false, "fork": false, "labels": []string{}, "labelsAdded": []string{}}))
	}
	pull(7)
	var runs []struct{ ID, Status, Trigger, Reason string }
	eventually(t, 60*time.Second, "the pr-review default ran on the event", func() bool {
		d.json(&runs, "runs", prReview)
		return len(runs) > 0
	})
	r = d.waitRun(runs[0].ID, 2*time.Minute, "running", "waiting", "succeeded", "failed")
	t.Logf("default pr-review run %s: trigger %s status %s (%s) steps %s", runs[0].ID, r.Trigger, r.Status, r.Reason, mustJSON(r.Steps))
	if r.Trigger != "webhook" || !strings.Contains(string(r.Event), "acme/api#7") {
		t.Errorf("run trigger %s event %s", r.Trigger, r.Event)
	}
	eventually(t, 60*time.Second, "the reviewer step filed its routing card", func() bool {
		for _, s := range d.runView(runs[0].ID).Steps {
			if s.NodeID == "n4" && s.Details["routeCardId"] != nil {
				return true
			}
		}
		return false
	})

	// 5. Kill switch: new runs are refused and the refusal is audited; an
	// event does not start the default either.
	k.kel("host", "stop", "--reason", "e2e drill")
	if out, err := d.try("start", wf); err == nil || !strings.Contains(out, "stopped") {
		t.Fatalf("a run started under the kill switch: %v %s", err, out)
	}
	d.waitLedger("", "kill_switch", wf)
	pull(8)
	time.Sleep(3 * time.Second)
	d.json(&runs, "runs", prReview)
	if len(runs) != 1 {
		t.Errorf("an event started a run under the kill switch: %s", mustJSON(runs))
	}
	k.kel("host", "resume")

	// 6. A2A blackout: the node's relay goes dark and a crew member's
	// envelope is refused by Keleustes (audited a2a.withheld).
	k.kel("sessions", "a2a-blackout", "on", "--reason", "e2e drill")
	eventually(t, 30*time.Second, "the node learned the blackout", func() bool {
		b, _ := os.ReadFile(filepath.Join(h.home, "a2a", "blackout.json"))
		return strings.Contains(string(b), `"on":true`)
	})
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/keleustes-e2e")
	c, err := factorylink.ActiveClient(h.home)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res, err := c.A2ASend(ctx, &nodev1.A2AEnvelope{
		Id: "e2e-crew-a2a-1", From: n.ID + ":crew-bug-repro", To: n.ID + ":crew-bug-builder",
		Text: "repro done", AtMs: time.Now().UnixMilli(),
		MetaJson: `{"crew":"belai:bug","role":"repro","kind":"peer"}`,
	})
	if err != nil || res.GetRefused() == "" || res.GetDelivered() {
		t.Fatalf("crew A2A under blackout: err %v result %+v", err, res)
	}
	t.Logf("crew A2A under blackout refused: %q", res.GetRefused())
	d.waitLedger("", "a2a.withheld", "e2e-crew-a2a-1")
	k.kel("sessions", "a2a-blackout", "off", "--reason", "drill over")
	var v struct{ OK bool }
	d.json(&v, "verify")
	if !v.OK {
		t.Error("the audit chain does not verify")
	}
}

// TestKeleustesFeaturesLibrary: a credential-free search against live
// sources, one skill imported through the review step with its provenance
// and audit entry, the kill switch (local index only, import refused), then
// the skill distributed to the connected node. Needs the network.
func TestKeleustesFeaturesLibrary(t *testing.T) {
	if os.Getenv("KLS_LIVE_NET") != "1" {
		t.Skip("set KLS_LIVE_NET=1 (live library sources)")
	}
	k := startKeleustes(t)
	d := driver(t, k)
	model := featuresModel(t)
	h := startFeatureRC(t, k, "f-library", model.URL)

	// Live sources: two remote (searched as you type), three indexed.
	var sr struct {
		Live    []string `json:"live"`
		Offline []string `json:"offline"`
		Stopped bool     `json:"stopped"`
		Hits    []struct{ Source, Name, Type string }
	}
	d.json(&sr, "libsearch", "pdf")
	live := map[string]bool{}
	for _, s := range sr.Live {
		live[s] = true
	}
	for _, s := range []string{"gemini-gallery", "aitmpl", "gh:anthropics/skills"} {
		var rr struct {
			Refreshed int        `json:"refreshed"`
			Added     int        `json:"added"`
			Failed    [][]string `json:"failed"`
		}
		d.json(&rr, "librefresh", s)
		if rr.Refreshed == 1 && rr.Added > 0 {
			live[s] = true
		}
		t.Logf("refresh %s: %+v", s, rr)
	}
	t.Logf("live sources: %v (remote search live %v, offline %v, %d hits)", live, sr.Live, sr.Offline, len(sr.Hits))
	if len(live) < 3 {
		t.Fatalf("only %d live sources: %v", len(live), live)
	}

	// Import one skill through the review step.
	var imp struct {
		ID, Name, Source string
		URLs             []string `json:"urls"`
		Upstream         string   `json:"upstreamSha256"`
		Doc              string   `json:"docSha256"`
		AuditSeq         int64    `json:"auditSeq"`
	}
	d.json(&imp, "libimport", "pdf", "")
	if len(imp.URLs) == 0 || len(imp.Upstream) != 64 || len(imp.Doc) != 64 || imp.AuditSeq == 0 {
		t.Fatalf("provenance = %+v", imp)
	}
	e := d.waitLedger("library.imported", "", imp.Doc)
	if e.Seq != imp.AuditSeq {
		t.Errorf("ledger seq %d, provenance audit_seq %d", e.Seq, imp.AuditSeq)
	}
	t.Logf("imported skill %s from %s %v upstream %s doc %s (ledger #%d)", imp.Name, imp.Source, imp.URLs, imp.Upstream[:12], imp.Doc[:12], e.Seq)

	// Kill switch: the local index answers, import is refused (audited).
	k.kel("host", "stop", "--reason", "e2e drill")
	d.json(&sr, "libsearch", "pdf")
	if !sr.Stopped || len(sr.Live) != 0 || len(sr.Hits) == 0 {
		t.Errorf("search under the kill switch: stopped %v live %v hits %d", sr.Stopped, sr.Live, len(sr.Hits))
	}
	k.kel("host", "resume")
	if out, err := d.try("libimport", "pdf", "pdf-", "--stop-before-import"); err == nil {
		t.Fatalf("import went through under the kill switch: %s", out)
	}
	d.waitLedger("library.refused", "", "kill_switch")
	k.kel("host", "resume")

	// Distribute the imported skill to the node (WP-E).
	d.waitNode(h.label)
	out, err := k.try("sessions", "library", "--node", h.label, "--install", "skill:"+imp.Name)
	t.Logf("sessions library: %v %s", err, out)
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(out)
	did := f[len(f)-1]
	t.Cleanup(func() {
		if t.Failed() {
			out, _ := d.try("dispatch", did)
			t.Logf("library dispatch %s at failure: %s", did, out)
		}
	})
	var ds struct{ Status, Error string }
	eventually(t, 60*time.Second, "the library dispatch settled", func() bool {
		d.json(&ds, "dispatch", did)
		return ds.Status == "started" || ds.Status == "failed"
	})
	t.Logf("library dispatch %s: %s %s", did, ds.Status, ds.Error)
	if ds.Status != "started" {
		t.Fatalf("library install on the node: %s %s", ds.Status, ds.Error)
	}
	var found string
	eventually(t, 60*time.Second, "the node stored the skill", func() bool {
		_ = filepath.WalkDir(filepath.Join(h.home, "skills"), func(p string, de fs.DirEntry, err error) error {
			if err == nil && !de.IsDir() && strings.Contains(p, imp.Name) {
				found = p
			}
			return nil
		})
		return found != ""
	})
	t.Logf("node stored %s", found)
}

// TestKeleustesFeaturesVault: a key for a provider tested against a local
// fake endpoint: the save returns at once, the test state moves untested →
// testing → accepted (or refused, and the key is still saved), a dispatch
// grants it to the node, and the value appears nowhere in the database,
// outbox, logs or transcript.
func TestKeleustesFeaturesVault(t *testing.T) {
	k := startKeleustes(t)
	d := driver(t, k)
	model := featuresModel(t)
	var probes atomic.Int64
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probes.Add(1)
		time.Sleep(1500 * time.Millisecond)
		if r.Header.Get("Authorization") == "Bearer sk-e2e-good-0123456789" {
			_, _ = w.Write([]byte(`{"data":[]}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"bad key"}}`))
	}))
	t.Cleanup(fake.Close)
	d.run("provider", mustJSON(map[string]any{"id": "e2efake", "name": "E2E fake", "env": "E2EFAKE_API_KEY", "probe_url": fake.URL + "/v1/models"}))

	type saved struct {
		Saved  string `json:"saved"`
		SaveMs int64  `json:"saveMs"`
		State  string `json:"state"`
	}
	type settled struct {
		ID     string   `json:"id"`
		States []string `json:"states"`
		Status int64    `json:"status"`
	}
	save := func(value string) (saved, settled) {
		out := d.run("vault-save", "e2efake", "", value)
		lines := strings.Split(out, "\n")
		var a saved
		var b settled
		if json.Unmarshal([]byte(lines[0]), &a) != nil || json.Unmarshal([]byte(lines[len(lines)-1]), &b) != nil {
			t.Fatalf("vault-save: %s", out)
		}
		return a, b
	}
	a, b := save("sk-e2e-good-0123456789")
	t.Logf("good key: saved in %dms (%q), states %v status %v", a.SaveMs, a.State, b.States, b.Status)
	if a.SaveMs > 1000 || strings.Join(b.States, ">") != ">testing>accepted" {
		t.Errorf("good key: save %dms, states %v; want a quick save and untested>testing>accepted", a.SaveMs, b.States)
	}
	a, b = save("sk-e2e-wrong-0123456789")
	t.Logf("wrong key: saved in %dms, states %v status %v", a.SaveMs, b.States, b.Status)
	if a.SaveMs > 1000 || b.States[len(b.States)-1] != "refused" {
		t.Errorf("wrong key: save %dms, states %v", a.SaveMs, b.States)
	}
	var secrets []struct{ ID, Provider, State string }
	d.json(&secrets, "secrets")
	if len(secrets) != 1 || secrets[0].ID != a.Saved || secrets[0].State != "refused" {
		// The wrong key replaced the good one (same provider and variable),
		// and is kept although it was refused.
		t.Errorf("secrets = %+v", secrets)
	}
	d.waitLedger("vault", "", "refused")

	// The command line save (`sessions vault-key`) tests the key too.
	cmd := exec.Command(k.bin, "--data", k.data, "sessions", "vault-key", "--provider", "e2efake", "--env", "E2EFAKE_API_KEY")
	cmd.Env, cmd.Stdin = k.env, strings.NewReader("sk-e2e-good-0123456789")
	t0 := time.Now()
	idb, err := cmd.Output()
	if err != nil {
		t.Fatalf("vault-key: %v", err)
	}
	t.Logf("vault-key returned in %v", time.Since(t0))
	cliKey := strings.TrimSpace(string(idb))
	eventually(t, 30*time.Second, "the key saved from the command line was tested", func() bool {
		d.json(&secrets, "secrets")
		for _, s := range secrets {
			if s.ID == cliKey && s.State == "accepted" {
				return true
			}
		}
		return false
	})

	// Grant on dispatch: the node gets the key for this session only.
	h := startFeatureRC(t, k, "f-vault", model.URL)
	out := k.kel("sessions", "dispatch", "--node", h.label, "--cwd", h.project, "--prompt", "say hello with a key",
		"--provider", "openai", "--model", "test", "--mode", "agent", "--vault", "e2efake", "--wait", "90")
	var sid2 string
	for _, line := range strings.Split(out, "\n") {
		if s, ok := strings.CutPrefix(line, "session "); ok {
			sid2 = strings.TrimSpace(s)
		}
	}
	if sid2 == "" {
		t.Fatalf("dispatch with a grant: %s", out)
	}
	waitTranscript(t, k.kel, sid2, 90*time.Second, func(tr string) bool { return strings.Contains(tr, "mock reply") })
	d.waitLedger("vault", "", "granted")
	tr := k.kel("sessions", "transcript", sid2)

	// The value is nowhere at rest or in a log.
	const secret = "sk-e2e-good-0123456789"
	var leaks []string
	for _, f := range []string{"keleustes.db", "keleustes.db-wal", "keleustes.db-shm"} {
		if b, err := os.ReadFile(filepath.Join(k.data, f)); err == nil && bytes.Contains(b, []byte(secret)) {
			leaks = append(leaks, f)
		}
	}
	if b, _ := os.ReadFile(k.log); bytes.Contains(b, []byte(secret)) {
		leaks = append(leaks, "keleustes log")
	}
	if b, _ := os.ReadFile(h.rlog); bytes.Contains(b, []byte(secret)) {
		leaks = append(leaks, "rc log")
	}
	if strings.Contains(tr, secret) {
		leaks = append(leaks, "transcript")
	}
	if q, err := exec.Command("sqlite3", "-readonly", filepath.Join(k.data, "keleustes.db"), "select count(*) from node_outbox where instr(frame, cast('sk-e2e' as blob)) > 0").CombinedOutput(); err == nil {
		t.Logf("outbox rows holding the key: %s", strings.TrimSpace(string(q)))
		if strings.TrimSpace(string(q)) != "0" {
			leaks = append(leaks, "outbox")
		}
	}
	if len(leaks) > 0 {
		t.Fatalf("the key value leaked into %v", leaks)
	}
	t.Logf("probes served: %d; no plaintext in db, outbox, logs or transcript", probes.Load())
}

// TestKeleustesFeaturesParity: budgets stop a dispatch (audited), a branch
// condition suppresses a non-matching event, a node's sessions are marked
// lost after it disconnects, project overrides dispatch and are acked, and
// the CLI contract's --json envelope and exit codes for a wait timeout (5)
// and a kill-switch refusal (6).
func TestKeleustesFeaturesParity(t *testing.T) {
	k := startKeleustes(t)
	d := driver(t, k)
	model := featuresModel(t)
	h := startFeatureRC(t, k, "f-parity", model.URL, "--keleustes-manage=config", "--web-project-settings")
	n := d.waitNode(h.label)

	// Budgets: an exhausted hard-stop budget fails the dispatch step.
	d.run("budget", mustJSON(map[string]any{"name": "e2e cap", "applies_to": "all", "provider": "all", "period": "day",
		"limit_tokens": 10, "alert_at": []int{}, "action_at_limit": "hard_stop"}))
	wf := d.workflow(mustJSON(map[string]any{
		"nodes": []any{
			map[string]any{"id": "t", "type": "trigger", "title": "Go", "config": map[string]any{"kind": "manual"}},
			map[string]any{"id": "b", "type": "crew", "title": "Scout", "budget": map[string]any{"tokens": 5000},
				"config": map[string]any{"dispatch": "worker", "agent": "belai:scout", "brief": "Look around", "cwd": h.project}},
		},
		"edges": []any{map[string]any{"from": "t", "to": "b"}},
	}))
	rid := d.start(wf)
	r := d.waitRun(rid, 90*time.Second, "failed", "succeeded")
	if r.Status != "failed" || !strings.Contains(mustJSON(r), "budget_exceeded") {
		t.Errorf("budget run = %s (%s) %s", r.Status, r.Reason, mustJSON(r.Steps))
	}
	e := d.waitLedger("budget", "", "e2e cap")
	t.Logf("budget gate: run %s %s; ledger %s %s", r.Status, r.Reason, e.Kind, e.Msg)
	var cards []struct{ ID string }
	d.json(&cards, "cards")
	if len(cards) != 0 {
		t.Errorf("a routing card was filed for a dispatch the budget stopped: %d", len(cards))
	}

	// Trigger conditions: a pull request into dev does not start the
	// main-only workflow; one into main does.
	wf = d.workflow(mustJSON(map[string]any{
		"nodes": []any{
			map[string]any{"id": "t", "type": "trigger", "title": "PR", "config": map[string]any{
				"kind": "webhook", "event": "pull_request", "conditions": map[string]any{"baseBranches": []string{"main"}}}},
			map[string]any{"id": "b", "type": "notify", "title": "Say", "config": map[string]any{"message": "hi"}},
		},
		"edges": []any{map[string]any{"from": "t", "to": "b"}},
	}))
	pull := func(num int, base string) {
		d.run("emit", "github.pull.opened", fmt.Sprintf("acme/web#%d", num), mustJSON(map[string]any{
			"repo": "acme/web", "number": num, "base": base, "head": "feature/y", "action": "opened",
			"author": "ana", "draft": false, "fork": false, "labels": []string{}, "labelsAdded": []string{}}))
	}
	var runs []struct{ ID, Status, Trigger string }
	pull(1, "dev")
	time.Sleep(4 * time.Second)
	d.json(&runs, "runs", wf)
	if len(runs) != 0 {
		t.Fatalf("a dev pull request started the main-only workflow: %s", mustJSON(runs))
	}
	pull(2, "main")
	eventually(t, 30*time.Second, "a main pull request started the workflow", func() bool {
		d.json(&runs, "runs", wf)
		return len(runs) == 1
	})
	t.Logf("branch filter: dev suppressed, main started run %s (%s)", runs[0].ID, runs[0].Trigger)

	// Project overrides: sent as a project_prefs dispatch, then acked by
	// the node's inventory (both audited).
	k.inventory(t, h.label)
	// The directory as the node reports it in its inventory.
	var repos struct {
		Repos []struct {
			Path  string            `json:"path"`
			Prefs map[string]string `json:"prefs"`
		} `json:"repos"`
	}
	dir := ""
	eventually(t, 60*time.Second, "the inventory lists the project", func() bool {
		out, _ := k.try("host", "inventory", h.label)
		_ = json.Unmarshal([]byte(out), &repos)
		for _, r := range repos.Repos {
			if filepath.Base(r.Path) == filepath.Base(h.project) {
				dir = r.Path
			}
		}
		if dir == "" {
			t.Logf("inventory repos: %+v", repos.Repos)
		}
		return dir != ""
	})
	var pr struct {
		DispatchID string `json:"dispatchId"`
	}
	d.json(&pr, "prefs", n.ID, dir, "show_reasoning=false")
	d.waitLedger("", "settings.project_prefs", pr.DispatchID, "sent")
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("prefs dispatch: %s", d.run("dispatch", pr.DispatchID))
			for _, e := range d.ledger("", "settings.project_prefs") {
				t.Logf("prefs ledger: %s", e.Msg)
			}
			out, _ := k.try("host", "inventory", h.label)
			t.Logf("inventory: %s", tail(out, 3000))
		}
	})
	k.kel("host", "act", h.label, "inventory_refresh", "--wait", "30")
	eventually(t, 90*time.Second, "the node acknowledged the project prefs", func() bool {
		for _, e := range d.ledger("", "settings.project_prefs") {
			if strings.Contains(e.Msg, "outcome=applied") {
				t.Logf("project prefs ack: %s", e.Msg)
				return true
			}
		}
		_, _ = k.try("host", "act", h.label, "inventory_refresh", "--wait", "10")
		return false
	})

	// The CLI contract: a wait that times out exits 5 with a timeout
	// envelope; a dispatch under the kill switch exits 6.
	sid := k.dispatch(h.label, h.project, "say hello")
	waitTranscript(t, k.kel, sid, 90*time.Second, func(tr string) bool { return strings.Contains(tr, "mock reply") })
	envelope := func(args ...string) (map[string]any, int) {
		out, err := k.try(append([]string{"--json"}, args...)...)
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		lines := strings.Split(out, "\n")
		var env map[string]any
		for i := len(lines) - 1; i >= 0; i-- {
			if json.Unmarshal([]byte(lines[i]), &env) == nil {
				break
			}
		}
		return env, code
	}
	env, code := envelope("sessions", "wait", sid, "--for", "ended", "--timeout", "1s")
	t.Logf("wait timeout: exit %d envelope %s", code, mustJSON(env))
	if code != 5 || env["ok"] != false || env["code"] != "timeout" {
		t.Errorf("wait timeout: exit %d envelope %v", code, env)
	}
	k.kel("host", "stop", "--reason", "e2e drill")
	env, code = envelope("sessions", "dispatch", "--node", h.label, "--cwd", h.project, "--prompt", "refused", "--provider", "openai", "--model", "test")
	t.Logf("dispatch under stop: exit %d envelope %s", code, mustJSON(env))
	if code != 6 || env["ok"] != false || env["code"] != "refused_stopped" {
		t.Errorf("dispatch under stop: exit %d envelope %v", code, env)
	}
	k.kel("host", "resume")

	// Lost sessions: rc dies without a goodbye; once the node is offline
	// its open sessions end as lost (the sweep after the grace period; the
	// driver runs it now).
	h.kill()
	eventually(t, 90*time.Second, "the node went offline", func() bool {
		out, err := d.try("lost", n.ID)
		if err != nil {
			return false
		}
		var l struct{ Marked int }
		_ = json.Unmarshal([]byte(out), &l)
		t.Logf("lost: %s", out)
		return l.Marked > 0
	})
	v := k.show(sid)
	if v.State != "ended" || v.EndReason != "lost" {
		t.Errorf("session after its node vanished: %+v", v)
	}
	d.waitLedger("session", "", "session.lost")
}
