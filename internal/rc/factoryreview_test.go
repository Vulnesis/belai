package rc

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// stubReview is a ReviewJob runner standing in for `belai review`: it records
// what it was asked and answers a fixed result.
type stubReview struct {
	mu      sync.Mutex
	jobs    []ReviewJob
	secrets [][]string
	res     *nodev1.ReviewResult
	why     string
}

func (s *stubReview) run(_ context.Context, j ReviewJob, g *factorylink.Grant) (*nodev1.ReviewResult, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs = append(s.jobs, j)
	var vals []string
	for _, sec := range g.Secrets(time.Now()) {
		vals = append(vals, sec.Value)
	}
	s.secrets = append(s.secrets, vals)
	return s.res, s.why, nil
}

func reviewPayload(t *testing.T, v map[string]any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestKeleustesReviewJobs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BELAI_HOME", home)
	path := forgeJobAudit(t)
	proj := t.TempDir()
	real, _ := Normalize(proj)
	sha := strings.Repeat("ab", 20)
	stub := &stubReview{res: &nodev1.ReviewResult{
		Verdict: "request_changes", Target: "pr", HeadSha: sha, Pr: 7, Files: 3, Dropped: 1,
		Findings: []*nodev1.ReviewFinding{
			{Path: "a.go", Line: 2, Severity: "major", Criterion: "correctness", Body: "nil map write\x1b[31m", Fix: "make the map"},
			{Path: "../etc/passwd", Line: 1, Severity: "major", Criterion: "security", Body: "x"},
			{Path: "b.go", Line: 4, Severity: "urgent", Criterion: "security", Body: "x"},
		},
	}}
	ff := newFake()
	ff.jobs = []*nodev1.Job{
		{Id: "r1", Kind: "review", Vault: testGrant(time.Now().Add(time.Minute)),
			PayloadJson: reviewPayload(t, map[string]any{"cwd": real, "target": "pr", "ref": "7", "runId": "run-1"})},
		{Id: "r2", Kind: "review", PayloadJson: reviewPayload(t, map[string]any{"cwd": real, "target": "everything"})},
		{Id: "r3", Kind: "review", PayloadJson: reviewPayload(t, map[string]any{"cwd": "/etc", "target": "workdir"})},
		{Id: "r4", Kind: "review", PayloadJson: reviewPayload(t, map[string]any{"cwd": real, "target": "branch", "ref": "--upload-pack=x"})},
		{Id: "r5", Kind: "review", PayloadJson: reviewPayload(t, map[string]any{"cwd": real, "target": "pr", "ref": "7; rm"})},
		{Id: "r6", Kind: "review", PayloadJson: reviewPayload(t, map[string]any{"cwd": real, "target": "branch", "ref": "feature", "base": "main", "force": true})},
	}
	got, log := runFactoryDaemon(t, ff, Options{
		Dirs:      []Dir{{Path: real, Name: "proj", Source: SourceTrusted}},
		ReviewJob: stub.run,
	})
	r := got["r1"]
	if r.GetStatus() != jobOK {
		t.Fatalf("r1 = %+v", r)
	}
	var res nodev1.ReviewResult
	if err := protojson.Unmarshal([]byte(r.GetOutputJson()), &res); err != nil {
		t.Fatal(err)
	}
	if res.GetVerdict() != "request_changes" || res.GetHeadSha() != sha || res.GetPr() != 7 || len(res.GetFindings()) != 1 {
		t.Fatalf("result = %v", &res)
	}
	if f := res.GetFindings()[0]; f.GetPath() != "a.go" || f.GetLine() != 2 || strings.Contains(f.GetBody(), "\x1b") || f.GetFix() != "make the map" {
		t.Errorf("finding = %v", f)
	}
	// The two findings outside the closed lists are dropped and counted.
	if res.GetDropped() != 3 {
		t.Errorf("dropped = %d", res.GetDropped())
	}
	for _, id := range []string{"r2", "r3", "r4", "r5"} {
		if r := got[id]; r.GetStatus() != jobRefused || r.GetError() == "" {
			t.Errorf("%s = %+v, want refused", id, r)
		}
	}
	if r := got["r6"]; r.GetStatus() != jobOK {
		t.Errorf("r6 = %+v", r)
	}
	stub.mu.Lock()
	jobs, secrets := stub.jobs, stub.secrets
	stub.mu.Unlock()
	if len(jobs) != 2 {
		t.Fatalf("the runner ran %d reviews: %+v", len(jobs), jobs)
	}
	for i, j := range jobs {
		switch j.Target {
		case "pr":
			if j.Dir != real || j.Ref != "7" || len(secrets[i]) != 1 || secrets[i][0] != grantSecret {
				t.Errorf("pr job = %+v, %d secrets", j, len(secrets[i]))
			}
		case "branch":
			if j.Ref != "feature" || j.Base != "main" || !j.Force {
				t.Errorf("branch job = %+v", j)
			}
		default:
			t.Errorf("unexpected job %+v", j)
		}
	}
	assertNoSecret(t, home, log.String())
	// Each review is a harness fact with its target, pull request and files.
	seen := map[string]int{}
	for _, e := range readStream(t, path) {
		if e.Kind == string(audit.HostDispatch) && e.Data["kind"] == "review" {
			seen[e.Data["status"]+" "+e.Data["target"]+" "+e.Data["pr"]+" "+e.Data["files"]]++
		}
	}
	if seen["ok pr 7 3"] != 1 || seen["refused   "] != 4 {
		t.Errorf("audit = %v", seen)
	}
}

func TestKeleustesReviewJobKillSwitch(t *testing.T) {
	t.Setenv("BELAI_HOME", t.TempDir())
	path := forgeJobAudit(t)
	proj := t.TempDir()
	real, _ := Normalize(proj)
	stub := &stubReview{res: &nodev1.ReviewResult{Verdict: "comment"}}
	ff := newFake()
	ff.control = &factorylink.Control{Stopped: true, Reason: "freeze"}
	ff.jobs = []*nodev1.Job{{Id: "r1", Kind: "review", PayloadJson: reviewPayload(t, map[string]any{"cwd": real})}}
	got, _ := runFactoryDaemon(t, ff, Options{
		Dirs:      []Dir{{Path: real, Name: "proj", Source: SourceTrusted}},
		ReviewJob: stub.run,
	})
	if r := got["r1"]; r.GetStatus() != jobRefused || !strings.Contains(r.GetError(), "stopped: freeze") {
		t.Fatalf("r1 = %+v", r)
	}
	if len(stub.jobs) != 0 {
		t.Fatal("a review ran while the factory was stopped")
	}
	found := false
	for _, e := range readStream(t, path) {
		found = found || e.Kind == string(audit.HostDispatch) && e.Data["kind"] == "review" &&
			e.Data["status"] == "refused" && e.Data["reason"] == "kill_switch"
	}
	if !found {
		t.Error("the refusal under the kill switch was not audited")
	}
}

func TestReviewJobWithoutRunnerOrRequest(t *testing.T) {
	d, root := p6Daemon(t, Options{})
	if _, why := d.runReviewJob(reviewPayload(t, map[string]any{"cwd": root}), nil, map[string]string{}); why == "" {
		t.Fatal("a host with no review runner took the job")
	}
	d, root = p6Daemon(t, Options{ReviewJob: (&stubReview{}).run})
	for _, bad := range []string{`not json`, `{}`, `{"repo":"acme/none"}`, strings.Repeat("x", 9<<10),
		reviewPayload(t, map[string]any{"cwd": root, "target": "workdir", "ref": "main"}),
		reviewPayload(t, map[string]any{"cwd": root, "target": "pr", "ref": "7", "base": "main"}),
		reviewPayload(t, map[string]any{"cwd": root, "target": "branch", "ref": "a..b"}),
		reviewPayload(t, map[string]any{"cwd": root, "model": "bad model!"}),
	} {
		if _, why := d.runReviewJob(bad, nil, map[string]string{}); why == "" {
			t.Errorf("accepted %.80s", bad)
		}
	}
}

func TestReviewJobResultChecksEveryField(t *testing.T) {
	long := strings.Repeat("x", maxReviewBody+1)
	in := &nodev1.ReviewResult{Verdict: "merge it", Target: "everything", HeadSha: "not-a-sha"}
	for i := 0; i < maxReviewFindings+2; i++ {
		in.Findings = append(in.Findings, &nodev1.ReviewFinding{Path: "a.go", Line: uint32(i + 1), Severity: "minor", Criterion: "docs", Body: "ok"})
	}
	in.Findings = append(in.Findings,
		&nodev1.ReviewFinding{Path: "/abs.go", Line: 1, Severity: "minor", Criterion: "docs", Body: "x"},
		&nodev1.ReviewFinding{Path: ".git/config", Line: 1, Severity: "minor", Criterion: "docs", Body: "x"},
		&nodev1.ReviewFinding{Path: "a.go", Line: 0, Severity: "minor", Criterion: "docs", Body: "x"},
		&nodev1.ReviewFinding{Path: "a.go", Line: 1, Severity: "minor", Criterion: "vibes", Body: "x"},
		&nodev1.ReviewFinding{Path: "a.go", Line: 1, Severity: "minor", Criterion: "docs", Body: long},
	)
	out, err := reviewJobResult(in)
	if err != nil {
		t.Fatal(err)
	}
	var res nodev1.ReviewResult
	if err := protojson.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	if res.GetVerdict() != "comment" || !res.GetIncomplete() || res.GetTarget() != "" || res.GetHeadSha() != "" {
		t.Errorf("result = %v", &res)
	}
	if len(res.GetFindings()) != maxReviewFindings || res.GetDropped() != 7 {
		t.Errorf("%d findings, %d dropped", len(res.GetFindings()), res.GetDropped())
	}
	// request_changes with nothing serious left is only a comment.
	out, _ = reviewJobResult(&nodev1.ReviewResult{Verdict: "request_changes", Findings: []*nodev1.ReviewFinding{
		{Path: "a.go", Line: 1, Severity: "nit", Criterion: "docs", Body: "x"},
		{Path: "a.go", Line: 1, Severity: "blocker", Criterion: "nope", Body: "x"},
	}})
	if err := protojson.Unmarshal(out, &res); err != nil || res.GetVerdict() != "comment" {
		t.Errorf("narrowed verdict = %q (%v)", res.GetVerdict(), err)
	}
	if out, err := reviewJobResult(nil); err != nil || !strings.Contains(string(out), "comment") {
		t.Errorf("nil result = %s (%v)", out, err)
	}
}
