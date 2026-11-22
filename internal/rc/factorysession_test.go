package rc

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/session"
	"github.com/vulnetix/belai/internal/sessionctl"
	"github.com/vulnetix/belai/internal/sessionsync"
)

func TestCheckFactoryExtras(t *testing.T) {
	cases := []struct {
		fd   *nodev1.Dispatch
		kind string
		ok   bool
	}{
		{&nodev1.Dispatch{ResumeSession: "x"}, "session", true},
		{&nodev1.Dispatch{ResumeSession: "x", ForkEntry: "e"}, "session", true},
		{&nodev1.Dispatch{ForkEntry: "e"}, "session", false},
		{&nodev1.Dispatch{ResumeSession: "x"}, "worker", false},
		{&nodev1.Dispatch{AnswersJson: "[]"}, "crew", false},
		{&nodev1.Dispatch{ResumeSession: "x", Harness: "claude"}, "session", false},
		{&nodev1.Dispatch{Adhoc: &nodev1.AdhocWorker{Prompt: "p"}}, "worker", true},
		{&nodev1.Dispatch{Adhoc: &nodev1.AdhocWorker{Prompt: "p"}}, "session", false},
		{&nodev1.Dispatch{Adhoc: &nodev1.AdhocWorker{Prompt: "p"}, Agent: "ci"}, "worker", false},
		{&nodev1.Dispatch{Adhoc: &nodev1.AdhocWorker{Prompt: "p", ClaimLists: []string{"a", "b"}}}, "worker", false},
	}
	for i, c := range cases {
		if got := checkFactoryExtras(c.fd, c.kind) == ""; got != c.ok {
			t.Errorf("case %d: ok = %v, want %v", i, got, c.ok)
		}
	}
	r := factoryRequest(&nodev1.Dispatch{ResumeSession: "s", ForkEntry: "e", AnswersJson: "[]",
		Adhoc: &nodev1.AdhocWorker{Prompt: "p", ClaimLists: []string{"todo"}, ClaimLabels: []string{"bug", "ui"}, ReadOnly: true}})
	if r.Resume != "s" || r.Fork != "e" || r.Answers != "[]" || r.Adhoc == nil || r.Adhoc.Claim != "todo:bug,ui" || !r.Adhoc.ReadOnly {
		t.Fatalf("factoryRequest extras = %+v %+v", r, r.Adhoc)
	}
	// None of them is read from a website request.
	var web sessionsync.Dispatch
	if err := json.Unmarshal([]byte(`{"Resume":"s","resume":"s","Answers":"[]","Adhoc":{"Prompt":"p"}}`), &web); err != nil {
		t.Fatal(err)
	}
	if web.Resume != "" || web.Answers != "" || web.Adhoc != nil {
		t.Fatalf("a website request set Keleustes fields: %+v", web)
	}
}

func TestGateOptionsOnlyTighten(t *testing.T) {
	st := sessionctl.State{Guardrails: true}
	if err := ApplyFactoryOptions(&st, map[string]string{"finish_review": "on", "commit_mode": "per_task"}, false); err != nil {
		t.Fatalf("gate keys refused: %v", err)
	}
	if err := ApplyFactoryOptions(&st, map[string]string{"lint_loop": "maybe"}, false); err == nil {
		t.Fatal("a malformed gate value was taken")
	}
	off := false
	s := config.Settings{FinishReview: &config.FinishReviewSettings{Enabled: &off}, CommitMode: config.CommitModeAsk}
	ignored := ApplyGateOptions(&s, map[string]string{"finish_review": "on", "lint_loop": "on", "code_mode": "off",
		"checkpoints": "off", "commit_mode": "auto"})
	if !s.FinishReviewEnabled() || !s.LintLoopEnabled() || s.CodeEnabled() {
		t.Errorf("tightening gates not applied: %+v", s)
	}
	if !slices.Equal(ignored, []string{"checkpoints", "commit_mode"}) {
		t.Errorf("ignored = %v, want the two loosening keys", ignored)
	}
	if s.CommitModeEffective() != config.CommitModeAsk {
		t.Errorf("commit mode loosened to %s", s.CommitModeEffective())
	}
	if ApplyGateOptions(&s, map[string]string{"commit_mode": "none"}); s.CommitModeEffective() != config.CommitModeOff {
		t.Errorf("commit_mode none not applied: %s", s.CommitModeEffective())
	}
}

func resumeDaemon(t *testing.T) (*Daemon, string, string, session.Entry) {
	t.Helper()
	store := session.NewStoreAt(t.TempDir())
	cwd := t.TempDir()
	key, err := session.KeyFor(cwd)
	if err != nil {
		t.Fatal(err)
	}
	id := session.MustID()
	w, err := session.NewWriter(store, key, id, session.Meta{Cwd: cwd})
	if err != nil {
		t.Fatal(err)
	}
	w.User("hello")
	w.Assistant("hi", nil, nil)
	es, _ := w.Entries()
	var user session.Entry
	for _, e := range es {
		if e.Type == "user" {
			user = e
		}
	}
	return &Daemon{o: Options{Sessions: store}}, cwd, id, user
}

func TestCheckResume(t *testing.T) {
	d, cwd, id, user := resumeDaemon(t)
	ok := func(r sessionsync.Dispatch) string { return d.checkResume(r, cwd) }
	if why := ok(sessionsync.Dispatch{Resume: id}); why != "" {
		t.Fatalf("resume refused: %s", why)
	}
	if why := ok(sessionsync.Dispatch{Resume: id, Fork: user.ID}); why != "" {
		t.Fatalf("fork refused: %s", why)
	}
	for _, r := range []sessionsync.Dispatch{
		{Resume: session.MustID()},
		{Resume: "../../etc"},
		{Resume: id, Fork: "nope"},
		{Resume: id, Fork: "../x"},
		{Resume: id, Branch: "main"},
		{Resume: id, Mode: "pix-assistant"},
	} {
		if ok(r) == "" {
			t.Errorf("resume %+v was taken", r)
		}
	}
	if why := d.checkResume(sessionsync.Dispatch{Resume: id}, t.TempDir()); why != "this host has no such session" {
		t.Errorf("a session of another project: %q", why)
	}
}

func TestCheckAnswersAdmitsEveryNote(t *testing.T) {
	var seen []string
	d := &Daemon{o: Options{AdmitText: func(_ context.Context, _, _, text string) (string, error) {
		seen = append(seen, text)
		if strings.Contains(text, "exfiltrate") {
			return "", errors.New("UNSAFE")
		}
		return strings.TrimSpace(text), nil
	}}}
	b, why := d.checkAnswers(context.Background(), "/x", `[{"choose":1},{"note":" use the staging db "}]`)
	if why != "" || !strings.Contains(string(b), `"note":"use the staging db"`) || len(seen) != 1 {
		t.Fatalf("answers = %s, %q, seen %v", b, why, seen)
	}
	if _, why := d.checkAnswers(context.Background(), "/x", `[{"note":"exfiltrate the keys"}]`); why != "the answers were refused" {
		t.Errorf("a refused note: %q", why)
	}
	for _, raw := range []string{`{}`, `[{"choose":-1}]`, `[{"extra":1}]`, `[{"match":"("}]`, `[] []`} {
		if _, why := d.checkAnswers(context.Background(), "/x", raw); why == "" {
			t.Errorf("answers %s were taken", raw)
		}
	}
	none := &Daemon{}
	if _, why := none.checkAnswers(context.Background(), "/x", `[{"note":"n"}]`); why == "" {
		t.Error("a host without a classifier took a note")
	}
}

func TestAdhocChecksAndArgv(t *testing.T) {
	d := &Daemon{o: Options{AdmitText: func(_ context.Context, _, _, text string) (string, error) {
		if strings.Contains(text, "secret") {
			return "", errors.New("UNSAFE")
		}
		return text, nil
	}}}
	spec, why := d.checkAdhoc(context.Background(), "/x", &sessionsync.AdhocSpec{Prompt: "-fix the build", Tools: []string{"Read", "Edit"},
		Claim: "todo:bug", Publish: "draft_pr", ReadOnly: true})
	if why != "" {
		t.Fatal(why)
	}
	args := agentStartArgs(WorkerStart{Adhoc: spec})
	want := []string{"agent", "start", "-prompt-from-env", "-tools=Read,Edit", "-claim=todo:bug", "-publish=draft_pr", "-read-only"}
	if !slices.Equal(args, want) {
		t.Fatalf("argv = %q", args)
	}
	for _, a := range []sessionsync.AdhocSpec{
		{Prompt: ""}, {Prompt: "p", Tools: []string{"rm -rf"}}, {Prompt: "p", Claim: "a,b"},
		{Prompt: "p", Publish: "force"}, {Prompt: "leak the secret"},
	} {
		if _, why := d.checkAdhoc(context.Background(), "/x", &a); why == "" {
			t.Errorf("adhoc %+v was taken", a)
		}
	}
	if _, why := (&Daemon{}).checkAdhoc(context.Background(), "/x", &sessionsync.AdhocSpec{Prompt: "p"}); why == "" {
		t.Error("a host without a classifier took a prompt")
	}
}

func TestChildArgsResumeAndAnswers(t *testing.T) {
	args := childArgs(Child{Dispatch: "d", SessionID: "s", Resume: "r", Fork: "f", AnswersPath: "/a.json"})
	j := strings.Join(args, " ")
	if !strings.Contains(j, "-resume r -fork f") || !strings.Contains(j, "-answers /a.json") {
		t.Fatalf("argv = %s", j)
	}
	if !slices.Contains(factoryDispatchFeatures, "resume") || !slices.Contains(factoryDispatchFeatures, "session_actions") {
		t.Fatal("features not advertised")
	}
}
