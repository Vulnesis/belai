package rc

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/forgejob"
)

// forgeJobAudit opens an audit stream for the test and returns its path.
func forgeJobAudit(t *testing.T) string {
	t.Helper()
	rec, err := audit.Open(t.TempDir(), "host-a")
	if err != nil {
		t.Fatal(err)
	}
	audit.SetDefault(rec)
	t.Cleanup(func() { audit.SetDefault(nil); rec.Close() })
	return rec.Path()
}

// fakeForgeExec records each CLI run and answers ok.
func fakeForgeExec(t *testing.T) func() [][]string {
	t.Helper()
	prev := forgejob.Exec
	t.Cleanup(func() { forgejob.Exec = prev })
	var mu sync.Mutex
	var ran [][]string
	forgejob.Exec = func(_ context.Context, prog string, args []string, _ string, _ []string) (forgejob.Result, error) {
		mu.Lock()
		defer mu.Unlock()
		ran = append(ran, append([]string{prog}, args...))
		return forgejob.Result{Stdout: `{"login":"octo"}`, Exit: 0}, nil
	}
	return func() [][]string { mu.Lock(); defer mu.Unlock(); return slices.Clone(ran) }
}

func TestKeleustesForgeJob(t *testing.T) {
	t.Setenv("BELAI_HOME", t.TempDir())
	path := forgeJobAudit(t)
	ran := fakeForgeExec(t)
	ff := newFake()
	ff.jobs = []*nodev1.Job{
		{Id: "f1", Kind: "forge", PayloadJson: `{"cli":"gh","host":"github.com","args":["api","user"],"stdin":null}`},
		{Id: "f2", Kind: "forge", PayloadJson: `{"cli":"glab","host":"gitlab.acme.dev","args":["api","--hostname","gitlab.acme.dev","projects/1"],"stdin":null}`},
		// Outside the allowlist, another host, and a host this node has no login for.
		{Id: "f3", Kind: "forge", PayloadJson: `{"cli":"glab","host":"gitlab.acme.dev","args":["mr","checkout","1"]}`},
		{Id: "f4", Kind: "forge", PayloadJson: `{"cli":"gh","host":"github.com","args":["api","--hostname","ghe.evil.dev","user"]}`},
		{Id: "f5", Kind: "forge", PayloadJson: `{"cli":"tea","host":"codeberg.org","args":["api","/user"]}`},
		{Id: "f6", Kind: "forge", PayloadJson: `{"cli":"gh","host":"github.com","args":["auth","token"]}`},
	}
	got, _ := runFactoryDaemon(t, ff, Options{
		ForgeSignedIn: func(_ context.Context, cli, host string) bool {
			return (cli == "gh" && host == "github.com") || (cli == "glab" && host == "gitlab.acme.dev")
		},
	})
	for _, id := range []string{"f1", "f2"} {
		r := got[id]
		var out struct{ Stdout string }
		if r.GetStatus() != jobOK || json.Unmarshal([]byte(r.GetOutputJson()), &out) != nil || out.Stdout != `{"login":"octo"}` {
			t.Errorf("%s = %+v", id, r)
		}
	}
	for _, id := range []string{"f3", "f4", "f5", "f6"} {
		if r := got[id]; r.GetStatus() != jobRefused || r.GetError() == "" {
			t.Errorf("%s = %+v, want refused", id, r)
		}
	}
	if !strings.Contains(got["f5"].GetError(), "no signed-in tea login for codeberg.org") {
		t.Errorf("f5 = %q", got["f5"].GetError())
	}
	runs := ran()
	if len(runs) != 2 {
		t.Fatalf("ran %q", runs)
	}
	for _, r := range runs {
		host := map[string]string{"gh": "github.com", "glab": "gitlab.acme.dev"}[r[0]]
		if !slices.Equal(r[1:4], []string{"api", "--hostname", host}) || strings.Count(strings.Join(r, " "), "--hostname") != 1 {
			t.Errorf("ran %q: --hostname not forced once", r)
		}
	}
	// The advert says the node runs forge jobs, so Keleustes routes them here.
	if !slices.Contains(factoryJobKinds, "forge") || !slices.Contains(factoryJobKinds, "github") {
		t.Errorf("job kinds = %v", factoryJobKinds)
	}
	// Every outcome is a harness fact with the host and CLI, and the stream verifies.
	evs := readStream(t, path)
	if bad := audit.Verify(evs); bad != -1 || len(evs) == 0 {
		t.Fatalf("audit chain breaks at %d", bad)
	}
	seen := map[string]int{}
	for _, e := range evs {
		if e.Kind == string(audit.HostDispatch) && e.Data["kind"] == "forge" {
			seen[e.Data["status"]+" "+e.Data["tool"]+" "+e.Data["forge"]]++
		}
	}
	if seen["ok gh github.com"] != 1 || seen["ok glab gitlab.acme.dev"] != 1 || seen["refused tea codeberg.org"] != 1 {
		t.Errorf("audit = %v", seen)
	}
}

func TestKeleustesForgeJobKillSwitch(t *testing.T) {
	t.Setenv("BELAI_HOME", t.TempDir())
	path := forgeJobAudit(t)
	ran := fakeForgeExec(t)
	ff := newFake()
	ff.control = &factorylink.Control{Stopped: true, Reason: "freeze"}
	ff.jobs = []*nodev1.Job{{Id: "f1", Kind: "forge", PayloadJson: `{"cli":"gh","host":"github.com","args":["api","user"]}`}}
	got, _ := runFactoryDaemon(t, ff, Options{
		ForgeSignedIn: func(context.Context, string, string) bool { return true },
	})
	if r := got["f1"]; r.GetStatus() != jobRefused || !strings.Contains(r.GetError(), "stopped: freeze") {
		t.Errorf("f1 = %+v", r)
	}
	if len(ran()) != 0 {
		t.Errorf("a CLI ran while the factory was stopped: %q", ran())
	}
	found := false
	for _, e := range readStream(t, path) {
		if e.Kind == string(audit.HostDispatch) && e.Data["kind"] == "forge" && e.Data["status"] == "refused" && e.Data["reason"] == "kill_switch" {
			found = true
		}
	}
	if !found {
		t.Error("the refusal under the kill switch was not audited")
	}
}
