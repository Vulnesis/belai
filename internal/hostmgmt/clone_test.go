package hostmgmt

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// repo_clone goes to <first workspace_dir>/<name> at the depth asked for
// (§5.6), the preview shows both, and the hook receives exactly them.
func TestRepoCloneTargetsTheWorkspaceDirAtDepth(t *testing.T) {
	var got []CloneRequest
	e := newEnv(t, LevelProvision, func(o *Options) {
		o.Hooks.Clone = func(_ context.Context, r CloneRequest) (string, string) {
			got = append(got, r)
			return filepath.Join(r.Parent, r.Dir), ""
		}
	})
	ws := filepath.Join(e.user, "code")
	if err := os.MkdirAll(ws, 0o700); err != nil {
		t.Fatal(err)
	}
	e.writeSettings(`{"workspace_dirs":["~/code","~/other"]}`)
	params := map[string]string{"forge_host": "github.com", "owner": "acme", "name": "web", "depth": "50"}
	dry := last(e.act(&nodev1.HostAction{Kind: "repo_clone", DryRun: true, Params: params}))
	if dry.GetState() != stateDone {
		t.Fatalf("dry run = %s %s", dry.GetState(), dry.GetError())
	}
	pj := dry.GetPreviewJson()
	for _, want := range []string{`"target":"~/code/web"`, `"depth":"50"`, "--depth", "https://github.com/acme/web.git"} {
		if !strings.Contains(pj, want) {
			t.Errorf("preview lacks %s: %s", want, pj)
		}
	}
	if strings.Contains(pj, "depth is not applied") || strings.Contains(pj, e.user) {
		t.Errorf("preview: %s", pj)
	}
	u := last(e.act(&nodev1.HostAction{Kind: "repo_clone", PreviewSha256: dry.GetPreviewSha256(), Params: params}))
	if u.GetState() != stateDone {
		t.Fatalf("clone = %s %s", u.GetState(), u.GetError())
	}
	if len(got) != 1 || got[0].Parent != ws || got[0].Dir != "web" || got[0].Depth != 50 || got[0].Owner != "acme" {
		t.Fatalf("hook got %+v", got)
	}
	if !strings.Contains(u.GetResultJson(), `"path":"~/code/web"`) {
		t.Fatalf("result %s", u.GetResultJson())
	}
}

// Without workspace_dirs the clone falls back to the worktrees directory and
// the plan says so; a target that exists and is not that repository is
// refused before anything runs.
func TestRepoCloneFallsBackAndRefusesAnOccupiedTarget(t *testing.T) {
	called := 0
	e := newEnv(t, LevelProvision, func(o *Options) {
		o.Hooks.Clone = func(context.Context, CloneRequest) (string, string) { called++; return "", "" }
	})
	e.writeSettings(`{}`)
	params := map[string]string{"forge_host": "git.example.test:8443", "owner": "team/sub", "name": "api"}
	dry := last(e.act(&nodev1.HostAction{Kind: "repo_clone", DryRun: true, Params: params}))
	if dry.GetState() != stateDone || !strings.Contains(dry.GetPreviewJson(), "no workspace_dirs") ||
		!strings.Contains(dry.GetPreviewJson(), "~/worktrees/repos/git.example.test_8443/team/sub/api") {
		t.Fatalf("fallback preview = %s %s %s", dry.GetState(), dry.GetError(), dry.GetPreviewJson())
	}
	if strings.Contains(dry.GetPreviewJson(), "--depth") {
		t.Fatalf("no depth asked: %s", dry.GetPreviewJson())
	}
	ws := filepath.Join(e.user, "code")
	if err := os.MkdirAll(filepath.Join(ws, "web"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "web", "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.writeSettings(`{"workspace_dirs":["~/code"]}`)
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "repo_clone", DryRun: true,
		Params: map[string]string{"forge_host": "github.com", "owner": "acme", "name": "web"}}), "not a git checkout")
	if called != 0 {
		t.Fatal("a dry run cloned")
	}
}

// A release base from the environment is kept only on a loopback address.
func TestLoopbackOverride(t *testing.T) {
	const def = "https://github.com/Vulnesis/belai/releases/download"
	for raw, want := range map[string]string{
		"":                                 def,
		"http://127.0.0.1:9999/rel/":       "http://127.0.0.1:9999/rel",
		"https://[::1]:8443/r":             "https://[::1]:8443/r",
		"https://example.com/r":            def,
		"http://10.0.0.1/r":                def,
		"http://localhost/r":               def,
		"file:///tmp/r":                    def,
		"http://user:pw@127.0.0.1/r":       def,
		"http://127.0.0.1.example.com/r":   def,
		"http://127.0.0.1/r?redirect=evil": def,
	} {
		if got := loopbackOverride(raw, def); got != want {
			t.Errorf("%q -> %q, want %q", raw, got, want)
		}
	}
	t.Setenv("BELAI_E2E_RELEASES", "https://evil.example/r")
	t.Setenv("VULNETIX_E2E_RELEASES", "http://127.0.0.1:1/cli")
	e := newEnv(t, LevelRead)
	if e.m.o.BelaiReleases != def || e.m.o.CLIReleases != "http://127.0.0.1:1/cli" {
		t.Fatalf("releases %q %q", e.m.o.BelaiReleases, e.m.o.CLIReleases)
	}
}
