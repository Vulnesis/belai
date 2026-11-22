package forgejob

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// checkGHStub stands in for rc.checkGHArgs: it refuses gh auth.
func checkGHStub(args []string) string {
	if args[0] == "auth" {
		return "gh auth is not a command a github job may run"
	}
	return ""
}

func forgePayload(cli, host string, args ...string) string {
	b, _ := json.Marshal(map[string]any{"cli": cli, "host": host, "args": args, "stdin": nil})
	return string(b)
}

func TestParseForgeForcesTheHost(t *testing.T) {
	cases := []struct {
		name, cli, host string
		args            []string
		want            []string
	}{
		{"gh api github.com", "gh", "github.com",
			[]string{"api", "--include", "--method", "GET", "-H", "Accept: application/vnd.github+json", "user"},
			[]string{"api", "--hostname", "github.com", "--include", "--method", "GET", "-H", "Accept: application/vnd.github+json", "user"}},
		{"gh api same host given", "gh", "ghe.acme.dev",
			[]string{"api", "--hostname", "GHE.acme.dev", "--input", "-", "repos/a/b/issues"},
			[]string{"api", "--hostname", "ghe.acme.dev", "--input", "-", "repos/a/b/issues"}},
		{"gh pr list", "gh", "github.com", []string{"pr", "list", "-R", "acme/api"}, []string{"pr", "list", "-R", "acme/api"}},
		{"glab api", "glab", "gitlab.example.com",
			[]string{"api", "--hostname", "gitlab.example.com", "--include", "--method", "POST", "-H", "Content-Type: application/json", "--input", "-", "projects/1/merge_requests"},
			[]string{"api", "--hostname", "gitlab.example.com", "--include", "--method", "POST", "-H", "Content-Type: application/json", "--input", "-", "projects/1/merge_requests"}},
		{"glab api no hostname", "glab", "gitlab.com", []string{"api", "user"}, []string{"api", "--hostname", "gitlab.com", "user"}},
		{"tea api", "tea", "codeberg.org",
			[]string{"api", "-l", "whatever", "-i", "-X", "PATCH", "-H", "Content-Type: application/json", "-d", "@-", "/repos/a/b/pulls/3"},
			[]string{"api", "-l", "codeberg.org", "-i", "-X", "PATCH", "-H", "Content-Type: application/json", "-d", "@-", "/repos/a/b/pulls/3"}},
	}
	for _, c := range cases {
		r, why := ParseForge(forgePayload(c.cli, c.host, c.args...), checkGHStub)
		if why != "" {
			t.Errorf("%s: refused: %s", c.name, why)
			continue
		}
		if !slices.Equal(r.Args, c.want) {
			t.Errorf("%s: args = %q\nwant %q", c.name, r.Args, c.want)
		}
	}
}

func TestParseForgeRefusesOutsideTheAllowlist(t *testing.T) {
	cases := []struct {
		name, cli, host string
		args            []string
	}{
		{"unknown cli", "git", "github.com", []string{"push"}},
		{"bad host", "gh", "evil host", []string{"api", "user"}},
		{"names the cli", "glab", "gitlab.com", []string{"glab", "api", "user"}},
		{"end of flags", "gh", "github.com", []string{"api", "--", "user"}},
		{"gh allowlist", "gh", "github.com", []string{"auth", "token"}},
		{"gh other hostname", "gh", "github.com", []string{"api", "--hostname", "ghe.evil.dev", "user"}},
		{"gh hostname off api", "gh", "github.com", []string{"pr", "list", "--hostname", "github.com"}},
		{"gh repo on another host", "gh", "github.com", []string{"pr", "list", "-R", "ghe.evil.dev/a/b"}},
		{"gh repo joined", "gh", "github.com", []string{"pr", "list", "-Rghe.evil.dev/a/b"}},
		{"gh api url endpoint", "gh", "github.com", []string{"api", "https://evil.dev/x"}},
		{"glab not api", "glab", "gitlab.com", []string{"mr", "list"}},
		{"glab other hostname", "glab", "gitlab.com", []string{"api", "--hostname", "gitlab.evil.dev", "user"}},
		{"glab input file", "glab", "gitlab.com", []string{"api", "--input", "/etc/passwd", "user"}},
		{"glab field file", "glab", "gitlab.com", []string{"api", "-F", "body=@/etc/passwd", "user"}},
		{"glab field file joined", "glab", "gitlab.com", []string{"api", "-Fbody=@secrets", "user"}},
		{"glab unknown flag", "glab", "gitlab.com", []string{"api", "--output", "x", "user"}},
		{"glab credential header", "glab", "gitlab.com", []string{"api", "-H", "PRIVATE-TOKEN: x", "user"}},
		{"glab bad method", "glab", "gitlab.com", []string{"api", "-X", "TRACE", "user"}},
		{"glab parent path", "glab", "gitlab.com", []string{"api", "projects/../../etc"}},
		{"glab escaped parent", "glab", "gitlab.com", []string{"api", "projects/%2e%2e/x"}},
		{"glab url", "glab", "gitlab.com", []string{"api", "https://gitlab.evil.dev/api/v4/user"}},
		{"glab two paths", "glab", "gitlab.com", []string{"api", "user", "projects"}},
		{"glab no path", "glab", "gitlab.com", []string{"api", "--include"}},
		{"glab flag value missing", "glab", "gitlab.com", []string{"api", "user", "-X"}},
		{"tea not api", "tea", "codeberg.org", []string{"login", "add", "--token", "x"}},
		{"tea output", "tea", "codeberg.org", []string{"api", "-o", "out.json", "/user"}},
		{"tea data file", "tea", "codeberg.org", []string{"api", "-d", "@body.json", "/user"}},
		{"tea typed field file", "tea", "codeberg.org", []string{"api", "-F", "x=@/etc/shadow", "/user"}},
		{"tea home path", "tea", "codeberg.org", []string{"api", "~/x"}},
	}
	for _, c := range cases {
		if _, why := ParseForge(forgePayload(c.cli, c.host, c.args...), checkGHStub); why == "" {
			t.Errorf("%s: %q was not refused", c.name, c.args)
		}
	}
	if _, why := ParseForge(`{"cli":"gh","host":"github.com","args":["api","user"],"token":"x"}`, checkGHStub); why == "" {
		t.Error("an unknown payload field was not refused")
	}
	if _, why := ParseForge(`not json`, checkGHStub); why == "" {
		t.Error("a bad payload was not refused")
	}
}

func TestRunForcesTheEnvironmentAndTeaLogin(t *testing.T) {
	prevExec, prevTea := Exec, TeaLogin
	t.Cleanup(func() { Exec, TeaLogin = prevExec, prevTea })
	t.Setenv("GH_HOST", "ghe.evil.dev")
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-forge-job-secret")
	var gotProg string
	var gotArgs, gotEnv []string
	var gotStdin string
	Exec = func(_ context.Context, prog string, args []string, stdin string, env []string) (Result, error) {
		gotProg, gotArgs, gotStdin, gotEnv = prog, args, stdin, env
		return Result{Stdout: "{\"login\":\"octo\"}", Stderr: "HTTP/2.0 200 OK", Exit: 0}, nil
	}
	r, why := ParseForge(`{"cli":"gh","host":"github.com","args":["api","--input","-","user"],"stdin":"{}"}`, checkGHStub)
	if why != "" {
		t.Fatal(why)
	}
	out, why, err := Run(context.Background(), r)
	if err != nil || why != "" {
		t.Fatalf("run: %v %s", err, why)
	}
	var res struct {
		Stdout, Stderr string
		Exit           int
	}
	if json.Unmarshal(out, &res) != nil || res.Stdout != `{"login":"octo"}` || res.Exit != 0 {
		t.Errorf("answer = %s", out)
	}
	if gotProg != "gh" || gotStdin != "{}" || !slices.Equal(gotArgs[:3], []string{"api", "--hostname", "github.com"}) {
		t.Errorf("ran %s %q stdin %q", gotProg, gotArgs, gotStdin)
	}
	hosts := 0
	for _, e := range gotEnv {
		if strings.HasPrefix(e, "GH_HOST=") {
			hosts++
			if e != "GH_HOST=github.com" {
				t.Errorf("env carries %s", e)
			}
		}
		if strings.Contains(e, "sk-ant-forge-job-secret") {
			t.Error("a provider key reached the CLI's environment")
		}
	}
	if hosts == 0 {
		t.Error("GH_HOST was not forced")
	}

	// tea: the login comes from this host's own list, never the payload.
	TeaLogin = func(_ context.Context, host string) (string, bool) {
		return map[string]string{"codeberg.org": "cb"}[host], host == "codeberg.org"
	}
	r, why = ParseForge(forgePayload("tea", "codeberg.org", "api", "-l", "evil", "/user"), checkGHStub)
	if why != "" {
		t.Fatal(why)
	}
	if _, why, err := Run(context.Background(), r); err != nil || why != "" {
		t.Fatalf("tea run: %v %s", err, why)
	}
	if !slices.Equal(gotArgs, []string{"api", "-l", "cb", "/user"}) {
		t.Errorf("tea ran %q", gotArgs)
	}
	r, _ = ParseForge(forgePayload("tea", "gitea.other.dev", "api", "/user"), checkGHStub)
	if _, why, _ := Run(context.Background(), r); !strings.Contains(why, "no tea login") {
		t.Errorf("tea without a login: %q", why)
	}
}

func TestTeaLoginIn(t *testing.T) {
	list := `[{"Name":"cb","URL":"https://codeberg.org","User":"me"},{"name":"bad name","url":"https://x.dev"},{"name":"g","url":"https://gitea.acme.dev:3000"}]`
	if n, ok := teaLoginIn(list, "codeberg.org"); !ok || n != "cb" {
		t.Errorf("codeberg = %q %v", n, ok)
	}
	if n, ok := teaLoginIn(list, "gitea.acme.dev:3000"); !ok || n != "g" {
		t.Errorf("acme = %q %v", n, ok)
	}
	if _, ok := teaLoginIn(list, "x.dev"); ok {
		t.Error("a login name that is not an identifier was taken")
	}
	if _, ok := teaLoginIn("nope", "codeberg.org"); ok {
		t.Error("bad JSON gave a login")
	}
}
