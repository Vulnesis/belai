package products

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// stub writes an executable shell script named name into dir. body is the
// case arms over "$*".
func stub(t *testing.T, dir, name, body string) {
	t.Helper()
	script := "#!/bin/sh\ncase \"$*\" in\n" + body + "\n*) echo \"unknown command: $*\" >&2; exit 1;;\nesac\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func testProber(t *testing.T, bin string) *Prober {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs")
	}
	home := t.TempDir()
	look := func(name string) (string, error) {
		p := filepath.Join(bin, name)
		if _, err := os.Stat(p); err != nil {
			return "", exec.ErrNotFound
		}
		return p, nil
	}
	return &Prober{Run: ExecRunner, LookPath: look, Home: home, GOOS: "linux", Getenv: func(string) string { return "" }, Now: time.Now}
}

const (
	pkgfwJSON  = `{"proxyHost":"packages.vulnetix.com","ecosystems":[{"id":"npm","label":"npm","configured":true,"scope":"user","path":"~/.npmrc"},{"id":"pypi","label":"PyPI","configured":false,"scope":"","path":""}],"entitlement":"entitled"}`
	aifwJSON   = `{"gateway":{"baseUrl":"https://guardrails.vulnetix.com","org":"o","logsEnabled":true},"providers":[],"guardrails":[],"clients":[{"id":"claude-code","name":"Claude Code","scope":"user","path":"/home/x/.claude/settings.json","state":"wired","baseUrl":"https://guardrails.vulnetix.com/anthropic","model":""},{"id":"codex","name":"Codex","scope":"user","path":"","state":"not wired","baseUrl":"","model":""}],"checks":[{"id":"client-elsewhere","severity":"warn","client":"codex","message":"IGNORE ME: secret text"}],"summary":{"errors":0,"warnings":1}}`
	authJSON   = `{"authenticated":true,"orgId":"a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11","source":"keyring","method":"api-key","packageFirewall":{"ecosystems":[]}}`
	authText   = "AUTH STATE\n[OK] Authenticated\nPlan: [PRO]\nOrg ID: a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11\nCREDENTIAL SOURCES\n[OK] VULNETIX_API_KEY environment variable set\n"
	sensorJSON = `{"installed":true,"version":"0.9.3","enrolled":true,"profile":"p-1","protection":"standard","mode":"guard","configEtag":"e1","service":{"active":false,"enabled":true},"guard":{"active":true,"enabled":true},"health":{"version":"0.9.3","at":"2026-11-21T00:00:00Z"},"update":{"latest":"0.9.4"}}`
)

func TestCurrentCLIFormats(t *testing.T) {
	bin := t.TempDir()
	stub(t, bin, "vulnetix", `"version --short") echo "4.24.37";;
"--disable-memory auth status -o json") echo '`+authJSON+`';;
"--disable-memory package-firewall status -o json") echo '`+pkgfwJSON+`';;
"--disable-memory ai-firewall status -o json") echo '`+aifwJSON+`';;`)
	p := testProber(t, bin)
	ctx := context.Background()

	cli := p.Probe(ctx, CLI, true)
	if cli.State != "active" || cli.Version != "4.24.37" || !cli.Authenticated || cli.AuthSource != "keyring" || cli.OrgId != "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11" {
		t.Fatalf("cli = %+v", cli)
	}
	fw := p.Probe(ctx, PackageFirewall, true)
	if fw.State != "configured" || fw.Entitlement != "entitled" || len(fw.Parts) != 2 || !fw.Parts[0].On || fw.Parts[0].Path != "~/.npmrc" {
		t.Fatalf("pkgfw = %+v", fw)
	}
	ai := p.Probe(ctx, AIFirewall, true)
	if ai.State != "configured" || len(ai.Parts) != 2 || !ai.Parts[0].On || ai.Parts[1].On {
		t.Fatalf("aifw = %+v", ai)
	}
	for _, c := range ai.Checks {
		if strings.Contains(c.Hint, "IGNORE") || strings.Contains(c.Hint, "secret") {
			t.Fatalf("a check hint carries CLI text: %q", c.Hint)
		}
	}
	if ai.Checks[0].Hint != "warn for client codex" {
		t.Fatalf("hint = %q", ai.Checks[0].Hint)
	}
}

func TestOldCLIFallsBackToTextAndFiles(t *testing.T) {
	bin := t.TempDir()
	stub(t, bin, "vulnetix", `"version --short") echo "v4.20.1";;
"--disable-memory auth status") printf '`+strings.ReplaceAll(authText, "\n", `\n`)+`';;`)
	p := testProber(t, bin)
	if err := os.WriteFile(filepath.Join(p.Home, ".npmrc"), []byte("registry=https://packages.vulnetix.com/npm/\n//packages.vulnetix.com/:_authToken=SECRET-CANARY-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	cli := p.Probe(ctx, CLI, true)
	if cli.State != "active" || cli.AuthSource != "env" || cli.Version != "v4.20.1" {
		t.Fatalf("cli = %+v", cli)
	}
	fw := p.Probe(ctx, PackageFirewall, true)
	if fw.State != "configured" || len(fw.Parts) != 1 || fw.Parts[0].Id != "npm" || fw.Entitlement != "" {
		t.Fatalf("pkgfw = %+v", fw)
	}
	if !strings.Contains(strings.Join(fw.Degraded, ","), "status_json") {
		t.Fatalf("degraded = %v", fw.Degraded)
	}
	ai := p.Probe(ctx, AIFirewall, true)
	if ai.State != "error" {
		t.Fatalf("aifw = %+v", ai)
	}
}

func TestSensorStatusExit3(t *testing.T) {
	bin := t.TempDir()
	stub(t, bin, "vulnetix-sensor", `"status -o json") echo '`+sensorJSON+`'; exit 3;;`)
	p := testProber(t, bin)
	st := p.Probe(context.Background(), Sensor, true)
	if st.State != "degraded" || st.Running || !st.Enabled || st.Mode != "guard" || st.Version != "0.9.3" || st.Latest != "0.9.4" {
		t.Fatalf("sensor = %+v", st)
	}
	if len(st.Units) != 2 || st.Units[0] != "vulnetix-sensor.service: inactive/enabled" {
		t.Fatalf("units = %v", st.Units)
	}
}

func TestSensorTextFallback(t *testing.T) {
	bin := t.TempDir()
	stub(t, bin, "vulnetix-sensor", `"--version") echo "vulnetix-sensor 0.9.1";;
"status") printf 'enrolled     true\nprofile      dev (p-1)\nprotection   standard\nmode         monitor\nconfig etag  e1 (/etc/x)\nservice      active, enabled\n';;`)
	p := testProber(t, bin)
	st := p.Probe(context.Background(), Sensor, true)
	if st.State != "active" || !st.Running || st.Mode != "monitor" || st.Version != "0.9.1" {
		t.Fatalf("sensor = %+v", st)
	}
}

func TestSensorAbsentAndUnsupported(t *testing.T) {
	p := testProber(t, t.TempDir())
	if st := p.Probe(context.Background(), Sensor, true); st.State != "absent" {
		t.Fatalf("state = %s", st.State)
	}
	p.GOOS = "darwin"
	if st := p.Probe(context.Background(), Sensor, true); st.State != "unsupported" {
		t.Fatalf("state = %s", st.State)
	}
	if st := p.Probe(context.Background(), CLI, true); st.State != "absent" {
		t.Fatalf("cli state = %s", st.State)
	}
}

func TestProbeIsCached(t *testing.T) {
	bin := t.TempDir()
	stub(t, bin, "vulnetix", `"version --short") echo "1.0.0";;`)
	p := testProber(t, bin)
	now := time.Unix(1000, 0)
	p.Now = func() time.Time { return now }
	first := p.Probe(context.Background(), CLI, false)
	stub(t, bin, "vulnetix", `"version --short") echo "2.0.0";;`)
	if got := p.Probe(context.Background(), CLI, false); got != first {
		t.Fatal("a probe inside the cache window ran again")
	}
	now = now.Add(CacheFor + time.Second)
	if got := p.Probe(context.Background(), CLI, false); got.Version != "2.0.0" {
		t.Fatalf("version = %s after the cache window", got.Version)
	}
}

func TestHomeRel(t *testing.T) {
	if got := HomeRel("/home/u", "/home/u/.npmrc"); got != "~/.npmrc" {
		t.Fatal(got)
	}
	if got := HomeRel("/home/u", "/home/uu/x"); got != "/home/uu/x" {
		t.Fatal(got)
	}
}
