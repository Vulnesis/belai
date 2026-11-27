package harnessdetect

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vulnetix/belai/internal/harness"
)

// script installs an executable stub. It writes a hidden temporary file and
// renames it into place, so a detector scanning dir concurrently (Watch) never
// execs the stub while it is still open for writing, which fails with
// "text file busy" (ETXTBSY).
func script(t *testing.T, dir, name, body string) {
	t.Helper()
	tmp := filepath.Join(dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
}

func registry() []harness.Harness {
	pty := func(bin string) *harness.Launch {
		return &harness.Launch{Tier: harness.TierPTY, Conf: harness.ConfHost, Bins: []string{bin}, Argv: []string{"{bin}"},
			VersionArgs: []string{"--version"}, Modes: map[string][]string{"default": {}, "plan": {"--plan"}},
			Keys: harness.Keys{Allow: []string{"enter", "1"}}, MCP: &harness.Wire{How: "flag-file", Flag: "--mcp"},
			Transcript: &harness.Transcript{Dialect: "jsonl-claude"}}
	}
	return []harness.Harness{
		{ID: "claude-code", Name: "Claude Code", Launch: pty("claude")},
		{ID: "broke", Name: "Broke", Launch: pty("broke")},
		{ID: "slow", Name: "Slow", Launch: pty("slow")},
		{ID: "docs", Name: "Docs", Launch: &harness.Launch{Tier: harness.TierPTY, Conf: harness.ConfUnverified, Bins: []string{"docs"}, Argv: []string{"{bin}"}}},
		{ID: "hermes", Name: "Hermes", Detect: []string{"~/.hermes"}, Launch: pty("hermes")},
		{ID: "zed", Name: "Zed", Launch: &harness.Launch{Tier: harness.TierGUI, Conf: harness.ConfDocs, AppBins: []string{"zed"}}},
		{ID: "absent", Name: "Absent", Detect: []string{"~/.absent"}, Launch: pty("absent")},
	}
}

func TestDetectStates(t *testing.T) {
	home, bin, login := t.TempDir(), t.TempDir(), t.TempDir()
	script(t, bin, "claude", `echo "2.3.1 (Claude Code)"`)
	script(t, bin, "broke", `exit 1`)
	script(t, login, "slow", `sleep 10`)
	script(t, bin, "docs", `echo 0.1`)
	script(t, login, "zed", `echo zed`)
	if err := os.MkdirAll(filepath.Join(home, ".hermes", "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := Detect(context.Background(), Options{Home: home, Path: bin, LoginPath: login, Registry: registry(),
		LoggedIn: func(_, id string) bool { return id == "claude-code" }})
	by := map[string]Harness{}
	for _, h := range got {
		by[h.ID] = h
	}
	c := by["claude-code"]
	if c.State != StateLaunch || c.Version != "2.3.1 (Claude Code)" || c.Path != filepath.Join(bin, "claude") || !c.LoggedIn || !c.A2A {
		t.Errorf("claude: %+v", c)
	}
	if len(c.Modes) != 2 || c.Modes[0] != "default" || c.Transcript != "jsonl-claude" || c.VersionHash == "" {
		t.Errorf("claude facts: %+v", c)
	}
	if by["broke"].State != StateBroken || by["broke"].Detail == "" {
		t.Errorf("broke: %+v", by["broke"])
	}
	if by["slow"].State != StateBroken {
		t.Errorf("slow (login PATH, times out): %+v", by["slow"])
	}
	if by["docs"].State != StateUnverified || by["docs"].Launchable() {
		t.Errorf("docs: %+v", by["docs"])
	}
	if by["hermes"].State != StateConfigured {
		t.Errorf("a skills dir alone must read as configured: %+v", by["hermes"])
	}
	if by["zed"].State != StateGUI {
		t.Errorf("zed: %+v", by["zed"])
	}
	if _, ok := by["absent"]; ok {
		t.Error("absent harness listed")
	}
	if got[0].ID != "claude-code" {
		t.Errorf("launchable first, got %s", got[0].ID)
	}
}

func TestVersionLineIsSanitized(t *testing.T) {
	home, bin := t.TempDir(), t.TempDir()
	script(t, bin, "claude", `printf '\033]52;c;aGk=\007v1 \033[31mred\033[0m and a very long tail that goes past sixty four characters for sure\n'`)
	got := Detect(context.Background(), Options{Home: home, Path: bin, Registry: registry()[:1], LoggedIn: func(string, string) bool { return false }})
	if len(got) != 1 {
		t.Fatal(got)
	}
	v := got[0].Version
	if len([]rune(v)) > VersionMax {
		t.Errorf("version not capped: %q", v)
	}
	for _, r := range v {
		if r < 0x20 {
			t.Fatalf("control rune in %q", v)
		}
	}
}

func TestPathDirsMerge(t *testing.T) {
	got := pathDirs("/a:/b:rel", "/b:/c")
	if len(got) != 3 || got[0] != "/a" || got[2] != "/c" {
		t.Fatal(got)
	}
}

func TestWatchReportsChangesOnly(t *testing.T) {
	home, bin := t.TempDir(), t.TempDir()
	o := Options{Home: home, Path: bin, LoginPath: "/nonexistent", Registry: registry()[:1], LoggedIn: func(string, string) bool { return false }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kick := make(chan struct{})
	got := make(chan []Harness, 4)
	go Watch(ctx, o, time.Hour, kick, func(h []Harness) { got <- h })
	if h := <-got; len(h) != 0 {
		t.Fatalf("first: %v", h)
	}
	kick <- struct{}{}
	script(t, bin, "claude", `echo 1.0`)
	kick <- struct{}{}
	select {
	case h := <-got:
		if len(h) != 1 || h[0].State != StateLaunch {
			t.Fatalf("after install: %+v", h)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no change reported")
	}
}

func TestStartupFiguresFromTimingFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "timing.jsonl")
	var lines string
	for _, ms := range []int{100, 200, 300, 400, 5000} {
		lines += `{"harness":"claude-code","startupMs":` + strconv.Itoa(ms) + `,"at":` + strconv.Itoa(ms) + "}\n"
	}
	lines += `{"harness":"codex","startupMs":9}` + "\n" + "junk\n"
	if err := os.WriteFile(f, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	p50, p95, n, at := startup(f, "claude-code")
	if p50 != 300 || p95 != 5000 || n != 5 || at != 5000 {
		t.Fatal(p50, p95, n, at)
	}
}

func TestCapabilitiesAndCaveatsAdvertised(t *testing.T) {
	home, bin := t.TempDir(), t.TempDir()
	script(t, bin, "claude", `echo "2.1.330 (Claude Code)"`)
	reg := []harness.Harness{}
	if h, ok := harness.ByID("claude-code"); ok {
		reg = append(reg, h)
	}
	got := Detect(context.Background(), Options{Home: home, Path: bin, Registry: reg, LoggedIn: func(string, string) bool { return false }})
	if len(got) != 1 {
		t.Fatal(got)
	}
	c := got[0]
	if !c.Resume || !c.Asks || !c.Named || len(c.Continuity) == 0 || len(c.Caveats) == 0 {
		t.Fatalf("%+v", c)
	}
}

func TestMinVersionPin(t *testing.T) {
	home, bin := t.TempDir(), t.TempDir()
	reg := registry()[:1]
	l := *reg[0].Launch
	l.MinVersion = "2.3.0"
	reg[0].Launch = &l
	for out, want := range map[string]string{"2.3.1 (Claude Code)": StateLaunch, "2.2.9 (Claude Code)": StateBroken, "Claude Code": StateBroken} {
		script(t, bin, "claude", `echo "`+out+`"`)
		got := Detect(context.Background(), Options{Home: home, Path: bin, Registry: reg, LoggedIn: func(string, string) bool { return false }})
		if len(got) != 1 || got[0].State != want {
			t.Errorf("%q: want %s, got %+v", out, want, got)
		}
		if want == StateLaunch && got[0].Launch == nil {
			t.Errorf("%q: no checked profile", out)
		}
	}
}

// A vendor-docs profile launches only once the installed binary's help names
// every flag it passes.
func TestVendorDocsProfileNeedsInstallCheck(t *testing.T) {
	home, bin := t.TempDir(), t.TempDir()
	docs := &harness.Launch{Tier: harness.TierPTY, Conf: harness.ConfDocs, Bins: []string{"gem"}, Argv: []string{"{bin}"},
		ModelFlag: []string{"--model", "{model}"}, Modes: map[string][]string{"default": {}, "plan": {"--approval-mode=plan"}}}
	reg := []harness.Harness{{ID: "gem", Name: "Gem", Launch: docs}}
	detect := func() Harness {
		got := Detect(context.Background(), Options{Home: home, Path: bin, Registry: reg, LoggedIn: func(string, string) bool { return false }})
		if len(got) != 1 {
			t.Fatal(got)
		}
		return got[0]
	}
	script(t, bin, "gem", `case "$1" in --version) echo 1.0;; --help) echo "  --modelx  --approval-mode";; esac`)
	if g := detect(); g.State != StateUnverified || g.Launch != nil || !strings.Contains(g.Detail, "--model") {
		t.Fatalf("missing flag: %+v", g)
	}
	script(t, bin, "gem", `case "$1" in --version) echo 1.0;; --help) exit 3;; esac`)
	if g := detect(); g.State != StateUnverified {
		t.Fatalf("help failed: %+v", g)
	}
	script(t, bin, "gem", `case "$1" in --version) echo 1.0;; --help) echo "  -m, --model <id>"; echo "  --approval-mode <mode>";; esac`)
	g := detect()
	if g.State != StateLaunch || g.Launch == nil || !g.Launch.Launchable() || g.Conf != harness.ConfDocs {
		t.Fatalf("checked: %+v", g)
	}
	if docs.Launchable() {
		t.Fatal("the registry's copy became launchable")
	}
}
