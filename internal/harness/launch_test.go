package harness

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestEveryLaunchProfileValidates(t *testing.T) {
	n := 0
	for _, h := range All() {
		if h.Launch == nil {
			continue
		}
		n++
		if err := h.Launch.Validate(); err != nil {
			t.Errorf("%s: %v", h.ID, err)
		}
	}
	if n == 0 {
		t.Fatal("no launch profiles in the registry")
	}
}

func TestVerifiedTierIsLaunchable(t *testing.T) {
	for _, id := range []string{"claude-code", "codex", "pi", "opencode", "goose", "github-copilot", "antigravity-cli"} {
		h, ok := ByID(id)
		if !ok {
			t.Fatalf("%s missing", id)
		}
		if !h.Launch.Launchable() || h.Launch.Conf != ConfHost {
			t.Errorf("%s: want a launchable host-verified profile, got %+v", id, h.Launch)
		}
	}
}

func claude(t *testing.T) *Launch {
	t.Helper()
	h, ok := ByID("claude-code")
	if !ok || h.Launch == nil {
		t.Fatal("claude-code has no profile")
	}
	return h.Launch
}

func TestBuildClaudeGolden(t *testing.T) {
	l := claude(t)
	base := Values{Bin: "/bin/claude", NativeID: "0b6f9a3e-1111-4222-8333-444455556666", Cwd: "/w", Sid: "s1"}
	cases := []struct {
		name string
		v    func(Values) Values
		want string
	}{
		{"default", func(v Values) Values { return v }, "/bin/claude --session-id 0b6f9a3e-1111-4222-8333-444455556666"},
		{"plan", func(v Values) Values { v.Mode = "plan"; return v }, "/bin/claude --session-id 0b6f9a3e-1111-4222-8333-444455556666 --permission-mode plan"},
		{"accept", func(v Values) Values { v.Mode = "accept_edits"; return v }, "/bin/claude --session-id 0b6f9a3e-1111-4222-8333-444455556666 --permission-mode acceptEdits"},
		{"model", func(v Values) Values { v.Model = "claude-opus-4-1"; return v }, "/bin/claude --session-id 0b6f9a3e-1111-4222-8333-444455556666 --model claude-opus-4-1"},
		{"mcp", func(v Values) Values { v.MCPFile, v.SettingsFile = "/m.json", "/s.json"; return v },
			"/bin/claude --session-id 0b6f9a3e-1111-4222-8333-444455556666 --mcp-config /m.json --settings /s.json"},
		{"resume", func(v Values) Values { v.Resume = true; return v }, "/bin/claude --resume 0b6f9a3e-1111-4222-8333-444455556666"},
	}
	for _, c := range cases {
		got, err := l.Build(c.v(base))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if s := strings.Join(got, " "); s != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, s, c.want)
		}
	}
}

func TestBuildRefusesBadValues(t *testing.T) {
	l := claude(t)
	base := Values{Bin: "/bin/claude", NativeID: "abc", Cwd: "/w"}
	for name, v := range map[string]Values{
		"flag as model":   {Bin: base.Bin, NativeID: base.NativeID, Cwd: base.Cwd, Model: "--dangerously-skip-permissions"},
		"space in model":  {Bin: base.Bin, NativeID: base.NativeID, Cwd: base.Cwd, Model: "a b"},
		"unknown mode":    {Bin: base.Bin, NativeID: base.NativeID, Cwd: base.Cwd, Mode: "bypassPermissions"},
		"native id shape": {Bin: base.Bin, NativeID: "../../etc", Cwd: base.Cwd},
		"no native id":    {Bin: base.Bin, Cwd: base.Cwd},
	} {
		if _, err := l.Build(v); err == nil {
			t.Errorf("%s: built", name)
		}
	}
}

func TestBuildNeverProducesNeverFlags(t *testing.T) {
	for _, h := range All() {
		l := h.Launch
		if !l.MayLaunch() {
			continue
		}
		if l.NeedsInstallCheck() {
			c := *l
			c.installChecked = true
			l = &c
		}
		for _, mode := range append(l.ModeNames(), "") {
			v := Values{Bin: "/x", NativeID: "id1", Cwd: "/w", Sid: "s1", Mode: mode, MCPFile: "/m", MCPJSON: "{}", MCPCmd: "c", SettingsFile: "/s"}
			argv, err := l.Build(v)
			if err != nil {
				t.Errorf("%s %s: %v", h.ID, mode, err)
				continue
			}
			for _, el := range argv {
				if slices.Contains(l.NeverFlags, el) {
					t.Errorf("%s %s: produced never flag %q", h.ID, mode, el)
				}
				if el == "-p" || el == "--print" || el == "exec" {
					t.Errorf("%s %s: produced a non-interactive argv %v", h.ID, mode, argv)
				}
			}
		}
	}
}

func TestValidateRefuses(t *testing.T) {
	ok := Launch{Tier: TierPTY, Conf: ConfHost, Bins: []string{"x"}, Argv: []string{"{bin}"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]Launch{
		"placeholder": {Tier: TierPTY, Conf: ConfHost, Bins: []string{"x"}, Argv: []string{"{bin}", "{prompt}"}},
		"never":       {Tier: TierPTY, Conf: ConfHost, Bins: []string{"x"}, Argv: []string{"{bin}", "-p"}, NeverFlags: []string{"-p"}},
		"never=":      {Tier: TierPTY, Conf: ConfHost, Bins: []string{"x"}, Argv: []string{"{bin}", "--mode=json"}, NeverFlags: []string{"--mode"}},
		"bin path":    {Tier: TierPTY, Conf: ConfHost, Bins: []string{"/usr/bin/x"}, Argv: []string{"{bin}"}},
		"key":         {Tier: TierPTY, Conf: ConfHost, Bins: []string{"x"}, Argv: []string{"{bin}"}, Keys: Keys{Allow: []string{"f12"}}},
		"tier":        {Tier: "web", Conf: ConfHost, Bins: []string{"x"}},
		"gui argv":    {Tier: TierGUI, Conf: ConfDocs, AppBins: []string{"x"}, Argv: []string{"{bin}"}},
		"first":       {Tier: TierPTY, Conf: ConfHost, Bins: []string{"x"}, Argv: []string{"sh", "-c"}},
	}
	for name, l := range bad {
		if err := l.Validate(); err == nil {
			t.Errorf("%s: validated", name)
		}
	}
}

func TestUnverifiedIsNotLaunchable(t *testing.T) {
	l := &Launch{Tier: TierPTY, Conf: ConfUnverified, Bins: []string{"x"}, Argv: []string{"{bin}"}}
	if l.Launchable() {
		t.Fatal("an unverified profile is launchable")
	}
	if _, err := l.Build(Values{Bin: "/x", Cwd: "/w"}); err == nil {
		t.Fatal("built an unverified profile")
	}
}

func TestCwdSlug(t *testing.T) {
	if got := CwdSlug("/home/u/x.y"); got != "-home-u-x-y" {
		t.Fatal(got)
	}
}

func TestGrantEnvNames(t *testing.T) {
	for _, ok := range []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "COPILOT_GITHUB_TOKEN"} {
		if !GrantEnvName(ok) {
			t.Errorf("%s refused", ok)
		}
	}
	for _, bad := range []string{"ANTHROPIC_BASE_URL", "OPENAI_API_ENDPOINT", "HTTPS_PROXY", "OLLAMA_HOST", "PATH", "LD_PRELOAD", "lower", "X"} {
		if GrantEnvName(bad) {
			t.Errorf("%s accepted", bad)
		}
	}
	l := Launch{Tier: TierPTY, Conf: ConfHost, Bins: []string{"x"}, Argv: []string{"{bin}"}, GrantEnv: []string{"ANTHROPIC_BASE_URL"}}
	if l.Validate() == nil {
		t.Error("a URL variable validated as grant_env")
	}
}

func TestExpandHarnessConfigDirs(t *testing.T) {
	env := map[string]string{"CLAUDE_CONFIG_DIR": "/c", "CODEX_HOME": "rel"}
	get := func(k string) string { return env[k] }
	if got := ExpandHarness("/h", "~/.claude/projects", get); got != "/c/projects" {
		t.Fatal(got)
	}
	if got := ExpandHarness("/h", "~/.codex/auth.json", get); got != "/h/.codex/auth.json" {
		t.Fatalf("a relative CODEX_HOME must be ignored: %s", got)
	}
	if got := ExpandHarness("/h", "~/.claudette", get); got != "/h/.claudette" {
		t.Fatal(got)
	}
}

func TestBuildNamesTheNativeSession(t *testing.T) {
	l := claude(t)
	got, err := l.Build(Values{Bin: "/c", NativeID: "id1", Cwd: "/w", ThreadName: "kls-1a2b3c4d"})
	if err != nil || !strings.Contains(strings.Join(got, " "), "--name kls-1a2b3c4d") {
		t.Fatal(got, err)
	}
	if _, err := l.Build(Values{Bin: "/c", NativeID: "id1", Cwd: "/w", ThreadName: "--yolo"}); err == nil {
		t.Fatal("a flag as a session name")
	}
	got, _ = l.Build(Values{Bin: "/c", NativeID: "id1", Cwd: "/w", ThreadName: "kls-x", Resume: true})
	if strings.Contains(strings.Join(got, " "), "--name") {
		t.Fatal("a resume renames the session")
	}
}

func TestVendorDocsNeedsInstallCheck(t *testing.T) {
	l := &Launch{Tier: TierPTY, Conf: ConfDocs, Bins: []string{"x"}, Argv: []string{"{bin}", "--tui"},
		ModelFlag: []string{"-m", "{model}"}, Modes: map[string][]string{"plan": {"--mode=plan"}},
		MCP: &Wire{How: "flag-file", Flag: "--mcp-config"}}
	if l.Launchable() || !l.NeedsInstallCheck() {
		t.Fatal("a vendor-docs profile is launchable before its install check")
	}
	if _, err := l.Build(Values{Bin: "/x", Cwd: "/w"}); err == nil {
		t.Fatal("built an unchecked vendor-docs profile")
	}
	if got := l.Flags(); !slices.Equal(got, []string{"--mcp-config", "--mode", "--tui", "-m"}) {
		t.Fatalf("flags %v", got)
	}
	for name, help := range map[string]string{
		"empty":  "",
		"prefix": "--tuix -m --mode --mcp-config",
		"absent": "--tui --mode --mcp-config",
	} {
		if _, err := l.CheckInstall(help); err == nil {
			t.Errorf("%s: checked", name)
		}
	}
	c, err := l.CheckInstall("Usage: x [--tui]\n  -m, --model\n  --mode <m>\n  --mcp-config <file>\n")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Launchable() || l.Launchable() {
		t.Fatal("the check must return a launchable copy and leave the profile alone")
	}
	if _, err := c.Build(Values{Bin: "/x", Cwd: "/w"}); err != nil {
		t.Fatal(err)
	}
	// JSON never sets the check.
	var fromJSON Launch
	if err := json.Unmarshal([]byte(`{"tier":"pty","conf":"M","bins":["x"],"argv":["{bin}"],"installChecked":true}`), &fromJSON); err != nil {
		t.Fatal(err)
	}
	if fromJSON.Launchable() {
		t.Fatal("JSON made a vendor-docs profile launchable")
	}
}

func TestVersionOK(t *testing.T) {
	l := &Launch{MinVersion: "2.1.330"}
	for line, ok := range map[string]bool{
		"2.1.330 (Claude Code)": true, "2.2.0": true, "v10.0": true, "codex-cli 2.1.331": true,
		"2.1.329": false, "1.9": false, "unknown": false, "": false,
	} {
		if err := l.VersionOK(line); (err == nil) != ok {
			t.Errorf("%q: %v", line, err)
		}
	}
	if (&Launch{}).VersionOK("") != nil {
		t.Error("no pin refused")
	}
	if err := (&Launch{Tier: TierPTY, Conf: ConfHost, Bins: []string{"x"}, Argv: []string{"{bin}"}, MinVersion: "latest"}).Validate(); err == nil {
		t.Error("a non-numeric min_version validated")
	}
}

func TestHostCheckedProfilesPinMinVersion(t *testing.T) {
	for _, h := range All() {
		if l := h.Launch; l != nil && l.Tier == TierPTY && l.Conf == ConfHost && l.MinVersion == "" {
			t.Errorf("%s: no min_version", h.ID)
		}
	}
}
