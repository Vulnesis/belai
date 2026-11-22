package harnessrun

import (
	"strings"
	"testing"

	"github.com/vulnetix/belai/internal/harness"
)

func TestNeutralise(t *testing.T) {
	got := Neutralise("a\x1b[201~b\r\nc\x00d\u009be\x7f\tf")
	if got != "a[201~b\ncde\tf" {
		t.Fatalf("%q", got)
	}
	if len(Neutralise(strings.Repeat("x", MaxPrompt+10))) != MaxPrompt {
		t.Fatal("not capped")
	}
}

func TestPromptBytes(t *testing.T) {
	b, err := PromptBytes("hi\x1b[201~\x03", true, harness.Input{})
	if err != nil || string(b) != PasteStart+"hi[201~"+PasteEnd {
		t.Fatalf("%q %v", b, err)
	}
	for _, p := range []string{"/exit", "!rm -rf /", "#remember", "  "} {
		if _, err := PromptBytes(p, true, harness.Input{}); err == nil {
			t.Errorf("%q typed", p)
		}
	}
	if _, err := PromptBytes("a\nb", false, harness.Input{Multiline: "refuse"}); err != ErrMultiline {
		t.Fatal(err)
	}
	if b, _ := PromptBytes("a\nb", false, harness.Input{Multiline: "join"}); string(b) != "a b" {
		t.Fatal(string(b))
	}
}

func TestKeyBytes(t *testing.T) {
	if b, err := KeyBytes("Enter", []string{"enter"}); err != nil || string(b) != "\r" {
		t.Fatal(b, err)
	}
	if _, err := KeyBytes("ctrl-c", []string{"enter"}); err == nil {
		t.Fatal("a key outside the allowlist")
	}
}

func TestModesAcrossChunks(t *testing.T) {
	var m Modes
	m.Feed([]byte("hello \x1b[?20"))
	m.Feed([]byte("04h world"))
	if !m.Bracketed() {
		t.Fatal("split DECSET missed")
	}
	m.Feed([]byte("\x1b[?2004l"))
	if m.Bracketed() {
		t.Fatal("reset missed")
	}
}

func TestMatchPrompt(t *testing.T) {
	if !matchPrompt("list  the\ncrates", "list the crates") || matchPrompt("abc", "xyz") {
		t.Fatal("match")
	}
}

func TestWireNeverEditsUserFiles(t *testing.T) {
	h, _ := harness.ByID("claude-code")
	dir := t.TempDir() + "/s"
	w, err := Wire(h.Launch, dir, "/x/belai", dir+"/sock", true)
	if err != nil || !w.A2A || !strings.HasPrefix(w.MCPFile, dir) || !strings.HasPrefix(w.SettingsFile, dir) {
		t.Fatal(w, err)
	}
	w, _ = Wire(h.Launch, dir, "/x/belai", dir+"/sock", false)
	if w.A2A || w.MCPFile != "" {
		t.Fatal("bridge wired with A2A off")
	}
}

func TestEnvDropsOwnVariables(t *testing.T) {
	env := Env([]string{"PATH=/usr/bin", "BELAI_X=1", "VULNETIX_TOKEN=t", "TERM=dumb", "HOME=/h"}, "/opt/c/bin/claude", "/s", []string{"A=1"})
	got := strings.Join(env, " ")
	if strings.Contains(got, "BELAI_X") || strings.Contains(got, "VULNETIX") || strings.Contains(got, "TERM=dumb") ||
		!strings.Contains(got, "PATH=/opt/c/bin:/usr/bin") || !strings.Contains(got, "A=1") {
		t.Fatal(got)
	}
}

func TestScreenTextKeepsCursorSpaces(t *testing.T) {
	if got := screenText([]byte("Quick\x1b[1Csafety\x1b[Ccheck\x1b[31m!\x1b[0m\r\n"), 5); got != "Quick safety check!" {
		t.Fatalf("%q", got)
	}
}

func TestEnvDropsParentSessionMarkers(t *testing.T) {
	got := strings.Join(Env([]string{"CLAUDECODE=1", "CLAUDE_CODE_CHILD_SESSION=1", "CLAUDE_CODE_USE_BEDROCK=1", "PATH=/b"}, "/b/c", "/s", nil), " ")
	if strings.Contains(got, "CLAUDECODE") || strings.Contains(got, "CHILD_SESSION") || !strings.Contains(got, "CLAUDE_CODE_USE_BEDROCK=1") {
		t.Fatal(got)
	}
}

func TestDialogDecisionShapes(t *testing.T) {
	for in, want := range map[string]string{`{"decision":"trust"}`: "trust", `"trust"`: "trust", `{"answers":{"dlg-1":"dont_trust"}}`: "dont_trust"} {
		got, err := dialogDecision([]byte(in), "dlg-1")
		if err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	if _, err := dialogDecision([]byte(`{"answers":{"dlg-9":"trust"}}`), "dlg-1"); err == nil || !strings.Contains(err.Error(), "dlg-9") {
		t.Errorf("unknown id: %v", err)
	}
	if _, err := dialogDecision([]byte(`[1,2]`), "dlg-1"); err == nil {
		t.Error("junk accepted")
	}
}
