package harnessrun

import (
	"os"
	"strings"
	"testing"

	"github.com/vulnetix/belai/internal/harness"
)

// The recorded screens are real PTY output: Codex 0.164.0 asking to run a
// shell command (a full-screen TUI that redraws by cursor addressing) and
// Claude Code 2.1.330 asking to create a file, both at 120x40.
func replay(t *testing.T, file string) string {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	g := newGrid(120, 40)
	if _, err := g.Write(b); err != nil {
		t.Fatal(err)
	}
	return g.text()
}

func dialogsOf(t *testing.T, id string) []harness.Dialog {
	t.Helper()
	h, ok := harness.ByID(id)
	if !ok || h.Launch == nil {
		t.Fatalf("%s has no profile", id)
	}
	return h.Launch.Dialogs
}

func TestCodexApprovalScreenIsADialog(t *testing.T) {
	screen := replay(t, "testdata/codex-approval.raw")
	var hit *harness.Dialog
	for _, d := range dialogsOf(t, "codex") {
		if dialogOn(d, screen) {
			hit = &d
		}
	}
	if hit == nil || hit.ID != "approval" {
		t.Fatalf("no approval dialog on:\n%s", screen)
	}
	if q := questionLine(screen, hit.Match[0]); !strings.Contains(q, "Would you like to run the following command?") {
		t.Fatalf("question line %q", q)
	}
}

func TestClaudePermissionScreenIsADialog(t *testing.T) {
	screen := replay(t, "testdata/claude-permission.raw")
	var hit *harness.Dialog
	for _, d := range dialogsOf(t, "claude-code") {
		if dialogOn(d, screen) {
			hit = &d
		}
	}
	if hit == nil || hit.ID != "tool_permission" {
		t.Fatalf("no permission dialog on:\n%s", screen)
	}
	if q := questionLine(screen, hit.Match[0]); q != "Do you want to create hello.txt?" {
		t.Fatalf("question line %q (the grid keeps the spaces)", q)
	}
	if dialogOn(dialogsOf(t, "claude-code")[0], screen) {
		t.Fatal("the trust dialog matched a permission screen")
	}
}

func TestGridDrainsTerminalQueries(t *testing.T) {
	g := newGrid(40, 5)
	// Device attributes and cursor position queries make the emulator write
	// replies; a write must not block on them.
	for i := 0; i < 100; i++ {
		if _, err := g.Write([]byte("\x1b[c\x1b[6nhello\r\n")); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(g.text(), "hello") {
		t.Fatal(g.text())
	}
}
