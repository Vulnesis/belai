package rc

import (
	"slices"
	"testing"

	"github.com/vulnetix/belai/internal/harnessdetect"
)

func TestCheckHarness(t *testing.T) {
	cat := &harnessdetect.Catalog{}
	cat.Set([]harnessdetect.Harness{
		{ID: "claude-code", Name: "Claude Code", State: harnessdetect.StateLaunch, Modes: []string{"default", "plan"}, Resume: true},
		{ID: "cursor", Name: "Cursor", State: harnessdetect.StateGUI},
	})
	ok := HarnessStart{ID: "claude-code", Mode: "plan", Resume: "0b6f9a3e-1111-4222-8333-444455556666", Keys: "handoff"}
	if why := checkHarness(ok, "claude-opus-4-1", cat); why != "" {
		t.Fatal(why)
	}
	for name, h := range map[string]HarnessStart{
		"unadvertised": {ID: "codex"},
		"gui":          {ID: "cursor"},
		"mode":         {ID: "claude-code", Mode: "bypassPermissions"},
		"resume":       {ID: "claude-code", Resume: "../x"},
		"keys":         {ID: "claude-code", Keys: "env"},
	} {
		if checkHarness(h, "", cat) == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	if checkHarness(HarnessStart{ID: "claude-code"}, "--dangerously-skip-permissions", cat) == "" {
		t.Error("a flag passed as a model")
	}
}

func TestHarnessChildArgs(t *testing.T) {
	got := harnessChildArgs("d1", "s1", HarnessStart{ID: "claude-code", Mode: "plan", Keys: "own_login"}, "", true)
	want := []string{"rc-harness", "-dispatch", "d1", "-session-id", "s1", "-harness", "claude-code", "-mode", "plan", "-keys", "own_login", "-controls"}
	if !slices.Equal(got, want) {
		t.Fatal(got)
	}
}
