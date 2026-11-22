package tui

import "testing"

func TestParseOn(t *testing.T) {
	name, on, cwd, ok := parseOn("patcher --on build-box --cwd /src/api", "/here")
	if !ok || name != "patcher" || on != "build-box" || cwd != "/src/api" {
		t.Errorf("got %q %q %q %v", name, on, cwd, ok)
	}
	if name, on, cwd, ok = parseOn("patcher --on any", "/here"); !ok || on != "any" || cwd != "/here" || name != "patcher" {
		t.Errorf("default cwd: %q %q %q %v", name, on, cwd, ok)
	}
	if _, _, _, ok = parseOn("--on any", "/here"); ok {
		t.Error("no name accepted")
	}
}
