package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const libBuilderMD = `---
name: e2e-builder
description: Builds what a card asks
mode: worker
tools: [Read, Write]
kanban:
  labels: [build]
  on_success: {list: review}
workspace: {isolation: worktree}
---
Build it.
`

const libCrewID = "5d1b8f9e-2a3c-4d4e-9f60-718293a4b5c6"

// TestKeleustesCrewRoundTrip (P5, belai-counterparts #21): a crew and its
// member profile go from host A to Keleustes's library with a
// library_backup, and from there to host B with a library_install, which
// writes the member before the crew and keeps the crew's id. The real
// keleustes and belai binaries, two rc daemons, no network.
func TestKeleustesCrewRoundTrip(t *testing.T) {
	k := startKeleustes(t)
	model := newKeleustesModel(t)
	a := startRC(t, k, "lib-a", model.URL)
	b := startRC(t, k, "lib-b", model.URL)

	// Host A holds a worker profile and a crew of it.
	onA := func(args ...string) {
		t.Helper()
		cmd := exec.Command(belaiBin, args...)
		cmd.Env = belaiEnv(model.URL, a.home, "DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent/keleustes-e2e")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("belai %v on A: %v\n%s", args, err, out)
		}
	}
	md := filepath.Join(t.TempDir(), "e2e-builder.md")
	os.WriteFile(md, []byte(libBuilderMD), 0o600)
	onA("agent", "import", md)
	crew := filepath.Join(t.TempDir(), "e2e-crew.json")
	os.WriteFile(crew, []byte(`{"id":"`+libCrewID+`","name":"e2e-crew","description":"two builders","members":[{"profile":"e2e-builder","replicas":2}]}`), 0o600)
	onA("agent", "crew", "import", crew)

	// Back both up from A.
	if out, err := k.try("sessions", "library", "--node", a.label, "--backup", "profile:e2e-builder", "--backup", "crew:e2e-crew"); err != nil {
		t.Fatalf("backup: %v %s", err, out)
	}
	// Install both on B, the crew named first: B writes the member first.
	// Until A's backup lands the fetch finds nothing, so ask again.
	crewFile := filepath.Join(b.home, "profiles", "crews", "e2e-crew.json")
	deadline := time.Now().Add(120 * time.Second)
	for {
		if _, err := os.Stat(crewFile); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("host B never wrote the crew")
		}
		_, _ = k.try("sessions", "library", "--node", b.label, "--install", "crew:e2e-crew", "--install", "profile:e2e-builder")
		time.Sleep(4 * time.Second)
	}
	data, err := os.ReadFile(crewFile)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Members []struct {
			Profile  string `json:"profile"`
			Replicas int    `json:"replicas"`
		} `json:"members"`
	}
	if err := json.Unmarshal(data, &got); err != nil || got.ID != libCrewID || got.Name != "e2e-crew" ||
		len(got.Members) != 1 || got.Members[0].Profile != "e2e-builder" || got.Members[0].Replicas != 2 {
		t.Fatalf("host B crew = %s (%v)", data, err)
	}
	if _, err := os.Stat(filepath.Join(b.home, "profiles", "agents", "e2e-builder.json")); err != nil {
		t.Errorf("host B has no member profile: %v", err)
	}
}
