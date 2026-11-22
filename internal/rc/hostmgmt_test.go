package rc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sessionsync"
)

func hostTestDaemon(t *testing.T, started *[]WorkerStart) (*Daemon, string) {
	t.Helper()
	t.Setenv("BELAI_HOME", t.TempDir())
	proj := t.TempDir()
	real, _ := Normalize(proj)
	client, err := sessionsync.NewClient("http://127.0.0.1:1", func() (string, error) { return "ApiKey o:k", nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	d, err := New(Options{
		Client: client, HostID: testHost, Dirs: []Dir{{Path: real, Name: "proj", Source: SourceTrusted}}, ProjectSettings: true,
		Inventory: func() Inventory {
			return Inventory{Profiles: []sessionsync.RCProfile{{Name: "belai:builder"}, {Name: "mine"}}}
		},
		StartWorkers: func(w WorkerStart) (string, error) { *started = append(*started, w); return "ok", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return d, real
}

// agents.builtin.<profile>=false in the host's preferences refuses a worker
// start of that built-in in the directory, whoever asked (a website request,
// a Keleustes dispatch or a stored schedule all go through startWorkers).
func TestBuiltinOffForRepoRefusesStartWorkers(t *testing.T) {
	var started []WorkerStart
	d, dir := hostTestDaemon(t, &started)
	if _, why := d.startWorkers(sessionsync.Dispatch{Kind: "worker", Cwd: dir, Profile: "belai:builder"}); why != "" {
		t.Fatalf("refused before the switch: %s", why)
	}
	// Set through the same path the project_prefs request and the host
	// action take.
	if _, why := d.hostHooks().SetProjectPrefs(dir, map[string]any{"agents.builtin.belai:builder": false}, nil); why != "" {
		t.Fatalf("set prefs: %s", why)
	}
	_, why := d.startWorkers(sessionsync.Dispatch{Kind: "worker", Cwd: dir, Profile: "belai:builder"})
	if !strings.HasPrefix(why, "disabled for repo") {
		t.Fatalf("why = %q, want disabled for repo", why)
	}
	if _, why := d.startWorkers(sessionsync.Dispatch{Kind: "worker", Cwd: dir, Profile: "mine"}); why != "" {
		t.Fatalf("another profile refused: %s", why)
	}
	if len(started) != 2 {
		t.Fatalf("%d starts, want 2", len(started))
	}
	if p, _ := config.LoadProjectPrefs(dir); p.BuiltinAgentState("belai:builder") != "off" {
		t.Fatal("the preference was not written")
	}
}

// A drain refuses new Keleustes dispatches with "restarting" and returns
// once nothing runs; Undrain lets work in again.
func TestHostDrainRefusesDispatches(t *testing.T) {
	var started []WorkerStart
	d, dir := hostTestDaemon(t, &started)
	h := d.hostHooks()
	if forced := h.Drain(context.Background(), time.Second); forced {
		t.Fatal("an idle daemon did not drain at once")
	}
	_, _, why, _ := d.factoryStart(context.Background(), &nodev1.Dispatch{Id: "d1", Kind: "worker", Cwd: dir, Agent: "mine"}, nil)
	if why != restartingReason {
		t.Fatalf("why = %q, want the restarting refusal", why)
	}
	h.Undrain()
	if _, _, why, _ := d.factoryStart(context.Background(), &nodev1.Dispatch{Id: "d2", Kind: "worker", Cwd: dir, Agent: "mine"}, nil); why != "" {
		t.Fatalf("refused after undrain: %s", why)
	}
}
