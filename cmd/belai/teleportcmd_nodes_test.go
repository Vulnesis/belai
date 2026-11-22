package main

import (
	"strings"
	"testing"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// -teleport-to completes a node id, a name or a unique prefix from
// Fleet.Nodes; this host, bad ids and control characters never show.
func TestTeleportToCompletesFromTheFleet(t *testing.T) {
	cands := teleportCandidates([]*nodev1.NodeSummary{
		{NodeId: "n-self", Name: "self"},
		{NodeId: "n-build1", Name: "build-01", Online: true},
		{NodeId: "n-build2", Name: "build-02"},
		{NodeId: "n-gpu", Name: "gpu\x1b[31m"},
		{NodeId: "bad id", Name: "x"},
	}, "n-self")
	if len(cands) != 3 || strings.ContainsRune(cands[2].Name, 0x1b) {
		t.Fatalf("candidates = %+v", cands)
	}
	for v, want := range map[string]string{"n-gpu": "n-gpu", "BUILD-01": "n-build1", "n-build2": "n-build2", "gp": "n-gpu"} {
		if id, _ := matchTeleportNode(cands, v); id != want {
			t.Errorf("%q = %q, want %q", v, id, want)
		}
	}
	if id, fit := matchTeleportNode(cands, "build"); id != "" || len(fit) != 2 {
		t.Errorf("ambiguous = %q %+v", id, fit)
	}
	if id, fit := matchTeleportNode(cands, "zzz"); id != "" || len(fit) != 3 {
		t.Errorf("unknown = %q %+v", id, fit)
	}
	if s := formatTeleportNodes(cands[:1]); !strings.Contains(s, "n-build1  build-01  online") {
		t.Errorf("list = %q", s)
	}
}
