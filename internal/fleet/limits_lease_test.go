package fleet

import (
	"testing"

	"github.com/vulnetix/belai/internal/agentprofile"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// A dispatched crew lease replaces the profile's, within the board's bounds.
func TestLimitsLease(t *testing.T) {
	p := agentprofile.AgentProfile{Kanban: &agentprofile.KanbanSpec{Lease: "20m"}}
	got := LimitsFrom(&sessionsync.WorkerBudget{Lease: "45m"}).Apply(p)
	if got.Kanban.Lease != "45m0s" || p.Kanban.Lease != "20m" {
		t.Errorf("lease = %q (profile %q)", got.Kanban.Lease, p.Kanban.Lease)
	}
	if got := LimitsFrom(&sessionsync.WorkerBudget{Lease: "1s"}).Apply(p); got.Kanban.Lease != "1m0s" {
		t.Errorf("clamped lease = %q", got.Kanban.Lease)
	}
}
