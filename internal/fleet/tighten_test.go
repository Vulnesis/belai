package fleet

import (
	"testing"

	"github.com/vulnetix/belai/internal/agentprofile"
)

func TestTightenOnlyLowersCaps(t *testing.T) {
	cur := &Limits{MaxCostUSDPerItem: 2, MaxTokensPerItem: 1000, MaxWallPerItem: "30m"}
	got := cur.Tighten(&Limits{MaxCostUSDPerItem: 5, MaxTokensPerItem: 400, MaxWallPerItem: "1h", MaxPassesPerItem: 3})
	if got.MaxCostUSDPerItem != 2 || got.MaxTokensPerItem != 400 || got.MaxWallPerItem != "30m" || got.MaxPassesPerItem != 3 {
		t.Fatalf("tightened = %+v", got)
	}
	if cur.MaxTokensPerItem != 1000 {
		t.Fatal("Tighten changed its receiver")
	}
	if n := (*Limits)(nil).Tighten(&Limits{MaxAttempts: 2}); n.MaxAttempts != 2 {
		t.Fatalf("from nil = %+v", n)
	}
}

func TestTightenProfileKeepsTheLowerCap(t *testing.T) {
	p := agentprofile.AgentProfile{Budget: &agentprofile.BudgetSpec{MaxCostUSDPerItem: 1, MaxWallPerItem: "10m"},
		Kanban: &agentprofile.KanbanSpec{}, MaxIterations: 40}
	q := TightenProfile(p, &Limits{MaxCostUSDPerItem: 3, MaxWallPerItem: "5m", MaxAttempts: 9, MaxContinuations: 2, MaxIterations: 60})
	if q.Budget.MaxCostUSDPerItem != 1 || q.Budget.MaxWallPerItem != "5m0s" {
		t.Fatalf("budget = %+v", q.Budget)
	}
	// A push above the board default does not raise it.
	if q.Kanban.MaxAttempts != agentprofile.DefaultMaxAttempts || q.Kanban.MaxContinuations != 2 || q.MaxIterations != 40 {
		t.Fatalf("kanban = %+v, iterations %d", q.Kanban, q.MaxIterations)
	}
	if p.Budget.MaxWallPerItem != "10m" {
		t.Fatal("TightenProfile changed the profile it was given")
	}
}

func TestAControlLowersTheWorkersCaps(t *testing.T) {
	store, reg := testEnv(t)
	w := newWorker(t, store, reg, builderProfile(), complete)
	w.Record.ID = "t-builder-bbbbbb"
	w.Limits = &Limits{MaxTokensPerItem: 5000}
	if _, err := reg.SetControl(w.Record.ID, "factory", func(c *Control) {
		c.Limits = c.Limits.Tighten(&Limits{MaxTokensPerItem: 800})
	}); err != nil {
		t.Fatal(err)
	}
	w.applyControl()
	if w.Limits.MaxTokensPerItem != 800 || w.Profile.Budget == nil || w.Profile.Budget.MaxTokensPerItem != 800 {
		t.Fatalf("limits %+v, budget %+v", w.Limits, w.Profile.Budget)
	}
	if a, _ := reg.Ack(w.Record.ID); a.Status != AckAccepted {
		t.Fatalf("ack %+v", a)
	}
}
