package fleet

import (
	"time"

	"github.com/vulnetix/belai/internal/agentprofile"
)

// Budget pushes from the Software Factory (belai rc budget_update) lower a
// running worker's caps. Unlike the dispatched Limits a worker starts with,
// which replace the profile's values, a push only tightens: each cap becomes
// the lower of what the worker runs with and what the push says, and a zero
// in the push keeps the worker's own.

// lowerInt is the tighter of two caps where zero means no cap.
func lowerInt(cur, push int) int {
	if push > 0 && (cur <= 0 || push < cur) {
		return push
	}
	return cur
}

func lowerFloat(cur, push float64) float64 {
	if push > 0 && (cur <= 0 || push < cur) {
		return push
	}
	return cur
}

// lowerWall is the shorter of two Go durations, "" meaning no cap. An
// unparsable push keeps cur.
func lowerWall(cur, push string) string {
	p, err := time.ParseDuration(push)
	if err != nil || p <= 0 {
		return cur
	}
	c, err := time.ParseDuration(cur)
	if err != nil || c <= 0 || p < c {
		return p.String()
	}
	return cur
}

// Tighten returns l with every cap of push that is lower applied; l is not
// changed. A nil l starts from no caps.
func (l *Limits) Tighten(push *Limits) *Limits {
	var out Limits
	if l != nil {
		out = *l
	}
	if push == nil {
		return &out
	}
	out.MaxCostUSDPerItem = lowerFloat(out.MaxCostUSDPerItem, push.MaxCostUSDPerItem)
	out.MaxContinuations = lowerInt(out.MaxContinuations, push.MaxContinuations)
	out.MaxAttempts = lowerInt(out.MaxAttempts, push.MaxAttempts)
	out.MaxWallPerItem = lowerWall(out.MaxWallPerItem, push.MaxWallPerItem)
	out.MaxPassesPerItem = lowerInt(out.MaxPassesPerItem, push.MaxPassesPerItem)
	out.MaxTokensPerItem = lowerInt(out.MaxTokensPerItem, push.MaxTokensPerItem)
	out.MaxIterations = lowerInt(out.MaxIterations, push.MaxIterations)
	return &out
}

// TightenProfile lowers p's caps to push's where push's are lower; p's own
// blocks are copied, never changed.
func TightenProfile(p agentprofile.AgentProfile, push *Limits) agentprofile.AgentProfile {
	if push == nil {
		return p
	}
	b := agentprofile.BudgetSpec{}
	if p.Budget != nil {
		b = *p.Budget
	}
	b.MaxCostUSDPerItem = lowerFloat(b.MaxCostUSDPerItem, push.MaxCostUSDPerItem)
	b.MaxWallPerItem = lowerWall(b.MaxWallPerItem, push.MaxWallPerItem)
	b.MaxPassesPerItem = lowerInt(b.MaxPassesPerItem, push.MaxPassesPerItem)
	b.MaxTokensPerItem = lowerInt(b.MaxTokensPerItem, push.MaxTokensPerItem)
	if b != (agentprofile.BudgetSpec{}) {
		p.Budget = &b
	}
	if p.Kanban != nil && (push.MaxAttempts > 0 || push.MaxContinuations > 0) {
		k := *p.Kanban
		// A zero here means the board default, not no cap.
		if k.MaxAttempts <= 0 {
			k.MaxAttempts = agentprofile.DefaultMaxAttempts
		}
		if k.MaxContinuations <= 0 {
			k.MaxContinuations = agentprofile.DefaultMaxContinuations
		}
		k.MaxAttempts = lowerInt(k.MaxAttempts, push.MaxAttempts)
		k.MaxContinuations = lowerInt(k.MaxContinuations, push.MaxContinuations)
		p.Kanban = &k
	}
	// A zero means the harness default, which a push does not know: only a
	// set cap is lowered.
	if p.MaxIterations > 0 {
		p.MaxIterations = lowerInt(p.MaxIterations, push.MaxIterations)
	}
	return p
}

// tightenLimits takes a pushed cap set: the worker's limits and its profile
// both keep the lower of each cap, from the next item.
func (w *Worker) tightenLimits(push *Limits) {
	w.Limits = w.Limits.Tighten(push)
	w.Profile = TightenProfile(w.Profile, push)
}
