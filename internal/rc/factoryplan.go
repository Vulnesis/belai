package rc

import (
	"time"

	"github.com/vulnetix/belai/internal/budget"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sanitize"
)

// Provider plan windows in the Keleustes host status (keleustes
// belai-counterparts row 48): the latest five-hour, seven-day and per-minute
// readings this host's usage ledger holds (internal/budget, from provider
// response headers), so Keleustes routing can skip a host whose window is
// nearly used. Numbers, provider ids and times only.

// maxPlanLimits bounds the windows one status carries.
const maxPlanLimits = 32

// localPlanLimits reads the host's usage ledger, read only.
func localPlanLimits() []budget.PlanLimit {
	path, err := budget.DefaultPath()
	if err != nil {
		return nil
	}
	return budget.ReadLimits(path, time.Now())
}

// planWindow is Keleustes's word for a budget window; "" for one it has none
// for.
func planWindow(w string) string {
	switch w {
	case budget.WindowFiveHour, budget.WindowSevenDay:
		return w
	case budget.WindowMinRequests:
		return "rpm"
	case budget.WindowMinTokens:
		return "tpm"
	}
	return ""
}

// planLimitsPB maps readings onto the wire form at now: pace is the share
// used against an even spend over the window (1 = on pace), and runway the
// time left at that rate before the window is spent.
func planLimitsPB(ls []budget.PlanLimit, now time.Time) []*nodev1.PlanLimit {
	var out []*nodev1.PlanLimit
	for _, l := range ls {
		w := planWindow(l.Window)
		if w == "" || l.Provider == "" || sanitize.Ident(l.Provider, 64) != l.Provider || len(out) >= maxPlanLimits {
			continue
		}
		p := &nodev1.PlanLimit{Provider: l.Provider, Window: w, UsedFraction: l.Used,
			ResetAtMs: l.Reset.UnixMilli(), Source: "exact"}
		span := l.Span()
		if elapsed := span - l.Reset.Sub(now); span > 0 && elapsed > 0 && elapsed <= span && l.Used > 0 {
			frac := float64(elapsed) / float64(span)
			p.Pace = l.Used / frac
			rate := l.Used / float64(elapsed) // share per nanosecond
			p.RunwayMs = int64(min((1-l.Used)/rate/1e6, float64(30*24*time.Hour/time.Millisecond)))
		}
		out = append(out, p)
	}
	return out
}

// withPlanLimits adds the host's plan windows to a status.
func (d *Daemon) withPlanLimits(st *nodev1.HostStatus) *nodev1.HostStatus {
	if st != nil && d.o.PlanLimits != nil {
		st.PlanLimits = planLimitsPB(d.o.PlanLimits(), time.Now())
	}
	return st
}
