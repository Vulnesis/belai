package rc

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/fleet"
	"github.com/vulnetix/belai/internal/sanitize"
)

// Keleustes budget pushes (dispatch kind "budget_update", keleustes
// belai-counterparts #33). A budget limit changed or was hit while work runs;
// the push says what to do with this host's live workers:
//
//	limits     lower the workers' per-item caps to Dispatch.budget (a lower cap
//	           wins; a push never loosens one), from the next item
//	downgrade  move the next turn to Dispatch.provider/model (the fast tier
//	           Keleustes resolved), through the worker's own control file
//	pause      finish the item in hand, then claim nothing (the pause marker)
//	resume     lift that pause
//
// worker_id, session_ids and run_id narrow it; with all empty every live
// worker of this host matches. An rc session has no live channel for a
// budget, so a session it names is only reported as noted. The kill switch
// check in factoryStart refuses a push while the factory is stopped.

// budgetActions are the push actions this host takes.
var budgetActions = []string{"limits", "downgrade", "pause", "resume"}

// factoryModelName is the shape a provider or model name a push carries must have.
var factoryModelName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$`)

// maxBudgetSessions bounds the session ids one push may name.
const maxBudgetSessions = 256

// budgetPush is a checked push.
type budgetPush struct {
	action, tier, budgetID, worker, run string
	provider, model                     string
	sessions                            []string
	limits                              *fleet.Limits
}

// parseBudgetPush checks every field of a budget_update dispatch.
func parseBudgetPush(fd *nodev1.Dispatch) (budgetPush, string) {
	bp := fd.GetBudgetPush()
	if bp == nil {
		return budgetPush{}, "a budget_update carries a budget push"
	}
	p := budgetPush{action: bp.GetAction(), tier: bp.GetTier(), worker: fd.GetWorkerId(), run: fd.GetRunId()}
	if !slices.Contains(budgetActions, p.action) {
		return budgetPush{}, fmt.Sprintf("unknown budget action %q", sanitize.Ident(p.action, 32))
	}
	if p.budgetID = bp.GetBudgetId(); p.budgetID != "" && sanitize.Ident(p.budgetID, 64) != p.budgetID {
		return budgetPush{}, "the budget id is not an identifier"
	}
	if p.worker != "" && !fleet.ValidID(p.worker) {
		return budgetPush{}, "that is not a worker id"
	}
	if p.run != "" && sanitize.Ident(p.run, 64) != p.run {
		return budgetPush{}, "the run id is not an identifier"
	}
	if len(bp.GetSessionIds()) > maxBudgetSessions {
		return budgetPush{}, fmt.Sprintf("a budget push names at most %d sessions", maxBudgetSessions)
	}
	for _, s := range bp.GetSessionIds() {
		if s == "" || sanitize.Ident(s, 64) != s {
			return budgetPush{}, "a session id is not an identifier"
		}
		p.sessions = append(p.sessions, strings.ToLower(s))
	}
	switch p.action {
	case "downgrade":
		if p.tier != "fast" {
			return budgetPush{}, fmt.Sprintf("unknown model tier %q", sanitize.Ident(p.tier, 32))
		}
		p.provider, p.model = fd.GetProvider(), fd.GetModel()
		if p.model == "" || !factoryModelName.MatchString(p.model) || (p.provider != "" && !factoryModelName.MatchString(p.provider)) {
			return budgetPush{}, "a downgrade names the model to move to"
		}
	case "limits":
		p.limits = fleet.LimitsFrom(factoryBudget(fd.GetBudget()))
		if p.limits == nil || *p.limits == (fleet.Limits{}) {
			return budgetPush{}, "a limits push carries the new caps"
		}
		// Only caps travel: a price or a lease is not a limit.
		p.limits.Price, p.limits.PriceModel, p.limits.Lease, p.limits.FinalizeAt = nil, "", "", 0
	default:
		if p.tier != "" {
			return budgetPush{}, "only a downgrade names a tier"
		}
	}
	return p, ""
}

// matches reports whether a live worker is one the push names.
func (p budgetPush) matches(rec fleet.Record) bool {
	if p.worker == "" && len(p.sessions) == 0 && p.run == "" {
		return true
	}
	return (p.worker != "" && rec.ID == p.worker) ||
		(rec.Session != "" && slices.Contains(p.sessions, strings.ToLower(rec.Session))) ||
		(p.run != "" && rec.Run == p.run)
}

// factoryBudgetUpdate applies a budget push to this host's live workers. It
// returns factoryStart's values: a report with counts, or why it refused.
func (d *Daemon) factoryBudgetUpdate(fd *nodev1.Dispatch) (sid, report, why string, failed bool) {
	p, why := parseBudgetPush(fd)
	if why != "" {
		return "", "", why, false
	}
	reg, err := d.o.Fleet()
	if err != nil {
		return "", "", "this host's worker registry cannot be read", true
	}
	live, _ := reg.Live()
	var applied, refused int
	var errs []error
	for _, rec := range live {
		if !p.matches(rec) {
			continue
		}
		var err error
		switch p.action {
		case "pause", "resume":
			err = reg.SetPaused(rec.ID, p.action == "pause")
		case "downgrade":
			_, err = reg.SetControl(rec.ID, "factory", func(c *fleet.Control) {
				c.Target = fleet.Target{Provider: p.provider, Model: p.model}
			})
		case "limits":
			_, err = reg.SetControl(rec.ID, "factory", func(c *fleet.Control) {
				c.Limits = c.Limits.Tighten(p.limits)
			})
		}
		if err != nil {
			refused++
			errs = append(errs, err)
			continue
		}
		applied++
	}
	noted := 0
	d.mu.Lock()
	for _, s := range p.sessions {
		if _, ok := d.sessions[s]; ok {
			noted++
		}
	}
	d.mu.Unlock()
	audit.Emit(audit.Fact{Kind: audit.HostDispatch, ActorKind: audit.ActorWeb,
		Data: map[string]string{"dispatch": "budget_update", "action": p.action, "budget": p.budgetID,
			"workers": strconv.Itoa(applied), "refused": strconv.Itoa(refused), "sessions": strconv.Itoa(noted), "via": "keleustes"}})
	report = fmt.Sprintf("budget %s: %d worker%s", p.action, applied, plural(applied, "", "s"))
	if refused > 0 {
		report += fmt.Sprintf(", %d not changed (%s)", refused, clip(errors.Join(errs...).Error()))
	}
	if noted > 0 {
		report += fmt.Sprintf(", %d session%s noted (sessions take budgets at their next dispatch)", noted, plural(noted, "", "s"))
	}
	d.logf("keleustes %s", report)
	return "", report, "", false
}
