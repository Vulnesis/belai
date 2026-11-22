package rc

import (
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/sessionctl"
)

// Keleustes crew and step settings (Dispatch.options). Each maps onto a
// control the session already has, and none widens what the host allows:
//
//	guardrails            "on" only: remote work keeps guardrails on
//	tests_post_end        a sessionctl tests value; a value other than "off"
//	tests_on_fail         needs the daemon's --web-controls, as the control does
//	auto_commit_per_task  "false" only: committing is the user's own setting
//	show_internal_work    the console's display; nothing changes on the host
//	a2a_show              the console's display; nothing changes on the host
//	crew_lease_ms         a worker's claim lease (rides on its budget)
var FactoryOptionKeys = []string{"guardrails", "tests_post_end", "tests_on_fail", "auto_commit_per_task",
	"show_internal_work", "a2a_show", "crew_lease_ms"}

// ApplyFactoryOptions applies opts to a session's starting controls, or
// says why it cannot. controls is the daemon's --web-controls.
func ApplyFactoryOptions(st *sessionctl.State, opts map[string]string, controls bool) error {
	for k, v := range opts {
		if slices.Contains(GateOptionKeys, k) {
			// A harness gate (factorygates.go): shape-checked here, applied to
			// the session's settings by ApplyGateOptions, tighten-only.
			if why := checkGateOption(k, v); why != "" {
				return fmt.Errorf("%s", why)
			}
			continue
		}
		if !slices.Contains(FactoryOptionKeys, k) {
			return fmt.Errorf("unknown dispatch option %q", sanitize.Ident(k, 40))
		}
		switch k {
		case "guardrails":
			if v != "on" && v != "true" {
				return fmt.Errorf("a dispatch cannot turn guardrails off on this host")
			}
		case "tests_post_end", "tests_on_fail":
			values := sessionctl.TestsPostEnd
			if k == "tests_on_fail" {
				values = sessionctl.TestsOnFail
			}
			if !slices.Contains(values, v) {
				return fmt.Errorf("%s takes one of %v", k, values)
			}
			if v != "off" && !controls {
				return fmt.Errorf("%s=%s needs belai rc --web-controls on this host", k, v)
			}
			if k == "tests_post_end" {
				st.TestsPostEnd = v
			} else {
				st.TestsOnFail = v
			}
		case "auto_commit_per_task":
			on, err := strconv.ParseBool(v)
			if err != nil {
				return fmt.Errorf("auto_commit_per_task is true or false")
			}
			if on {
				return fmt.Errorf("committing is this host's own setting; a dispatch may only turn it off")
			}
			st.AutoCommit = false
		case "crew_lease_ms":
			ms, err := strconv.ParseInt(v, 10, 64)
			if err != nil || ms <= 0 || time.Duration(ms)*time.Millisecond > 24*time.Hour {
				return fmt.Errorf("crew_lease_ms is a positive number of milliseconds")
			}
		case "show_internal_work", "a2a_show":
			if _, err := strconv.ParseBool(v); err != nil {
				return fmt.Errorf("%s is true or false", k)
			}
		}
	}
	return nil
}
