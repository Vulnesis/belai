package rc

import (
	"slices"
	"testing"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sessionctl"
)

// Dispatch.options apply to the session's starting controls within the
// host's gates, and never widen them.
func TestApplyFactoryOptions(t *testing.T) {
	st := sessionctl.State{Guardrails: true, AutoCommit: true, TestsPostEnd: "off", TestsOnFail: "off"}
	opts := map[string]string{"tests_post_end": "goal", "tests_on_fail": "diagnose", "auto_commit_per_task": "false",
		"guardrails": "on", "a2a_show": "true", "crew_lease_ms": "600000"}
	if err := ApplyFactoryOptions(&st, opts, true); err != nil {
		t.Fatal(err)
	}
	if st.TestsPostEnd != "goal" || st.TestsOnFail != "diagnose" || st.AutoCommit || !st.Guardrails {
		t.Errorf("state = %+v", st)
	}
	for _, bad := range []map[string]string{
		{"guardrails": "off"},
		{"auto_commit_per_task": "true"},
		{"tests_post_end": "always"},
		{"model": "x"},
		{"crew_lease_ms": "-1"},
	} {
		s := sessionctl.State{Guardrails: true}
		if ApplyFactoryOptions(&s, bad, true) == nil {
			t.Errorf("%v was applied", bad)
		}
	}
	// Turning the test pass on is a session control: it needs --web-controls.
	s := sessionctl.State{}
	if ApplyFactoryOptions(&s, map[string]string{"tests_post_end": "goal"}, false) == nil {
		t.Error("tests on without --web-controls")
	}
	if err := ApplyFactoryOptions(&s, map[string]string{"tests_post_end": "off"}, false); err != nil {
		t.Errorf("tests off refused: %v", err)
	}
}

// The options reach the rc-session child as fixed argv, and a crew lease
// rides on the worker budget.
func TestFactoryOptionsReachTheChildAndTheBudget(t *testing.T) {
	r := factoryRequest(&nodev1.Dispatch{Id: "d", Kind: "worker", Options: map[string]string{"crew_lease_ms": "900000", "a2a_show": "true"}})
	if r.Budget == nil || r.Budget.Lease != "15m0s" || r.Options["a2a_show"] != "true" || r.Options["crew_lease_ms"] != "" {
		t.Fatalf("request = %+v (budget %+v)", r, r.Budget)
	}
	args := childArgs(Child{Dispatch: "d", SessionID: "s", Options: map[string]string{"tests_post_end": "goal", "a2a_show": "true"}})
	i := slices.Index(args, "-factory-option")
	if i < 0 || args[i+1] != "a2a_show=true" || !slices.Contains(args, "tests_post_end=goal") {
		t.Errorf("args = %v", args)
	}
}
