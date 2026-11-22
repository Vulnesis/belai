package main

import (
	"testing"

	"github.com/vulnetix/belai/internal/harness"
)

func TestCheckProfile(t *testing.T) {
	env := Env{Own: map[string][]string{"cc": {"ANTHROPIC_API_KEY", "CLAUDE_CODE_*"}}, Services: []string{"OPENAI_API_KEY"}}
	pty := func(conf, min string, grant ...string) *harness.Launch {
		return &harness.Launch{Tier: harness.TierPTY, Conf: conf, Bins: []string{"x"}, Argv: []string{"{bin}"}, MinVersion: min, GrantEnv: grant}
	}
	ok := map[string]*harness.Launch{
		"own":      pty(harness.ConfHost, "1.0", "ANTHROPIC_API_KEY"),
		"prefix":   pty(harness.ConfHost, "1.0", "CLAUDE_CODE_TOKEN"),
		"service":  pty(harness.ConfHost, "1.0", "OPENAI_API_KEY"),
		"docs":     pty(harness.ConfDocs, ""),
		"no grant": pty(harness.ConfHost, "1.0"),
	}
	for name, l := range ok {
		if err := checkProfile("cc", l, env); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]*harness.Launch{
		"no pin":       pty(harness.ConfHost, ""),
		"unrecorded":   pty(harness.ConfHost, "1.0", "AUGMENT_SESSION_AUTH"),
		"other's own":  pty(harness.ConfHost, "1.0", "CODEX_KEY"),
		"bare star":    pty(harness.ConfDocs, "", "STAR"),
		"not a prefix": pty(harness.ConfHost, "1.0", "CLAUDE_CODEX"),
	}
	env.Own["other"] = []string{"CODEX_*", "*"}
	for name, l := range bad {
		if err := checkProfile("cc", l, env); err == nil {
			t.Errorf("%s: passed", name)
		}
	}
}
