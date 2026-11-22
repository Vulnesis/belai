package rc

import (
	"fmt"
	"slices"
	"sort"

	"github.com/vulnetix/belai/internal/config"
)

// Harness gates a Keleustes dispatch may set per session (Dispatch.options,
// belai-counterparts #51). Each can only tighten what the host's own settings
// say:
//
//	finish_review  "on": the finish review gate runs (docs/finish-review.md)
//	lint_loop      "on": the per-edit lint loop runs (docs/lint.md)
//	checkpoints    "on": file checkpoints are kept (docs/checkpoints.md)
//	code_mode      "off": the Code tool's interpreter is off (docs/code-mode.md)
//	commit_mode    "off", "ask" or "auto" (aliases "none", "end", "per_task"):
//	               no more committing than the host's commit_mode allows
//
// A value that would loosen the host's setting is not an error: it is left
// out of the session and audited as host.dispatch option_ignored by the
// daemon (gateIgnored), so the console learns the host kept its own gate.
var GateOptionKeys = []string{"finish_review", "lint_loop", "checkpoints", "code_mode", "commit_mode"}

// commitRank orders commit modes from the most to the least restrictive.
var commitRank = map[string]int{config.CommitModeOff: 0, config.CommitModeAsk: 1, config.CommitModeAuto: 2}

// gateCommitMode reads a commit_mode value, aliases included.
func gateCommitMode(v string) (string, bool) {
	switch v {
	case "off", "none":
		return config.CommitModeOff, true
	case "ask", "end":
		return config.CommitModeAsk, true
	case "auto", "per_task":
		return config.CommitModeAuto, true
	}
	return "", false
}

// checkGateOption says why a gate value is malformed, or "". Shape only: a
// well-formed value that would loosen a gate is ignored, not refused.
func checkGateOption(k, v string) string {
	switch k {
	case "finish_review", "lint_loop", "checkpoints", "code_mode":
		if v != "on" && v != "off" {
			return fmt.Sprintf("%s is on or off", k)
		}
	case "commit_mode":
		if _, ok := gateCommitMode(v); !ok {
			return "commit_mode is off, ask or auto"
		}
	}
	return ""
}

// ApplyGateOptions applies the gate keys in opts to s, each only where it
// tightens s, and returns the keys it left out because they would loosen it
// (sorted). Keys that are not gates are ignored here.
func ApplyGateOptions(s *config.Settings, opts map[string]string) []string {
	var ignored []string
	on, off := true, false
	for k, v := range opts {
		if !slices.Contains(GateOptionKeys, k) || checkGateOption(k, v) != "" {
			continue
		}
		switch k {
		case "finish_review":
			if v != "on" {
				if s.FinishReviewEnabled() {
					ignored = append(ignored, k)
				}
				continue
			}
			f := config.FinishReviewSettings{}
			if s.FinishReview != nil {
				f = *s.FinishReview
			}
			f.Enabled = &on
			s.FinishReview = &f
		case "lint_loop":
			if v != "on" {
				if s.LintLoopEnabled() {
					ignored = append(ignored, k)
				}
				continue
			}
			l := config.LintLoopSettings{}
			if s.LintLoop != nil {
				l = *s.LintLoop
			}
			l.Enabled = &on
			s.LintLoop = &l
		case "checkpoints":
			if v != "on" {
				if s.CheckpointsEnabled() {
					ignored = append(ignored, k)
				}
				continue
			}
			c := config.CheckpointSettings{}
			if s.Checkpoints != nil {
				c = *s.Checkpoints
			}
			c.Enabled = &on
			s.Checkpoints = &c
		case "code_mode":
			if v != "off" {
				if !s.CodeEnabled() {
					ignored = append(ignored, k)
				}
				continue
			}
			c := config.CodeSettings{}
			if s.Code != nil {
				c = *s.Code
			}
			c.Enabled = &off
			s.Code = &c
		case "commit_mode":
			want, _ := gateCommitMode(v)
			if commitRank[want] > commitRank[s.CommitModeEffective()] {
				ignored = append(ignored, k)
				continue
			}
			s.CommitMode = want
			if want == config.CommitModeOff {
				s.AutoCommitPerTask = &off
			}
		}
	}
	sort.Strings(ignored)
	return ignored
}
