package main

import (
	"errors"
	"flag"
	"os"
	"strings"

	"github.com/vulnetix/belai/internal/agentprofile"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// adhocFlags are the flags that describe a worker with no stored profile. They
// go with -prompt and are refused without it.
type adhocFlags struct {
	prompt, tools, claim, to, publish *string
	readOnly, promptEnv               *bool
}

func addAdhocFlags(fs *flag.FlagSet) adhocFlags {
	return adhocFlags{
		prompt:    fs.String("prompt", "", "run a worker made from this prompt instead of a stored profile"),
		tools:     fs.String("tools", "", "with -prompt, the tools the worker may use, comma separated (default: all)"),
		claim:     fs.String("claim", "", "with -prompt, what to claim: LIST[:LABEL,LABEL] (default: backlog)"),
		to:        fs.String("to", "", "with -prompt, the list a success goes to (default: review, or done for a worker that only decides)"),
		publish:   fs.String("publish", "", "with -prompt, none, draft_pr or agent (default: agent)"),
		readOnly:  fs.Bool("read-only", false, "with -prompt, run checks in a throwaway worktree and change nothing"),
		promptEnv: fs.Bool("prompt-from-env", false, "read -prompt from $"+sessionsync.AdhocPromptEnv+" (how belai rc passes it, off argv)"),
	}
}

// extras reports whether any flag besides -prompt was given.
func (a adhocFlags) extras() bool {
	return *a.tools != "" || *a.claim != "" || *a.to != "" || *a.publish != "" || *a.readOnly
}

// profile builds the worker the flags describe, or nil when there is no -prompt.
func (a adhocFlags) profile() (*agentprofile.AgentProfile, error) {
	if a.promptEnv != nil && *a.promptEnv {
		if *a.prompt != "" {
			return nil, errors.New("-prompt and -prompt-from-env are one or the other")
		}
		// Read once and unset, so the workers this start launches never inherit it.
		*a.prompt = os.Getenv(sessionsync.AdhocPromptEnv)
		_ = os.Unsetenv(sessionsync.AdhocPromptEnv)
		if *a.prompt == "" {
			return nil, errors.New("-prompt-from-env: $" + sessionsync.AdhocPromptEnv + " is empty")
		}
	}
	if strings.TrimSpace(*a.prompt) == "" {
		if *a.prompt != "" {
			return nil, errors.New("-prompt is empty")
		}
		if a.extras() {
			return nil, errors.New("-tools, -claim, -to, -publish and -read-only describe a worker made with -prompt")
		}
		return nil, nil
	}
	lists, labels, err := parseClaim(*a.claim)
	if err != nil {
		return nil, err
	}
	p, err := agentprofile.Ephemeral(agentprofile.EphemeralOptions{
		Prompt: *a.prompt, Tools: splitList(*a.tools), Lists: lists, Labels: labels,
		To: *a.to, Publish: *a.publish, ReadOnly: *a.readOnly,
	})
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// parseClaim reads LIST[:LABEL,LABEL].
func parseClaim(s string) (lists, labels []string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil, nil
	}
	list, rest, hasLabels := strings.Cut(s, ":")
	if strings.TrimSpace(list) == "" || strings.Contains(list, ",") {
		return nil, nil, errors.New("-claim is LIST[:LABEL,LABEL], one list")
	}
	lists = []string{strings.TrimSpace(list)}
	if hasLabels {
		if labels = splitList(rest); len(labels) == 0 {
			return nil, nil, errors.New("-claim names labels after the colon, or none")
		}
	}
	return lists, labels, nil
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}
