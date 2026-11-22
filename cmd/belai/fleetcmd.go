package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sanitize"
)

// runFleetCLI implements `belai connect nodes|dispatch|prompt`: this host
// asks Keleustes for work on another node (docs/keleustes.md#cross-host-dispatch).
// Every request it files is the user's (initiated_by "user"). Everything
// Keleustes answers is printed through sanitize.Line.
func runFleetCLI(ctx context.Context, home, cmd string, args []string, stdout, stderr io.Writer) int {
	p, err := factorylink.Active(home)
	if err != nil || p.Revoked != "" {
		fmt.Fprintln(stderr, "connect: this host is not an active Keleustes node")
		return 1
	}
	c, err := factorylink.NewClient(p)
	if err != nil {
		fmt.Fprintln(stderr, "connect:", err)
		return 1
	}
	defer c.Close()
	line := func(s string) string { return sanitize.Line(s, 400) }
	switch cmd {
	case "nodes":
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		nodes, err := c.FleetNodes(rctx)
		if err != nil {
			fmt.Fprintln(stderr, "connect nodes:", line(err.Error()))
			return 1
		}
		for _, n := range nodes {
			state := "offline"
			if n.GetOnline() {
				state = "online"
			}
			if n.GetRemoteControl() {
				state += ",rc"
			}
			fmt.Fprintf(stdout, "%s\t%s\t%s\t%d/%d\t%s\n", line(n.GetNodeId()), line(n.GetName()), state,
				n.GetRunningSessions(), n.GetMaxSessions(), line(strings.Join(n.GetAgents(), ",")))
		}
		return 0
	case "prompt":
		if len(args) < 2 {
			fmt.Fprintln(stderr, "usage: belai connect prompt NODE:SESSION TEXT")
			return 2
		}
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		t, err := c.FleetPrompt(rctx, args[0], strings.Join(args[1:], " "), "", factorylink.InitiatedByUser)
		if err != nil {
			fmt.Fprintln(stderr, "connect prompt:", line(err.Error()))
			return 1
		}
		fmt.Fprintf(stdout, "%s\t%s\n", line(t.GetRequestId()), line(t.GetState()))
		if t.GetState() == "refused" {
			fmt.Fprintln(stderr, "refused:", line(t.GetReason()))
			return 1
		}
		return 0
	}
	fs := flag.NewFlagSet("connect dispatch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	on := fs.String("on", "any", "target node id or name, or any")
	kind := fs.String("kind", "session", "session, worker or crew")
	cwd := fs.String("cwd", "", "a directory the target offers")
	prompt := fs.String("prompt", "", "the session's prompt")
	agent := fs.String("agent", "", "agent profile")
	crew := fs.String("crew", "", "crew")
	prov := fs.String("provider", "", "provider")
	model := fs.String("model", "", "model")
	wait := fs.Int("wait", 0, "seconds to wait for the target to start it")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	target := *on
	if target == "any" {
		target = ""
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	t, err := c.FleetRequest(rctx, target, &nodev1.Dispatch{Kind: *kind, Cwd: *cwd, Prompt: *prompt, Agent: *agent,
		Crew: *crew, Provider: *prov, Model: *model}, "", factorylink.InitiatedByUser)
	cancel()
	if err != nil {
		fmt.Fprintln(stderr, "connect dispatch:", line(err.Error()))
		return 1
	}
	fmt.Fprintf(stdout, "request %s\t%s\t%s\n", line(t.GetRequestId()), line(t.GetState()), line(t.GetTargetNode()))
	if t.GetState() == "refused" {
		fmt.Fprintln(stderr, "refused:", line(t.GetReason()))
		return 1
	}
	if *wait <= 0 {
		return 0
	}
	wctx, cancel := context.WithTimeout(ctx, time.Duration(*wait)*time.Second)
	defer cancel()
	code := 2
	_ = c.FleetWatch(wctx, []string{t.GetRequestId()}, func(s *nodev1.DispatchStatus) bool {
		fmt.Fprintf(stdout, "%s\t%s\n", line(s.GetState()), line(s.GetReason()))
		switch s.GetState() {
		case "started", "finished":
			if s.GetSessionId() != "" {
				fmt.Fprintf(stdout, "session %s\n", line(s.GetSessionId()))
			}
			code = 0
		case "refused", "failed":
			code = 1
		}
		return !factorylink.Settled(s.GetState())
	})
	return code
}
