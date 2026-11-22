package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sanitize"
)

// Cross-host dispatch from the TUI (docs/keleustes.md#cross-host-dispatch):
// `/fleet nodes` and `/fleet start|crew <name> --on <node|any> [--cwd DIR]`.
// A request typed here is the user's (initiated_by "user"); Keleustes's node
// policy decides, and may hold it for the owner. Everything Keleustes says
// back is shown through sanitize.Line as a system line.

// fleetRemoteMsg is one line about a cross-host request, and what to run
// next (the request's watch), if anything.
type fleetRemoteMsg struct {
	text string
	next tea.Cmd
}

// fleetClient is this host's Keleustes client, or why there is none.
func fleetClient() (*factorylink.Client, string) {
	dir, err := config.GlobalDir()
	if err != nil {
		return nil, "no state directory"
	}
	p, err := factorylink.Active(dir)
	if err != nil || p.Revoked != "" {
		return nil, "this host is not an active Keleustes node (/connect <token>)"
	}
	c, err := factorylink.NewClient(p)
	if err != nil {
		return nil, sanitize.Line(err.Error(), 200)
	}
	return c, ""
}

// fleetNodes lists the nodes this host may address.
func fleetNodes() tea.Cmd {
	return func() tea.Msg {
		c, why := fleetClient()
		if c == nil {
			return fleetRemoteMsg{text: "fleet nodes: " + why}
		}
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		nodes, err := c.FleetNodes(ctx)
		if err != nil {
			return fleetRemoteMsg{text: "fleet nodes: " + sanitize.Line(err.Error(), 200)}
		}
		if len(nodes) == 0 {
			return fleetRemoteMsg{text: "fleet nodes: none"}
		}
		var b strings.Builder
		b.WriteString("fleet nodes:")
		for _, n := range nodes {
			state := "offline"
			if n.GetOnline() {
				state = "online"
			}
			fmt.Fprintf(&b, "\n  %s  %s  %d/%d sessions  %s", sanitize.Line(n.GetName(), 64), state,
				n.GetRunningSessions(), n.GetMaxSessions(), sanitize.Line(strings.Join(n.GetAgents(), ", "), 200))
		}
		return fleetRemoteMsg{text: b.String()}
	}
}

// parseOn reads "<name> --on <node|any> [--cwd DIR]".
func parseOn(rest, workdir string) (name, on, cwd string, ok bool) {
	f := strings.Fields(rest)
	cwd = workdir
	for i := 0; i < len(f); i++ {
		switch f[i] {
		case "--on", "-on":
			if i+1 < len(f) {
				on = f[i+1]
				i++
			}
		case "--cwd", "-cwd":
			if i+1 < len(f) {
				cwd = f[i+1]
				i++
			}
		default:
			if name == "" {
				name = f[i]
			}
		}
	}
	return name, on, cwd, name != "" && on != ""
}

// fleetRequest asks Keleustes to start a worker or crew on another node and
// follows the request until it settles.
func fleetRequest(kind, name, on, cwd string) tea.Cmd {
	return func() tea.Msg {
		c, why := fleetClient()
		if c == nil {
			return fleetRemoteMsg{text: "fleet: " + why}
		}
		target := on
		if target == "any" {
			target = ""
		}
		spec := &nodev1.Dispatch{Kind: kind, Cwd: cwd}
		if kind == "crew" {
			spec.Crew = name
		} else {
			spec.Agent = name
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		t, err := c.FleetRequest(ctx, target, spec, "", factorylink.InitiatedByUser)
		cancel()
		if err != nil {
			c.Close()
			return fleetRemoteMsg{text: "fleet: " + sanitize.Line(err.Error(), 200)}
		}
		line := fmt.Sprintf("⚙ asked Keleustes for %s %s on %s: %s", kind, sanitize.Line(name, 64),
			sanitize.Line(on, 64), sanitize.Line(t.GetState(), 40))
		if t.GetReason() != "" {
			line += " (" + sanitize.Line(t.GetReason(), 200) + ")"
		}
		if t.GetState() == "refused" {
			c.Close()
			return fleetRemoteMsg{text: line}
		}
		return fleetRemoteMsg{text: line, next: fleetWatch(c, t.GetRequestId())}
	}
}

// fleetWatch waits for the request's next state and reports it, then waits
// again until it settles (at most ten minutes in all).
func fleetWatch(c *factorylink.Client, id string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		var last *nodev1.DispatchStatus
		_ = c.FleetWatch(ctx, []string{id}, func(s *nodev1.DispatchStatus) bool {
			last = s
			return !factorylink.Settled(s.GetState())
		})
		c.Close()
		if last == nil {
			return fleetRemoteMsg{text: "fleet: lost track of request " + sanitize.Ident(id, 40)}
		}
		text := "⚙ request " + sanitize.Ident(id, 12) + ": " + sanitize.Line(last.GetState(), 40)
		if s := last.GetSessionId(); s != "" {
			text += " (session " + sanitize.Ident(s, 64) + ")"
		}
		if r := last.GetReason(); r != "" {
			text += ": " + sanitize.Line(r, 200)
		}
		return fleetRemoteMsg{text: text}
	}
}
