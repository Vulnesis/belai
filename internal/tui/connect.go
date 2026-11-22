package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// Keleustes (the desktop Software Factory) link: /connect <token> joins
// this host as a managed node, /connect status shows the link, and
// /disconnect leaves. See docs/keleustes.md.

type connectJoinedMsg struct {
	p   *factorylink.Profile
	err error
}

func (a *App) factoryHome() (string, error) { return config.GlobalDir() }

func (a *App) factoryAdvert(ctx context.Context) *nodev1.HostAdvert {
	home, _ := a.factoryHome()
	return factorylink.HostAdvert(ctx, home, factorylink.HostOptions{Terminal: true})
}

// startFactoryLink opens the link to the active Keleustes profile, if any.
// Like session sync it only runs on a real run (start.go).
// When another belai process on this host already owns the link, this one
// watches it and takes over if that process exits.
func (a *App) startFactoryLink() {
	if a.factoryNode != nil {
		return
	}
	home, err := a.factoryHome()
	if err != nil {
		return
	}
	p, err := factorylink.Active(home)
	if err != nil || p.Revoked != "" {
		return
	}
	a.factoryNode = factorylink.NewNode(p, a.factoryAdvert, nil)
	if a.factoryCtl == nil {
		a.factoryCtl = make(chan factorylink.Control, 4)
	}
	ctl := a.factoryCtl
	a.factoryNode.OnControl(func(c factorylink.Control) {
		select {
		case ctl <- c:
		default:
		}
	})
	a.factoryNode.Start(context.Background())
}

func (a *App) stopFactoryLink() {
	if a.factoryNode == nil {
		return
	}
	a.factoryNode.Stop(3 * time.Second)
	a.factoryNode = nil
}

func (a *App) connectCommand(arg string) tea.Cmd {
	arg = strings.TrimSpace(arg)
	switch {
	case arg == "" || arg == "status":
		a.addSystem(a.connectStatusText())
		return nil
	case factorylink.LooksLikeToken(arg):
		tok, err := factorylink.ParseToken(arg, time.Now())
		if err != nil {
			a.addSystem("connect: " + err.Error())
			return nil
		}
		home, err := a.factoryHome()
		if err != nil {
			a.addSystem("connect: " + err.Error())
			return nil
		}
		if p, err := factorylink.Active(home); err == nil && p.Revoked == "" && p.ServerID != tok.ServerID {
			a.addSystem(fmt.Sprintf("connect: this host is already a node of %s; /disconnect first", p.ServerName))
			return nil
		}
		a.addSystem(fmt.Sprintf("connecting to Keleustes %q at %s …", tok.ServerName, strings.Join(tok.Addrs, ", ")))
		return func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			p, err := factorylink.Join(ctx, home, tok, a.factoryAdvert(ctx))
			return connectJoinedMsg{p: p, err: err}
		}
	default:
		a.addSystem("usage: /connect <kls1… token> | /connect status   (mint a token in Keleustes: Fleet → Add node)")
		return nil
	}
}

func (a *App) disconnectCommand() tea.Cmd {
	home, err := a.factoryHome()
	if err != nil {
		a.addSystem("disconnect: " + err.Error())
		return nil
	}
	p, err := factorylink.Active(home)
	if errors.Is(err, factorylink.ErrNoProfile) {
		a.addSystem("disconnect: this host is not a Keleustes node")
		return nil
	}
	if err != nil {
		a.addSystem("disconnect: " + err.Error())
		return nil
	}
	a.stopFactoryLink()
	if err := factorylink.Remove(home, p); err != nil {
		a.addSystem("disconnect: " + err.Error())
		return nil
	}
	a.addSystem(fmt.Sprintf("left Keleustes %q: this host's node certificate is deleted. It still shows in Keleustes Fleet until revoked there; rejoin with a new token.", p.ServerName))
	return a.resyncAfterFactoryChange()
}

func (a *App) handleConnectMsg(msg tea.Msg) (tea.Cmd, bool) {
	m, ok := msg.(connectJoinedMsg)
	if !ok {
		return nil, false
	}
	if m.err != nil {
		a.addSystem("connect: " + m.err.Error())
		return nil, true
	}
	a.stopFactoryLink()
	a.startFactoryLink()
	a.addSystem(fmt.Sprintf("joined Keleustes %q as node %s. The link stays open while belai runs; /connect status shows it.", m.p.ServerName, shortID(m.p.NodeID)))
	return a.resyncAfterFactoryChange(), true
}

func (a *App) connectStatusText() string {
	home, err := a.factoryHome()
	if err != nil {
		return "keleustes: " + err.Error()
	}
	p, err := factorylink.Active(home)
	if errors.Is(err, factorylink.ErrNoProfile) {
		return "keleustes: not connected (/connect <token> joins; mint one in Keleustes Fleet → Add node)"
	}
	if err != nil {
		return "keleustes: " + err.Error()
	}
	if p.Revoked != "" {
		return fmt.Sprintf("keleustes: node %s was revoked by %q (%s). /disconnect, then join with a new token.", shortID(p.NodeID), p.ServerName, p.Revoked)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "keleustes: %q · node %s", p.ServerName, shortID(p.NodeID))
	var st factorylink.NodeStatus
	if a.factoryNode != nil {
		st = a.factoryNode.Status()
	} else {
		st = factorylink.SharedStatus(p)
	}
	fmt.Fprintf(&b, " · %s", st.State)
	if !st.Owner && st.OwnerPID > 0 {
		fmt.Fprintf(&b, " (link held by belai pid %d)", st.OwnerPID)
	}
	if st.State == factorylink.StateOnline {
		fmt.Fprintf(&b, " via %s since %s", st.Addr, st.Since.Format("15:04:05"))
	}
	if st.LastError != "" && st.State != factorylink.StateOnline {
		fmt.Fprintf(&b, " · last error: %s", st.LastError)
	}
	return b.String()
}

// resyncAfterFactoryChange moves session sync to the server the host now
// belongs to: Keleustes after a join, the website after leaving. The live
// session ends on the old server and registers on the new one. A run that
// never started sync (every test) is left alone.
func (a *App) resyncAfterFactoryChange() tea.Cmd {
	if a.syncer == nil && a.syncNote == "" {
		return nil
	}
	a.closeSync()
	a.startSessionSync()
	return a.watchRemote()
}

// showFactoryControl reports, on the UI loop, each change of the factory's
// control state the link heard (docs/keleustes.md#factory-control). The
// state itself is already recorded for the host: remote prompts are refused
// while the factory is stopped, and the A2A relay stops during a blackout.
func (a *App) showFactoryControl() {
	if a.factoryCtl == nil {
		return
	}
	for {
		select {
		case c := <-a.factoryCtl:
			if c.Stopped == a.factoryLast.Stopped && c.A2ABlackout == a.factoryLast.A2ABlackout {
				continue
			}
			prev := a.factoryLast
			a.factoryLast = c
			why := ""
			if c.Reason != "" {
				why = " (" + c.Reason + ")"
			}
			if c.Stopped != prev.Stopped {
				if c.Stopped {
					a.addSystem("keleustes: the factory is stopped" + why + "; remote prompts are refused until it resumes")
				} else {
					a.addSystem("keleustes: the factory resumed")
				}
			}
			if c.A2ABlackout != prev.A2ABlackout {
				if c.A2ABlackout {
					a.addSystem("keleustes: A2A blackout" + why + "; nothing is relayed between hosts")
				} else {
					a.addSystem("keleustes: the A2A blackout is lifted")
				}
			}
		default:
			return
		}
	}
}
