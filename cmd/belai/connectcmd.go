package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/signal"
	"syscall"
	"time"

	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

const connectUsage = `usage: belai connect <token> | status | serve | leave | nodes | dispatch | prompt

Join this host to a Keleustes server (the desktop Software Factory) as a
managed node. Mint a token in Keleustes: Fleet → Add node.

  <token>   redeem a single-use kls1… join token and save the node profile
  status    show the saved profile and test the link once
  serve     keep the node link open in the foreground until interrupted
  leave     delete this host's node profile and certificate
  nodes     list the other nodes Keleustes lets this host address
  dispatch  ask Keleustes to run work on another node:
            dispatch -on NODE|any -cwd DIR -prompt TEXT [-kind session|worker|crew]
            [-agent NAME] [-crew NAME] [-provider P -model M] [-wait SECONDS]
  prompt    prompt a session on another node: prompt NODE:SESSION TEXT

A dispatch or prompt typed here is the user's; Keleustes applies its node
policy (off by default) and may hold it for approval.

See docs/keleustes.md.
`

// runConnectCLI implements `belai connect …` and returns the exit code.
func runConnectCLI(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, connectUsage)
		return 2
	}
	home, err := config.GlobalDir()
	if err != nil {
		fmt.Fprintln(stderr, "connect:", err)
		return 1
	}
	advert := func(ctx context.Context) *nodev1.HostAdvert {
		return factorylink.HostAdvert(ctx, home, factorylink.HostOptions{})
	}
	switch cmd := args[0]; cmd {
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stderr, connectUsage)
		return 0
	case "status":
		p, err := factorylink.Active(home)
		if err != nil {
			fmt.Fprintln(stdout, "not connected to a Keleustes server")
			return 1
		}
		fmt.Fprintf(stdout, "server %q (%s)\nnode   %s\naddrs  %v\njoined %s\n", p.ServerName, p.ServerID, p.NodeID, p.Addrs, p.JoinedAt.Format(time.RFC3339))
		if p.Revoked != "" {
			fmt.Fprintf(stdout, "state  revoked (%s)\n", p.Revoked)
			return 1
		}
		// When a belai process owns the link, report what it published;
		// opening a second link would only displace it.
		st := factorylink.SharedStatus(p)
		if st.OwnerPID > 0 {
			fmt.Fprintf(stdout, "owner  belai pid %d\n", st.OwnerPID)
		} else {
			st.Status = probe(ctx, p, advert)
		}
		fmt.Fprintf(stdout, "state  %s", st.State)
		if st.LastError != "" && st.State != factorylink.StateOnline {
			fmt.Fprintf(stdout, " (%s)", st.LastError)
		}
		fmt.Fprintln(stdout)
		if st.State != factorylink.StateOnline {
			return 1
		}
		return 0
	case "serve":
		p, err := factorylink.Active(home)
		if err != nil {
			fmt.Fprintln(stderr, "connect serve:", err)
			return 1
		}
		ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		n := factorylink.NewNode(p, advert, nil)
		n.Start(ctx)
		last := ""
		for {
			select {
			case <-ctx.Done():
				n.Stop(3 * time.Second)
				return 0
			case <-n.Changed():
				st := n.Status()
				line := fmt.Sprintf("keleustes %q: %s %s", p.ServerName, st.State, st.LastError)
				if !st.Owner && st.OwnerPID > 0 {
					line = fmt.Sprintf("keleustes %q: link held by belai pid %d; taking over when it exits", p.ServerName, st.OwnerPID)
				}
				if line != last {
					last = line
					fmt.Fprintln(stderr, line)
				}
				if st.State == factorylink.StateRevoked {
					n.Stop(3 * time.Second)
					return 1
				}
			}
		}
	case "nodes", "dispatch", "prompt":
		return runFleetCLI(ctx, home, cmd, args[1:], stdout, stderr)
	case "leave":
		p, err := factorylink.Active(home)
		if errors.Is(err, factorylink.ErrNoProfile) {
			fmt.Fprintln(stdout, "not connected to a Keleustes server")
			return 0
		}
		if err != nil {
			fmt.Fprintln(stderr, "connect leave:", err)
			return 1
		}
		if err := factorylink.Remove(home, p); err != nil {
			fmt.Fprintln(stderr, "connect leave:", err)
			return 1
		}
		fmt.Fprintf(stdout, "left %q; revoke node %s in Keleustes Fleet to remove it there\n", p.ServerName, p.NodeID)
		return 0
	default:
		tok, err := factorylink.ParseToken(cmd, time.Now())
		if err != nil {
			fmt.Fprintln(stderr, "connect:", err)
			return 2
		}
		if p, err := factorylink.Active(home); err == nil && p.Revoked == "" && p.ServerID != tok.ServerID {
			fmt.Fprintf(stderr, "connect: this host is already a node of %q; run belai connect leave first\n", p.ServerName)
			return 1
		}
		jctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		p, err := factorylink.Join(jctx, home, tok, advert(jctx))
		if err != nil {
			fmt.Fprintln(stderr, "connect:", err)
			return 1
		}
		fmt.Fprintf(stdout, "joined Keleustes %q as node %s\n", p.ServerName, p.NodeID)
		fmt.Fprintln(stdout, "the link opens whenever belai runs here; for a host with no TUI, run: belai connect serve")
		return 0
	}
}

// probe opens the link once and reports the state it reached.
func probe(ctx context.Context, p *factorylink.Profile, advert func(context.Context) *nodev1.HostAdvert) factorylink.Status {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	l := factorylink.NewLink(p, advert, nil)
	l.Start(ctx)
	defer l.Stop(2 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return l.Status()
		case <-l.Changed():
			st := l.Status()
			switch st.State {
			case factorylink.StateOnline, factorylink.StateRevoked, factorylink.StateOffline:
				return st
			}
		}
	}
}
