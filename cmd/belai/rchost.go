package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"google.golang.org/grpc"

	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/hostmgmt"
	"github.com/vulnetix/belai/internal/rc"
	"github.com/vulnetix/belai/internal/sanitize"
)

// Keleustes host management for `belai rc` (internal/hostmgmt). The gate,
// --keleustes-manage and --keleustes-shell, is the host's: only the command
// line sets it.

// connProvider is the node certificate's connection, when factorylink's
// Client offers it (keleustes docs/gaps/host-proto-request.md B1).
type connProvider interface {
	Conn(ctx context.Context) (*grpc.ClientConn, error)
}

// rcHostOptions are what runRCCLI knows for host management.
type rcHostOptions struct {
	home    string
	profile *factorylink.Profile
	pre     rc.PreflightOptions
	exe     string
	args    []string
	level   hostmgmt.Level
	shell   bool
	gates   hostmgmt.Gates
	log     io.Writer
}

// rcHostManager builds the daemon's HostManager, or nil when host management
// is off.
func rcHostManager(o rcHostOptions) rc.HostManager {
	if o.level == hostmgmt.LevelOff || o.profile == nil {
		return nil
	}
	logf := func(format string, args ...any) {
		fmt.Fprintf(o.log, "%s %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
	}
	return func(ctx context.Context, h rc.HostHooks) {
		client, err := factorylink.NewClient(o.profile)
		if err != nil {
			logf("keleustes host management: %v", err)
			return
		}
		defer client.Close()
		cp, ok := any(client).(connProvider)
		if !ok {
			logf("keleustes host management is waiting for a Belai build whose Keleustes client lends its connection; the host is not reported")
			return
		}
		conn, err := cp.Conn(ctx)
		if err != nil {
			logf("keleustes host management: %v", err)
			return
		}
		m, err := hostmgmt.New(hostmgmt.Options{
			Home: o.home, Level: o.level, Shell: o.shell, Gates: o.gates, Exe: o.exe, Args: o.args, Logf: logf,
			Hooks: hostmgmt.Hooks{
				Dirs: h.Dirs,
				Limits: func() hostmgmt.Limits {
					l := h.Limits()
					return hostmgmt.Limits{MaxSessions: l.MaxSessions, MaxWorkers: l.MaxWorkers, ReservedWorkers: l.ReservedWorkers,
						MaxJobs: l.MaxJobs, IdleS: l.IdleS, Sessions: l.Sessions, Workers: l.Workers, Jobs: l.Jobs}
				},
				Preflight: func(ctx context.Context) []*nodev1.Check {
					return preflightChecks(rc.Preflight(ctx, o.pre))
				},
				SetProjectPrefs: h.SetProjectPrefs,
				Clone: func(ctx context.Context, r hostmgmt.CloneRequest) (string, string) {
					return h.Clone(ctx, r.ForgeHost, r.Owner, r.Name, r.Parent, r.Dir, r.Depth)
				},
				Drain:   h.Drain,
				Undrain: h.Undrain,
				Reexec:  h.Reexec,
			},
		})
		if err != nil {
			logf("keleustes host management: %v", err)
			return
		}
		logf("keleustes host management on · gate %s · shell %v", o.level, o.shell)
		_ = m.Run(ctx, hostmgmt.NewGRPC(conn))
	}
}

// preflightChecks maps rc's preflight onto the wire's checks.
func preflightChecks(cs rc.Checks) []*nodev1.Check {
	out := make([]*nodev1.Check, 0, len(cs))
	for _, c := range cs {
		st := "ok"
		switch c.Level {
		case rc.Warn:
			st = "warn"
		case rc.Fail:
			st = "error"
		}
		out = append(out, &nodev1.Check{Id: sanitize.Line(c.Name, 64), Status: st, Hint: sanitize.Line(c.Detail, 160)})
	}
	return out
}
