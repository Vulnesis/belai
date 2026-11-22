package rc

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/forge"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// Keleustes host management (internal/hostmgmt, wired in cmd/belai) runs
// beside the factory link. The daemon lends it the parts only it knows: its
// offered directories, its caps and counts, its project_prefs and clone
// paths (so a host action takes the same checks a website request does), and
// the drain and re-exec a restart needs.

// HostManager runs host management until ctx ends.
type HostManager func(ctx context.Context, h HostHooks)

// HostLimits are the daemon's caps and live counts.
type HostLimits struct {
	MaxSessions, MaxWorkers, ReservedWorkers, MaxJobs, IdleS int
	Sessions, Workers, Jobs                                  int
}

// HostHooks are the daemon's paths a host action reuses.
type HostHooks struct {
	Dirs            func() []string
	Limits          func() HostLimits
	SetProjectPrefs func(dir string, set map[string]any, unset []string) (string, string)
	Clone           func(ctx context.Context, forgeHost, owner, name, parent, dir string, depth int) (string, string)
	Drain           func(ctx context.Context, forceAfter time.Duration) bool
	Undrain         func()
	Reexec          func() error
}

// restartingReason is the refusal while the daemon drains for a restart.
const restartingReason = "restarting: this host takes no new work until belai rc is back"

func (d *Daemon) hostHooks() HostHooks {
	return HostHooks{
		Dirs: func() []string {
			var out []string
			for _, dir := range d.dirs() {
				out = append(out, dir.Path)
			}
			return out
		},
		Limits: d.hostLimits,
		SetProjectPrefs: func(dir string, set map[string]any, unset []string) (string, string) {
			return d.setProjectPrefs(sessionsync.Dispatch{Cwd: dir, PrefsSet: set, PrefsUnset: unset})
		},
		Clone: d.hostClone,
		Drain: d.drain,
		Undrain: func() {
			d.draining.Store(false)
		},
		Reexec: reexec,
	}
}

func (d *Daemon) liveWorkers(inv Inventory) int {
	n := 0
	for _, w := range inv.Workers {
		if w.Stopped == 0 {
			n++
		}
	}
	return n
}

func (d *Daemon) hostLimits() HostLimits {
	inv := d.o.Inventory()
	return HostLimits{MaxSessions: d.o.Max, MaxWorkers: inv.MaxWorkers, ReservedWorkers: inv.ReservedWorkers,
		MaxJobs: maxFactoryJobs, IdleS: int(d.o.Idle / time.Second),
		Sessions: d.running(), Workers: d.liveWorkers(inv), Jobs: len(d.jobSlot)}
}

// hostClone clones a repository a host action names into dir under parent
// (docs/gaps/host-management.md §5.6) through rc/clone.go's engine, at depth
// (0 is the full history), trusts it for the directory and offers it.
func (d *Daemon) hostClone(ctx context.Context, forgeHost, owner, name, parent, dir string, depth int) (string, string) {
	c := &sessionsync.DispatchClone{Repo: owner + "/" + name}
	if forgeHost != "github.com" {
		s, err := config.LoadGlobal()
		if err != nil {
			return "", "the host's settings could not be read"
		}
		// forges names a host without its port.
		kind := s.Forges[strings.Split(forgeHost, ":")[0]]
		switch kind {
		case forge.HostGHES, forge.HostGitea, forge.HostForgejo, forge.HostGitLab:
		default:
			return "", "this host does not know the forge at " + forgeHost + " (forges in settings)"
		}
		c.Host, c.Forge = forgeHost, kind
		c.CloneURL = "https://" + forgeHost + "/" + strings.ToLower(owner) + "/" + strings.ToLower(name) + ".git"
	}
	return d.cloneInto(ctx, c, parent, dir, depth)
}

// drain stops the daemon taking new dispatches and waits until its sessions
// and workers end or forceAfter passes; it reports whether it gave up.
func (d *Daemon) drain(ctx context.Context, forceAfter time.Duration) bool {
	d.draining.Store(true)
	deadline := time.Now().Add(forceAfter)
	for {
		if d.running() == 0 && d.liveWorkers(d.o.Inventory()) == 0 {
			return false
		}
		if !time.Now().Before(deadline) {
			return true
		}
		select {
		case <-ctx.Done():
			return true
		case <-time.After(drainPoll):
		}
	}
}

// drainPoll is how often drain looks.
var drainPoll = time.Second

// reexec replaces this process with a fresh copy of itself (reexec_*.go).
var reexec = func() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return execSelf(exe, os.Args, os.Environ())
}

var errNoReexec = errors.New("this platform cannot re-exec")

// builtinDisabledForRepo is the per-repository switch (agents.builtin.<profile>
// off in the host's preferences for the directory).
func builtinDisabledForRepo(cwd, profile string) bool {
	return config.BuiltinAgentOff(cwd, profile)
}
