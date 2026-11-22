package factorylink

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sessionsync"
	"github.com/vulnetix/belai/internal/version"
)

// HostOptions are the parts of the advert the caller knows best.
type HostOptions struct {
	// Terminal: this process has an interactive terminal (the TUI).
	Terminal bool
	// RemoteControl: a `belai rc` daemon accepts dispatches on this host.
	RemoteControl bool
	TrustedDirs   []string
	Providers     []string
	// MaxSessions is how many dispatched sessions the daemon runs at once.
	MaxSessions int
	// Agents and Crews are the agent profile and crew names installed here.
	Agents, Crews []string
	// DispatchKinds and JobKinds are what this process takes from the
	// link; CanClone says a worker dispatch may name a repository to clone.
	DispatchKinds, JobKinds []string
	CanClone                bool
	// DispatchFeatures are the optional Dispatch fields this process applies
	// (Capabilities.dispatch_features: resume, fork, answers, gates, adhoc, ...).
	DispatchFeatures []string
	// Models are the models each provider offers a dispatched session.
	Models []*nodev1.ProviderModels
	// Routes say how each worker profile claims cards.
	Routes []*nodev1.AgentRoute
	// Harnesses are the third-party harnesses detected here, and
	// HarnessSessions whether this host runs them (harnesses.md).
	Harnesses       []*nodev1.Harness
	HarnessSessions bool
	// Inventory is the host's library: kinds, names and hashes only.
	Inventory []*nodev1.LibraryRef
}

// ghAuthenticated is swapped in tests.
var ghAuthenticated = func(ctx context.Context) bool {
	if _, err := exec.LookPath("gh"); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "gh", "auth", "status", "--hostname", "github.com")
	cmd.Stdout, cmd.Stderr = nil, nil
	return cmd.Run() == nil
}

// HostAdvert describes this host to Keleustes.
func HostAdvert(ctx context.Context, home string, o HostOptions) *nodev1.HostAdvert {
	hostname, _ := os.Hostname()
	hostID, _ := sessionsync.HostID(home)
	gh := ghAuthenticated(ctx)
	// Every gh, glab and tea login (forgelogins.go); cached for a minute.
	forges := cachedForgeLogins(ctx)
	return &nodev1.HostAdvert{
		Hostname:     hostname,
		Os:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		BelaiVersion: version.Version,
		HostId:       hostID,
		Capabilities: &nodev1.Capabilities{
			GhAuthenticated:  gh,
			Forges:           forges,
			Terminal:         o.Terminal,
			RemoteControl:    o.RemoteControl,
			Providers:        o.Providers,
			MaxSessions:      uint32(max(o.MaxSessions, 0)),
			DispatchKinds:    o.DispatchKinds,
			JobKinds:         o.JobKinds,
			DispatchFeatures: o.DispatchFeatures,
			CanClone:         o.CanClone,
			Models:           o.Models,
			HarnessSessions:  o.HarnessSessions,
		},
		AgentRoutes: o.Routes,
		Harnesses:   o.Harnesses,
		Inventory:   o.Inventory,
		TrustedDirs: o.TrustedDirs,
		Agents:      o.Agents,
		Crews:       o.Crews,
	}
}

// ghAuthTTL is how long GHAuthenticated reuses an answer.
const ghAuthTTL = time.Minute

var ghAuth struct {
	sync.Mutex
	ok bool
	at time.Time
}

// GHAuthenticated reports whether `gh` is installed and signed in to
// github.com, the same check the host advert makes, reused for a minute.
func GHAuthenticated(ctx context.Context) bool {
	ghAuth.Lock()
	defer ghAuth.Unlock()
	if !ghAuth.at.IsZero() && time.Since(ghAuth.at) < ghAuthTTL {
		return ghAuth.ok
	}
	ghAuth.ok, ghAuth.at = ghAuthenticated(ctx), time.Now()
	return ghAuth.ok
}
