// Package hostmgmt is the belai side of Keleustes host management
// (keleustes docs/gaps/host-management.md). A `belai rc` daemon that serves a
// Keleustes server reports what is installed and configured on this host
// (Host.Report: HostInventory) and runs the host actions the console sends on
// the Host.Actions stream, reporting each one with Host.Progress.
//
// The rules:
//
//   - The host gate is final. --keleustes-manage (off, read, config,
//     provision) and --keleustes-shell come from the rc command line, are
//     recorded in rc.json, and no setting or action changes them. Keleustes's
//     own policy only adds to them.
//   - Kinds are a closed table (actions.go). Each kind has the class this
//     host derives for it; an action whose class Keleustes stated differently
//     is refused, as is an unknown kind, an unknown parameter or a value that
//     fails its typed validator. No parameter reaches a model or a shell.
//   - The factory kill switch (factorylink.FactoryStopped) refuses every
//     config, provision and shell action, and every read a person did not ask
//     for (decision O3). The A2A blackout refuses the config writes that
//     touch a2a.* and sync.remote_*.
//   - Every refusal is a HostActionUpdate with state refused and a reason the
//     harness wrote, and every state change is a host.action.* audit event
//     carrying the action's origin.
//   - One action runs at a time. The queue in <belai home>/rc/hostactions
//     survives a restart, so an action Keleustes replays after a reconnect is
//     never run twice. A vault grant is never written there.
//   - What leaves the host is facts: inventory strings are capped and paths
//     home-relative, lines are harness text or vaultenv-scrubbed output, and
//     no update or inventory carries a secret value.
package hostmgmt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/vulnetix/belai/internal/a2a"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/products"
	"github.com/vulnetix/belai/internal/version"
)

// Level is the host gate, --keleustes-manage.
type Level int

// The levels, lowest first.
const (
	LevelOff Level = iota
	LevelRead
	LevelConfig
	LevelProvision
)

// DefaultLevel is the gate when the flag is not given.
const DefaultLevel = LevelRead

// ParseLevel reads a --keleustes-manage value.
func ParseLevel(s string) (Level, error) {
	switch s {
	case "off":
		return LevelOff, nil
	case "read", "":
		return LevelRead, nil
	case "config":
		return LevelConfig, nil
	case "provision":
		return LevelProvision, nil
	}
	return LevelOff, fmt.Errorf("--keleustes-manage takes off, read, config or provision, not %q", s)
}

func (l Level) String() string {
	switch l {
	case LevelRead:
		return "read"
	case LevelConfig:
		return "config"
	case LevelProvision:
		return "provision"
	}
	return "off"
}

// Gates are the daemon's rc flags, reported and obeyed, never changed.
type Gates struct {
	WebControls, WebShell, WebProjectSettings, AllowGuardrailsOff, NoClone, AllowPrivateCIDR bool
}

// Limits are the daemon's caps and live counts.
type Limits struct {
	MaxSessions, MaxWorkers, ReservedWorkers, MaxJobs, IdleS int
	Sessions, Workers, Jobs                                  int
}

// Hooks are what the rc daemon lends: the parts of the host only it knows,
// and the paths into rc that host actions reuse rather than copy.
type Hooks struct {
	// Dirs are the directories the daemon offers (absolute, resolved).
	Dirs func() []string
	// Limits are the daemon's caps and counts.
	Limits func() Limits
	// Preflight runs rc.Preflight.
	Preflight func(ctx context.Context) []*nodev1.Check
	// SetProjectPrefs is rc's project_prefs path (rc/prefs.go): it needs
	// --web-project-settings and an offered directory. It returns the report,
	// or the refusal reason.
	SetProjectPrefs func(dir string, set map[string]any, unset []string) (string, string)
	// Clone is rc/clone.go for a repo_clone action. It returns the checkout,
	// or the refusal reason.
	Clone func(ctx context.Context, r CloneRequest) (string, string)
	// Drain stops the daemon taking new work and waits until its sessions and
	// workers end or forceAfter passes. It reports whether it gave up waiting.
	Drain func(ctx context.Context, forceAfter time.Duration) (forced bool)
	// Reexec replaces the daemon with a fresh copy of itself. It returns only
	// on failure.
	Reexec func() error
	// Undrain lets the daemon take work again after a failed restart.
	Undrain func()
}

// CloneRequest is one repo_clone: the repository, the directory it goes in
// (Dir under Parent) and the history depth (0 is all of it).
type CloneRequest struct {
	ForgeHost, Owner, Name string
	Parent, Dir            string
	Depth                  int
}

// Transport is the Host service.
type Transport interface {
	Report(ctx context.Context, in *nodev1.HostInventory) error
	Actions(ctx context.Context, in *nodev1.HostActionsRequest) (nodev1.Host_ActionsClient, error)
	Progress(ctx context.Context, in *nodev1.HostActionUpdate) error
}

// NewGRPC is the Host service on a connection to Keleustes (the node
// certificate's connection; factorylink holds it).
func NewGRPC(cc grpc.ClientConnInterface) Transport {
	return grpcTransport{c: nodev1.NewHostClient(cc)}
}

type grpcTransport struct{ c nodev1.HostClient }

func (g grpcTransport) Report(ctx context.Context, in *nodev1.HostInventory) error {
	_, err := g.c.Report(ctx, in)
	return err
}

func (g grpcTransport) Actions(ctx context.Context, in *nodev1.HostActionsRequest) (nodev1.Host_ActionsClient, error) {
	return g.c.Actions(ctx, in)
}

func (g grpcTransport) Progress(ctx context.Context, in *nodev1.HostActionUpdate) error {
	_, err := g.c.Progress(ctx, in)
	return err
}

// Options configure a Manager.
type Options struct {
	// Home is the belai home (config.GlobalDir); UserHome the user's home.
	Home, UserHome string
	Level          Level
	Shell          bool
	Gates          Gates
	Hooks          Hooks
	Prober         *products.Prober
	// Exe is this belai binary; Args the rc daemon's argv after the program.
	Exe  string
	Args []string
	// Version is this belai's version (version.Version).
	Version string
	Now     func() time.Time
	Logf    func(format string, args ...any)
	// LookPath finds a recipe's program (exec.LookPath).
	LookPath func(string) (string, error)
	// HTTP downloads release assets. CLIReleases and BelaiReleases are the
	// release download bases ("https://github.com/Vulnesis/cli/releases/download").
	HTTP          *http.Client
	CLIReleases   string
	BelaiReleases string
	GOOS, GOARCH  string
	// Stopped and Blackout read the factory kill switch and the A2A blackout
	// (the host's control.json and blackout file unless a test replaces them).
	Stopped  func() (bool, string)
	Blackout func() bool
	// ReportEvery and Debounce pace Host.Report (60 s and 5 s).
	ReportEvery, Debounce time.Duration
	// Providers lists the providers and whether a key is present (the
	// credentials resolver unless a test replaces it).
	Providers func() []*nodev1.ProviderFact
}

// Manager serves Keleustes host management for one rc daemon.
type Manager struct {
	o Options
	q *queue

	mu       sync.Mutex
	pending  []*nodev1.HostAction
	wake     chan struct{}
	changed  chan struct{}
	running  string // the action id being worked on
	lastSent string // hash of the last inventory reported
	t        Transport
	pre      []*nodev1.Check
	preAt    time.Time
	det      map[string]detCache
	tools    []*nodev1.ToolFact
	toolsAt  time.Time
}

// New builds a Manager. It fills defaults and opens the queue, settling an
// action a previous run left mid-way.
func New(o Options) (*Manager, error) {
	if o.Home == "" {
		return nil, errors.New("hostmgmt: the belai home is required")
	}
	if o.UserHome == "" {
		o.UserHome, _ = os.UserHomeDir()
	}
	if o.Version == "" {
		o.Version = version.Version
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.LookPath == nil {
		o.LookPath = exec.LookPath
	}
	if o.Prober == nil {
		o.Prober = products.NewProber()
	}
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 10 * time.Minute}
	}
	if o.CLIReleases == "" {
		o.CLIReleases = loopbackOverride(os.Getenv("VULNETIX_E2E_RELEASES"), "https://github.com/Vulnesis/cli/releases/download")
	}
	if o.BelaiReleases == "" {
		o.BelaiReleases = loopbackOverride(os.Getenv("BELAI_E2E_RELEASES"), "https://github.com/Vulnesis/belai/releases/download")
	}
	if o.GOOS == "" {
		o.GOOS, o.GOARCH = runtime.GOOS, runtime.GOARCH
	}
	if o.Stopped == nil {
		home := o.Home
		o.Stopped = func() (bool, string) { return factorylink.FactoryStopped(home) }
	}
	if o.Blackout == nil {
		home := o.Home
		o.Blackout = func() bool {
			if a2a.Blackout(a2a.Dir(home)) {
				return true
			}
			p, err := factorylink.Active(home)
			return err == nil && p.Control().A2ABlackout
		}
	}
	if o.ReportEvery <= 0 {
		o.ReportEvery = 60 * time.Second
	}
	if o.Debounce <= 0 {
		o.Debounce = 5 * time.Second
	}
	if o.Providers == nil {
		o.Providers = localProviders
	}
	q, err := openQueue(filepath.Join(o.Home, "rc", "hostactions"))
	if err != nil {
		return nil, err
	}
	m := &Manager{o: o, q: q, wake: make(chan struct{}, 1), changed: make(chan struct{}, 1), det: map[string]detCache{}}
	q.prune(o.Now().Add(-30 * 24 * time.Hour))
	m.recover()
	return m, nil
}

// Level is the host gate.
func (m *Manager) Level() Level { return m.o.Level }

// Shell reports --keleustes-shell.
func (m *Manager) Shell() bool { return m.o.Shell }

// Run serves the Host service on t until ctx ends: the report loop, the
// action stream (reopened with a backoff when it drops) and the worker that
// runs one action at a time.
func (m *Manager) Run(ctx context.Context, t Transport) error {
	m.mu.Lock()
	m.t = t
	m.mu.Unlock()
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); m.reportLoop(ctx) }()
	go func() { defer wg.Done(); m.streamLoop(ctx) }()
	go func() { defer wg.Done(); m.workLoop(ctx) }()
	wg.Wait()
	return nil
}

// streamLoop keeps Host.Actions open, resending what the last stream did not
// deliver each time it opens.
func (m *Manager) streamLoop(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		opened := m.streamOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if opened {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (m *Manager) streamOnce(ctx context.Context) bool {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := m.transport().Actions(sctx, &nodev1.HostActionsRequest{BelaiVersion: m.o.Version})
	if err != nil {
		return false
	}
	m.flushUnsent(ctx)
	m.poke()
	for {
		a, err := st.Recv()
		if err != nil {
			return true
		}
		m.Receive(ctx, a)
	}
}

func (m *Manager) transport() Transport {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.t == nil {
		return nopTransport{}
	}
	return m.t
}

// nopTransport is the transport before Run: every call fails.
type nopTransport struct{}

var errNoTransport = errors.New("not connected to Keleustes")

func (nopTransport) Report(context.Context, *nodev1.HostInventory) error { return errNoTransport }
func (nopTransport) Actions(context.Context, *nodev1.HostActionsRequest) (nodev1.Host_ActionsClient, error) {
	return nil, errNoTransport
}
func (nopTransport) Progress(context.Context, *nodev1.HostActionUpdate) error { return errNoTransport }

// poke asks the report loop for a report soon (debounced).
func (m *Manager) poke() {
	select {
	case m.changed <- struct{}{}:
	default:
	}
}

// reportLoop sends the inventory when the link opens, after a change
// (debounced), and every ReportEvery. A snapshot equal to the last one sent
// is sent only by the periodic tick.
func (m *Manager) reportLoop(ctx context.Context) {
	m.report(ctx, true)
	tick := time.NewTicker(m.o.ReportEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			m.report(ctx, true)
		case <-m.changed:
			select {
			case <-ctx.Done():
				return
			case <-time.After(m.o.Debounce):
			}
			m.report(ctx, false)
		}
	}
}

// report collects the inventory and sends it. always sends even an
// unchanged snapshot.
func (m *Manager) report(ctx context.Context, always bool) error {
	inv := m.Inventory(ctx, false)
	h := inventoryHash(inv)
	m.mu.Lock()
	same := h == m.lastSent
	m.mu.Unlock()
	if same && !always {
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := m.transport().Report(rctx, inv); err != nil {
		return err
	}
	m.mu.Lock()
	m.lastSent = h
	m.mu.Unlock()
	return nil
}

// inventoryHash hashes a snapshot without its timestamps.
func inventoryHash(inv *nodev1.HostInventory) string {
	c := proto.Clone(inv).(*nodev1.HostInventory)
	c.AtMs = 0
	for _, p := range c.Products {
		p.ProbedAtMs = 0
	}
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(c)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// loopbackOverride is a release download base from the environment, kept only
// when it is an http(s) URL on a loopback address (a local fixture for the
// end-to-end suite); anything else falls back to def, so the environment can
// never point an upgrade at another server.
func loopbackOverride(raw, def string) string {
	if raw == "" {
		return def
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return def
	}
	if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
		return def
	}
	return strings.TrimRight(raw, "/")
}
