// Package harnessdetect finds the third-party agent harnesses this host can
// run (docs/harness-sessions.md). A harness counts as installed only when
// its binary is on PATH and answers a version probe: a registry detect
// directory alone (often just a skills folder belai's own installer made)
// reads as "configured", never as installed.
//
// Every probe runs the resolved absolute binary with no shell, a scrubbed
// environment, a 3 s timeout and 4 KiB of output; the version line is
// harness text and is sanitized to one short line. Nothing here reads a
// secret: the login state comes from agentscan's existing discovery, reduced
// to a boolean.
package harnessdetect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vulnetix/belai/internal/agentscan"
	"github.com/vulnetix/belai/internal/harness"
	"github.com/vulnetix/belai/internal/proc"
	"github.com/vulnetix/belai/internal/sanitize"
)

// States a detected harness can be in.
const (
	// StateLaunch: a verified PTY profile and a binary that answered.
	StateLaunch = "launch"
	// StateBroken: the binary is there but the probe failed.
	StateBroken = "broken"
	// StateUnverified: the binary answered, but the profile's facts are not
	// verified; it is listed and never started.
	StateUnverified = "unverified"
	// StateGUI: a desktop app; it can be opened, not typed into.
	StateGUI = "gui"
	// StateConfigured: a config directory only.
	StateConfigured = "configured"
)

// Probe limits.
const (
	ProbeTimeout = 3 * time.Second
	ProbeOutput  = 4 << 10
	// HelpOutput caps the help text an install check reads.
	HelpOutput = 64 << 10
	VersionMax = 64
	DetailMax  = 200
)

// Harness is one detected harness, as the node advertises it.
type Harness struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	State   string `json:"state"`
	Detail  string `json:"detail,omitempty"`
	// Path is the resolved absolute binary; launches exec it, not a lookup.
	Path string `json:"path,omitempty"`
	// VersionHash is the sha256 of the probe's output (provenance).
	VersionHash string   `json:"versionHash,omitempty"`
	ProbedAt    int64    `json:"probedAt,omitempty"`
	Conf        string   `json:"conf,omitempty"`
	Resume      bool     `json:"resume,omitempty"`
	A2A         bool     `json:"a2a,omitempty"`
	LoggedIn    bool     `json:"loggedIn,omitempty"`
	Modes       []string `json:"modes,omitempty"`
	AllowKeys   []string `json:"allowKeys,omitempty"`
	// Transcript is the native dialect; "" means the screen is the only view.
	Transcript string `json:"transcript,omitempty"`
	// Capability flags and caveats of the profile.
	Kill       bool             `json:"kill,omitempty"`
	Asks       bool             `json:"asks,omitempty"`
	Named      bool             `json:"named,omitempty"`
	Continuity []string         `json:"continuity,omitempty"`
	Caveats    []harness.Caveat `json:"caveats,omitempty"`
	// Startup overhead measured on this node (spawn to first output) over the
	// last sessions; zero until one ran.
	StartupP50MS int64 `json:"startupP50Ms,omitempty"`
	StartupP95MS int64 `json:"startupP95Ms,omitempty"`
	Samples      int   `json:"samples,omitempty"`
	MeasuredAt   int64 `json:"measuredAt,omitempty"`
	// Launch is the profile as checked on this host (a vendor-docs profile
	// after its install check), set when State is StateLaunch. A launch runs
	// this one, never the registry's unchecked copy.
	Launch *harness.Launch `json:"-"`
}

// Launchable reports whether the harness may be started.
func (h Harness) Launchable() bool { return h.State == StateLaunch }

// Runner runs one probe: the absolute binary and its argv, with env.
type Runner func(ctx context.Context, bin string, args, env []string) ([]byte, error)

// Options configures Detect.
type Options struct {
	Home string
	// Path is the daemon's PATH; LoginPath, when set, the user's login-shell
	// PATH (merged after it).
	Path      string
	LoginPath string
	// Registry defaults to harness.All().
	Registry []harness.Harness
	// Run defaults to running the binary for real.
	Run Runner
	// LoggedIn defaults to agentscan discovery.
	LoggedIn func(home, id string) bool
	// TimingFile is the node's harness timing samples (harnessrun.AppendTiming).
	TimingFile string
	Now        func() time.Time
}

// Detect lists every registry harness that has a binary, an app or a config
// directory on this host, launchable ones first, then by name.
func Detect(ctx context.Context, o Options) []Harness {
	if o.Registry == nil {
		o.Registry = harness.All()
	}
	if o.Run == nil {
		o.Run = run
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.LoggedIn == nil {
		o.LoggedIn = loggedIn()
	}
	dirs := pathDirs(o.Path, o.LoginPath)
	var out []Harness
	for _, h := range o.Registry {
		if d, ok := detectOne(ctx, o, dirs, h); ok {
			out = append(out, d)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := rank(out[i].State), rank(out[j].State)
		if ri != rj {
			return ri < rj
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func rank(state string) int {
	return slices.Index([]string{StateLaunch, StateUnverified, StateBroken, StateGUI, StateConfigured}, state)
}

func detectOne(ctx context.Context, o Options, dirs []string, h harness.Harness) (Harness, bool) {
	d := Harness{ID: h.ID, Name: h.Name}
	l := h.Launch
	if l != nil {
		d.Conf = l.Conf
		if bin := lookPath(dirs, l.Bins); bin != "" && l.Tier == harness.TierPTY {
			d.Path = bin
			d.ProbedAt = o.Now().UnixMilli()
			ver, sum, err := probe(ctx, o.Run, bin, l.VersionArgs, o.Home)
			d.VersionHash = sum
			unverified := "launch profile not verified"
			if err == nil && l.NeedsInstallCheck() {
				// Vendor-docs facts become launchable only once the installed
				// binary's own help names every flag the profile passes.
				if c, cerr := checkInstall(ctx, o, bin, l); cerr == nil {
					l = c
				} else {
					unverified = sanitize.Line("install check: "+cerr.Error(), DetailMax)
				}
			}
			var verErr error
			if err == nil {
				verErr = l.VersionOK(ver)
			}
			switch {
			case err != nil:
				d.State, d.Detail = StateBroken, sanitize.Line("version probe failed: "+err.Error(), DetailMax)
			case !l.Launchable():
				d.Caveats = l.Caveats
				d.Version, d.State, d.Detail = ver, StateUnverified, unverified
			case verErr != nil:
				d.Version, d.State, d.Detail = ver, StateBroken, sanitize.Line(verErr.Error(), DetailMax)
			default:
				d.Version, d.State, d.Launch = ver, StateLaunch, l
				d.Caveats = l.Caveats
				// Resume is offered only where it can be checked to continue the
				// recorded session.
				d.Resume = len(l.ResumeArgv) > 0 && len(l.Continuity) > 0
				caps := l.Caps(runtime.GOOS != "windows")
				d.Kill, d.Asks, d.Named, d.Continuity = caps.Kill, caps.Asks, caps.Name, caps.Continuity
				d.StartupP50MS, d.StartupP95MS, d.Samples, d.MeasuredAt = startup(o.TimingFile, h.ID)
				d.A2A = l.MCP != nil
				d.Modes = l.ModeNames()
				d.AllowKeys = slices.Clone(l.Keys.Allow)
				if l.Transcript != nil {
					d.Transcript = l.Transcript.Dialect
				}
				d.LoggedIn = o.LoggedIn(o.Home, h.ID)
			}
			return d, true
		}
		if bin := lookPath(dirs, l.AppBins); bin != "" {
			d.Path, d.State = bin, StateGUI
			if len(l.Open) == 0 {
				d.Detail = "app found; open it by hand"
			}
			return d, true
		}
	}
	if h.Installed(o.Home) {
		d.State, d.Detail = StateConfigured, "config directory only; no binary on PATH"
		return d, true
	}
	return d, false
}

// pathDirs merges PATH lists, keeping the first of each absolute directory.
func pathDirs(lists ...string) []string {
	var out []string
	for _, l := range lists {
		for _, d := range filepath.SplitList(l) {
			if d == "" || !filepath.IsAbs(d) || slices.Contains(out, d) {
				continue
			}
			out = append(out, filepath.Clean(d))
		}
	}
	return out
}

// lookPath finds the first name in dirs that is a regular executable file.
func lookPath(dirs, names []string) string {
	for _, n := range names {
		if n == "" || strings.ContainsAny(n, `/\`) {
			continue
		}
		for _, d := range dirs {
			p := filepath.Join(d, n)
			fi, err := os.Stat(p)
			if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
				continue
			}
			return p
		}
	}
	return ""
}

func probe(ctx context.Context, r Runner, bin string, args []string, home string) (string, string, error) {
	if len(args) == 0 {
		args = []string{"--version"}
	}
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	env := append(proc.ScrubbedEnv(), "HOME="+home, "NO_COLOR=1", "TERM=dumb")
	out, err := r(ctx, bin, args, env)
	if len(out) > ProbeOutput {
		out = out[:ProbeOutput]
	}
	sum := sha256.Sum256(out)
	if err != nil {
		return "", hex.EncodeToString(sum[:]), err
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	ver := sanitize.Line(line, VersionMax)
	if ver == "" {
		return "", hex.EncodeToString(sum[:]), errors.New("no version output")
	}
	return ver, hex.EncodeToString(sum[:]), nil
}

// checkInstall runs the profile's help argv on the installed binary (the
// probe's scrubbed environment and timeout) and checks its flags.
func checkInstall(ctx context.Context, o Options, bin string, l *harness.Launch) (*harness.Launch, error) {
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	env := append(proc.ScrubbedEnv(), "HOME="+o.Home, "NO_COLOR=1", "TERM=dumb")
	out, err := o.Run(ctx, bin, l.HelpArgv(), env)
	if err != nil {
		return nil, fmt.Errorf("help failed: %w", err)
	}
	return l.CheckInstall(string(out))
}

type capped struct {
	bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.Len(); room > 0 {
		c.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func run(ctx context.Context, bin string, args, env []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	cmd.Stdin = nil
	out := &capped{max: HelpOutput}
	cmd.Stdout, cmd.Stderr = out, io.Discard
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		return out.Bytes(), errors.New("timed out")
	}
	return out.Bytes(), err
}

// scanAgent maps a registry id to agentscan's agent name.
var scanAgent = map[string]string{"claude-code": "claude", "codex": "codex", "pi": "pi", "goose": "goose",
	"opencode": "opencode", "github-copilot": "copilot", "kiro-cli": "kiro"}

// oauthFiles are login files that hold no provider key agentscan would
// import, but whose presence means the harness's own login is done.
var oauthFiles = map[string]string{"claude-code": "~/.claude/.credentials.json", "codex": "~/.codex/auth.json"}

func loggedIn() func(home, id string) bool {
	var once sync.Once
	var found []agentscan.Found
	return func(home, id string) bool {
		if f, ok := oauthFiles[id]; ok {
			if fi, err := os.Lstat(harness.ExpandHarness(home, f, os.Getenv)); err == nil && fi.Mode().IsRegular() {
				return true
			}
		}
		name, ok := scanAgent[id]
		if !ok {
			return false
		}
		once.Do(func() { found = agentscan.Scan(home) })
		for _, f := range found {
			if f.Agent == name && f.Importable() {
				return true
			}
		}
		return false
	}
}

// LoginPath reads the PATH of the user's login shell ($SHELL -lc), bounded by
// ProbeTimeout. A GUI-started daemon often lacks ~/.local/bin and nvm or brew
// paths. "" when it cannot be read.
func LoginPath(ctx context.Context) string {
	sh := os.Getenv("SHELL")
	if sh == "" || !filepath.IsAbs(sh) {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, sh, "-lc", `printf %s "$PATH"`)
	cmd.Env = proc.ScrubbedEnv()
	out := &capped{max: ProbeOutput}
	cmd.Stdout, cmd.Stderr = out, io.Discard
	cmd.WaitDelay = time.Second
	if cmd.Run() != nil {
		return ""
	}
	return strings.TrimSpace(out.String())
}

// Equal reports whether two detections advertise the same thing (ProbedAt
// and VersionHash aside), so the daemon re-adverts only on a change.
func Equal(a, b []Harness) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		x.ProbedAt, y.ProbedAt = 0, 0
		if x.ID != y.ID || x.State != y.State || x.Version != y.Version || x.Path != y.Path || x.LoggedIn != y.LoggedIn {
			return false
		}
	}
	return true
}

// Watch runs Detect now, on every tick of every, and whenever kick receives,
// and calls changed with each result that differs from the last one (the
// first result always). The login-shell PATH is read once.
func Watch(ctx context.Context, o Options, every time.Duration, kick <-chan struct{}, changed func([]Harness)) {
	if o.LoginPath == "" {
		o.LoginPath = LoginPath(ctx)
	}
	var last []Harness
	first := true
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		cur := Detect(ctx, o)
		if first || !Equal(last, cur) {
			changed(cur)
			last, first = cur, false
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-kick:
		}
	}
}

// Catalog is the daemon's latest detection, read by the advert and by the
// start check (a dispatch may name only a harness advertised as launch).
type Catalog struct {
	mu   sync.Mutex
	list []Harness
}

// Default is the process's catalog.
var Default = &Catalog{}

// Set replaces the detection.
func (c *Catalog) Set(h []Harness) {
	c.mu.Lock()
	c.list = slices.Clone(h)
	c.mu.Unlock()
}

// All is the latest detection.
func (c *Catalog) All() []Harness {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.list)
}

// Get finds one harness by id.
func (c *Catalog) Get(id string) (Harness, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, h := range c.list {
		if h.ID == id {
			return h, true
		}
	}
	return Harness{}, false
}

// maxSamples is how many recent sessions the startup figures cover.
const maxSamples = 50

// startup reads the node's timing file and returns the p50 and p95 of the
// harness's last startups, how many, and when the latest was measured.
func startup(path, id string) (p50, p95 int64, n int, at int64) {
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var ms []int64
	for _, line := range bytes.Split(data, []byte("\n")) {
		var s struct {
			Harness   string `json:"harness"`
			StartupMS int64  `json:"startupMs"`
			At        int64  `json:"at"`
		}
		if json.Unmarshal(line, &s) != nil || s.Harness != id || s.StartupMS <= 0 {
			continue
		}
		ms = append(ms, s.StartupMS)
		at = max(at, s.At)
	}
	if len(ms) > maxSamples {
		ms = ms[len(ms)-maxSamples:]
	}
	if len(ms) == 0 {
		return 0, 0, 0, 0
	}
	slices.Sort(ms)
	pick := func(q float64) int64 { return ms[min(len(ms)-1, int(q*float64(len(ms))))] }
	return pick(0.5), pick(0.95), len(ms), at
}
