package hostmgmt

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/credentials"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/forge"
	"github.com/vulnetix/belai/internal/gitinfo"
	"github.com/vulnetix/belai/internal/plugins"
	"github.com/vulnetix/belai/internal/projectregistry"
	"github.com/vulnetix/belai/internal/sandbox"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/schedule"
	"github.com/vulnetix/belai/internal/selfupdate"
	"github.com/vulnetix/belai/internal/vulnetixcli"
)

// The inventory (HM-1): facts about this host, every string capped, every
// path home-relative, and no value that is a secret: providers report
// whether a key is present, MCP servers their transport and the names of the
// variables they bind, plugins and schedules their names.

const (
	maxRepos    = 200
	maxItems    = 500
	maxStr      = 256
	toolsFor    = time.Minute
	walkEntries = 200_000
)

func cap256(s string) string { return sanitize.Line(s, maxStr) }

// Inventory collects the host's snapshot. fresh re-runs the product probes.
func (m *Manager) Inventory(ctx context.Context, fresh bool) *nodev1.HostInventory {
	s, _ := config.LoadGlobal()
	sha, _, _ := settingsSHA256()
	inv := &nodev1.HostInventory{
		AtMs:           m.o.Now().UnixMilli(),
		Belai:          m.belaiFacts(),
		Products:       m.o.Prober.All(ctx, fresh),
		Repos:          m.repos(),
		Tools:          m.toolFacts(ctx),
		Preflight:      m.preflight(ctx, false),
		Limits:         m.limits(),
		Gates:          m.gates(),
		Disk:           m.disk(),
		SettingsSha256: sha,
		Plugins:        pluginNames(),
		Mcp:            mcpFacts(s),
		Providers:      m.o.Providers(),
		Sandbox:        sandboxFact(s),
		Manage:         &nodev1.HostManage{HostActions: m.advertised(), ManageLevel: m.o.Level.String(), ManageShell: m.o.Shell},
		Schedules:      m.schedules(),
		BuiltinAgents:  builtinAgents(),
		AgentsEnabled:  s.AgentsEnabled(),
		Worktrees:      m.worktrees(ctx),
	}
	return inv
}

// advertised is HostManage.host_actions: every kind this build runs, so
// Keleustes can show a gated one as locked. shell_exec is listed only with
// --keleustes-shell.
func (m *Manager) advertised() []string {
	var out []string
	for _, k := range Kinds() {
		if k == "shell_exec" && !m.o.Shell {
			continue
		}
		out = append(out, k)
	}
	return out
}

// offlineTransport refuses every request: the inventory reads the update
// check's cache and never the network.
type offlineTransport struct{}

func (offlineTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("offline")
}

func (m *Manager) belaiFacts() *nodev1.BelaiFacts {
	f := &nodev1.BelaiFacts{Version: cap256(m.o.Version), Root: homeRel(m.o.UserHome, m.o.Home)}
	if m.o.Exe != "" {
		if meth, _ := vulnetixcli.DetectInstall(m.o.Exe, nil); meth != "" && meth != vulnetixcli.InstallUnknown {
			f.InstallMethod = string(meth)
		}
		st := selfupdate.Check(context.Background(), selfupdate.Options{Client: &http.Client{Transport: offlineTransport{}}, ExecPath: m.o.Exe})
		if st.Checked {
			f.Latest, f.UpdateAvailable = cap256(st.Latest.String()), st.Available
		}
	}
	return f
}

func (m *Manager) limits() *nodev1.HostLimits {
	if m.o.Hooks.Limits == nil {
		return &nodev1.HostLimits{}
	}
	l := m.o.Hooks.Limits()
	u := func(n int) uint32 { return uint32(max(n, 0)) }
	return &nodev1.HostLimits{MaxSessions: u(l.MaxSessions), MaxWorkers: u(l.MaxWorkers), ReservedWorkers: u(l.ReservedWorkers),
		MaxJobs: u(l.MaxJobs), IdleS: u(l.IdleS), Sessions: u(l.Sessions), Workers: u(l.Workers), Jobs: u(l.Jobs)}
}

func (m *Manager) gates() *nodev1.RcGates {
	g := m.o.Gates
	return &nodev1.RcGates{WebControls: g.WebControls, WebShell: g.WebShell, WebProjectSettings: g.WebProjectSettings,
		AllowGuardrailsOff: g.AllowGuardrailsOff, NoClone: g.NoClone, AllowPrivateCidr: g.AllowPrivateCIDR}
}

// repos lists the offered directories and the trusted projects.
func (m *Manager) repos() []*nodev1.HostRepo {
	reg, _ := projectregistry.Load()
	entries := map[string]projectregistry.Entry{}
	for _, e := range reg.All() {
		entries[e.Path] = e
	}
	seen := map[string]bool{}
	var dirs []string
	add := func(d string) {
		if !seen[d] && len(dirs) < maxRepos {
			seen[d] = true
			dirs = append(dirs, d)
		}
	}
	for _, d := range m.offeredDirs() {
		add(d)
	}
	for _, e := range reg.All() {
		if e.Trusted && !e.Missing {
			add(e.Path)
		}
	}
	builtins := builtinAgents()
	var out []*nodev1.HostRepo
	for _, d := range dirs {
		e, registered := entries[d]
		r := &nodev1.HostRepo{Path: homeRel(m.o.UserHome, d), Trusted: e.Trusted, Registered: registered}
		if !e.LastSeen.IsZero() {
			r.LastUsedMs = e.LastSeen.UnixMilli()
		}
		if info, ok := gitinfo.Detect(d); ok {
			r.Branch = sanitize.Ident(info.Branch, 200)
			r.Git = &nodev1.GitFacts{Commit: sanitize.Ident(info.Head, 64), Detached: info.Detached}
			if rem, ok := forge.ParseRemote(gitinfo.OriginURL(d)); ok {
				r.Remote, r.ForgeHost = cap256(rem.URL), sanitize.Ident(rem.Host, 253)
				r.Owner, r.Name = sanitize.Ident(rem.Owner, 200), sanitize.Ident(rem.Repo, 100)
			}
			det := m.detections(info.Root, info.Head)
			r.Detections = &nodev1.RepoDetections{Build: det.build, Lint: det.lint, Test: det.test, Languages: det.langs}
		} else {
			r.Detections = &nodev1.RepoDetections{}
		}
		prefs, err := config.LoadProjectPrefs(d)
		if err == nil {
			r.Prefs = map[string]string{}
			for k, v := range prefs.Flat() {
				r.Prefs[k] = cap256(prefString(v))
			}
			for _, b := range builtins {
				if st := prefs.BuiltinAgentState(b); st != "inherit" {
					r.Agents = append(r.Agents, &nodev1.Toggle{Id: b, On: st == "on", State: st})
				}
			}
			if s, err := config.Resolve(d, os.Getenv, config.Settings{}); err == nil && s.Settings.Vulnetix != nil {
				r.Detections.Scans = append(r.Detections.Scans, s.Settings.Vulnetix.Subcommands...)
			}
			if pr := prefs.Repo; pr != nil {
				for sub, on := range pr.Scans {
					if on && !has(r.Detections.Scans, sub) {
						r.Detections.Scans = append(r.Detections.Scans, sub)
					}
				}
				if pr.DepWatch != nil {
					r.Detections.DepWatch = *pr.DepWatch
				}
			}
			sort.Strings(r.Detections.Scans)
		}
		r.Detections.InSweep = !config.SweepOff(d)
		out = append(out, r)
	}
	return out
}

var toolNames = []string{"gh", "git", "bwrap", "rg", "llama-server", "docker"}

// toolFacts reports the external tools, re-read once a minute.
func (m *Manager) toolFacts(ctx context.Context) []*nodev1.ToolFact {
	m.mu.Lock()
	if m.tools != nil && m.o.Now().Sub(m.toolsAt) < toolsFor {
		out := m.tools
		m.mu.Unlock()
		return out
	}
	m.mu.Unlock()
	var out []*nodev1.ToolFact
	for _, name := range toolNames {
		f := &nodev1.ToolFact{Name: name}
		path, err := m.o.LookPath(name)
		if err == nil && path != "" {
			f.Ok = true
			if o, err := m.o.Prober.Run(ctx, path, "--version"); err == nil && o.Exit == 0 {
				f.Version = toolVersion(string(o.Stdout))
			}
			if name == "gh" {
				if factorylink.GHAuthenticated(ctx) {
					f.Note = "auth"
				} else {
					f.Note = "no auth"
				}
			}
		}
		out = append(out, f)
	}
	m.mu.Lock()
	m.tools, m.toolsAt = out, m.o.Now()
	m.mu.Unlock()
	return out
}

// toolVersion picks the first version-shaped word of a --version line.
func toolVersion(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	for _, w := range strings.Fields(line) {
		w = strings.TrimSuffix(strings.TrimPrefix(w, "v"), ",")
		if versionRE.MatchString(w) || versionRE.MatchString(w+".0") {
			return w
		}
	}
	return ""
}

// dirSize sums file sizes under dir, looking at most at walkEntries entries.
func dirSize(dir string) int64 {
	var n int64
	seen := 0
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if seen++; seen > walkEntries {
			return filepath.SkipAll
		}
		if d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}

func (m *Manager) disk() *nodev1.DiskUsage {
	d := &nodev1.DiskUsage{}
	if root := sessionsRoot(); root != "" {
		d.Sessions = dirSize(root)
	}
	if wt, err := config.WorktreesDir(); err == nil {
		d.Worktrees = dirSize(wt)
	}
	d.Logs = dirSize(filepath.Join(m.o.Home, "rc"))
	if agents, err := config.AgentsDir(); err == nil {
		d.Logs += dirSize(filepath.Join(agents, "logs"))
	}
	d.Free = freeBytes(m.o.Home)
	return d
}

func pluginNames() []string {
	recs, err := plugins.List()
	if err != nil {
		return nil
	}
	var out []string
	for _, r := range recs {
		if plugins.ValidName(r.Name) && len(out) < maxItems {
			out = append(out, r.Name)
		}
	}
	return out
}

// mcpFacts names the MCP servers, their transport and the variable names
// they bind; never a value, a command or an argument.
func mcpFacts(s config.Settings) []*nodev1.McpServerFact {
	out := []*nodev1.McpServerFact{{Name: "clef", Transport: "builtin", Builtin: true}}
	if s.MCP == nil {
		return out
	}
	names := make([]string, 0, len(s.MCP.Servers))
	for n := range s.MCP.Servers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		srv := s.MCP.Servers[n]
		f := &nodev1.McpServerFact{Name: sanitize.Ident(n, 64), Transport: sanitize.Ident(srv.Transport, 16)}
		if f.Transport == "" {
			if srv.URL != "" {
				f.Transport = "http"
			} else {
				f.Transport = "stdio"
			}
		}
		for k := range srv.Env {
			f.KeysBound = append(f.KeysBound, sanitize.Ident(k, 64))
		}
		for k := range srv.Secrets {
			f.KeysBound = append(f.KeysBound, sanitize.Ident(k, 64))
		}
		sort.Strings(f.KeysBound)
		out = append(out, f)
		if len(out) >= maxItems {
			break
		}
	}
	return out
}

// localProviders lists the providers this host could use and whether a key
// resolves for each; never the key.
func localProviders() []*nodev1.ProviderFact {
	r, err := credentials.NewGlobalResolver()
	if err != nil {
		return nil
	}
	var out []*nodev1.ProviderFact
	for _, p := range r.ConfiguredProviders() {
		out = append(out, &nodev1.ProviderFact{Provider: sanitize.Ident(p, 64), KeyPresent: true})
	}
	return out
}

func sandboxFact(s config.Settings) *nodev1.SandboxFact {
	name, _ := sandbox.Backend()
	return &nodev1.SandboxFact{Mode: s.Sandbox.ModeOr(), Network: s.Sandbox.NetworkOr(), Backend: sanitize.Ident(name, 32)}
}

func (m *Manager) schedules() []*nodev1.HostSchedule {
	st, err := schedule.Open()
	if err != nil {
		return nil
	}
	recs, err := st.Live()
	if err != nil {
		return nil
	}
	var out []*nodev1.HostSchedule
	for _, r := range recs {
		out = append(out, &nodev1.HostSchedule{Id: sanitize.Ident(r.ID, 64), Target: sanitize.Ident(r.Profile, 128),
			Cron: cap256(r.Cron), Dir: homeRel(m.o.UserHome, r.Dir), Enabled: r.Enabled, LastRunMs: r.LastRunAt,
			LastStatus: sanitize.Ident(r.LastStatus, 32)})
		if len(out) >= maxItems {
			break
		}
	}
	return out
}

// worktrees lists the linked worktrees under the worktrees directory (not
// the clones under repos/).
func (m *Manager) worktrees(ctx context.Context) []*nodev1.WorktreeFact {
	root, err := config.WorktreesDir()
	if err != nil {
		return nil
	}
	var out []*nodev1.WorktreeFact
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if rel == "repos" || strings.Count(rel, string(filepath.Separator)) > 3 || len(out) >= maxItems {
			return filepath.SkipDir
		}
		if _, linked := worktreeOrphan(path); !linked || path == root {
			return nil
		}
		f := &nodev1.WorktreeFact{Path: homeRel(m.o.UserHome, path), Bytes: dirSize(path)}
		if info, ok := gitinfo.Detect(path); ok {
			f.Branch = sanitize.Ident(info.Branch, 200)
		}
		if rem, ok := forge.ParseRemote(gitinfo.OriginURL(path)); ok {
			f.Repo = sanitize.Ident(rem.Slug(), 200)
		}
		f.Stale, _ = worktreeStale(ctx, path, m.o.Now())
		out = append(out, f)
		return filepath.SkipDir
	})
	return out
}
