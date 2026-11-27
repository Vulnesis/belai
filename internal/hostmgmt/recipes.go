package hostmgmt

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/vulnetix/belai/internal/proc"
	"github.com/vulnetix/belai/internal/products"
	"github.com/vulnetix/belai/internal/vulnetixcli"
)

// Product recipes (docs/gaps/host-management.md §5.3): a fixed program and an
// argv whose every word is a literal or a validated parameter, never a shell.
// A download fetches a pinned release asset and its checksums.txt and refuses
// a mismatch; install.sh is never piped anywhere. A step that needs root is a
// hand-off: belai never runs sudo, and no sudoers rule is written (decision
// O2).

// pkgfwWriters are the package firewall ecosystems with a writer, and the
// subcommand that configures each (cli/pkg/packagefirewall/ecosystem.go;
// conda, julia, oci, debian, rpm, alpine, chef and terraform have none).
var pkgfwWriters = map[string]string{
	"go": "go", "npm": "npm", "pypi": "pypi", "cargo": "cargo", "gem": "gem", "hex": "hex", "pub": "pub",
	"maven": "maven", "nuget": "nuget", "composer": "composer", "conan": "conan", "cran": "cran",
	"helm": "helm", "aur": "aur", "homebrew": "homebrew",
}

// pkgfwFiles are the files a package firewall change may touch, pinned in
// the preview so a file changed since makes the preview stale.
var pkgfwFiles = []string{".npmrc", ".config/pip/pip.conf", ".cargo/config.toml", ".gemrc", ".netrc", ".m2/settings.xml"}

// aifwClients are the AI firewall clients the CLI writes (cursor and
// windsurf are instruction-only and not offered).
var aifwClients = []string{"shell", "env", "claude-code", "codex", "continue", "aider"}

// aifwProjectDefault are the clients whose default scope is the project;
// uninstall has no --scope and removes at the default scope only.
var aifwProjectDefault = map[string]bool{"env": true, "claude-code": true, "aider": true}

const (
	stepTimeout     = 10 * time.Minute
	maxDownload     = 512 << 20
	sensorInstallTo = "/usr/local/bin/vulnetix-sensor"
)

func (m *Manager) look(name string) (string, bool) {
	p, err := m.o.LookPath(name)
	return p, err == nil && p != ""
}

func (m *Manager) assetName(base string) string {
	n := fmt.Sprintf("%s-%s-%s", base, m.o.GOOS, m.o.GOARCH)
	if m.o.GOOS == "windows" {
		n += ".exe"
	}
	return n
}

func planProductInstall(_ context.Context, c *call) (*Plan, string) {
	m := c.m
	pl := &Plan{Params: map[string]string{"product": c.p["product"], "method": c.p["method"], "version": c.p["version"]}}
	switch c.p["product"] {
	case products.CLI:
		if _, ok := m.look("vulnetix"); ok {
			return nil, "the Vulnetix CLI is already installed; use product_upgrade"
		}
		method := c.p["method"]
		if method == "" {
			if p, ok := vulnetixcli.PlanInstall(m.o.GOOS, m.o.LookPath); ok {
				method = string(p.Manager)
			} else {
				method = "direct"
			}
		}
		pl.Params["method"] = method
		switch method {
		case "brew", "scoop":
			p, ok := vulnetixcli.PlanInstall(m.o.GOOS, m.o.LookPath)
			if !ok || string(p.Manager) != method {
				return nil, method + " is not available on this host"
			}
			for _, s := range p.Steps {
				pl.Steps = append(pl.Steps, Step{Argv: s.Argv, Timeout: int(stepTimeout.Seconds())})
			}
		case "direct":
			if c.p["version"] == "" {
				return nil, "a direct install names the release version to pin"
			}
			asset := m.assetName("vulnetix")
			base := strings.TrimRight(m.o.CLIReleases, "/") + "/" + c.p["version"] + "/"
			pl.Steps = []Step{{Download: &Download{URL: base + asset, Checksums: base + "checksums.txt", Asset: asset,
				To: filepath.Join(m.o.UserHome, ".local", "bin", "vulnetix")}}}
			pl.Notes = []string{"install.sh is never run; the asset is checked against checksums.txt"}
		}
		return pl, ""
	case products.Sensor:
		if m.o.GOOS != "linux" {
			return nil, "the runtime sensor runs on Linux only"
		}
		profile := c.p["profile"]
		if profile == "" {
			return nil, "a sensor install names the sensor profile to enroll with"
		}
		cmd := "sudo vulnetix-sensor enroll --from-cli-login --profile " + profile
		if _, ok := m.look("vulnetix-sensor"); !ok {
			if c.p["version"] == "" {
				return nil, "a sensor install names the release version to pin"
			}
			asset := m.assetName("vulnetix-sensor")
			base := strings.TrimRight(m.o.CLIReleases, "/") + "/" + c.p["version"] + "/"
			staging := filepath.Join(m.o.Home, "rc", "staging", "vulnetix-sensor")
			pl.Steps = []Step{{Download: &Download{URL: base + asset, Checksums: base + "checksums.txt", Asset: asset, To: staging}}}
			cmd = "sudo install -m 0755 " + staging + " " + sensorInstallTo + " && " + cmd
		}
		pl.Handoff = &Handoff{Command: cmd, Reason: "needs_root"}
		return pl, ""
	}
	return nil, "install that product from the Vulnetix console; it has nothing to install on the host"
}

func planProductUpgrade(_ context.Context, c *call) (*Plan, string) {
	m := c.m
	pl := &Plan{Params: map[string]string{"product": c.p["product"]}}
	switch c.p["product"] {
	case products.CLI:
		path, ok := m.look("vulnetix")
		if !ok {
			return nil, "the Vulnetix CLI is not installed"
		}
		method, _ := vulnetixcli.DetectInstall(path, nil)
		switch method {
		case vulnetixcli.InstallBrew:
			pl.Steps = []Step{{Argv: []string{"brew", "upgrade", "vulnetix"}}}
		case vulnetixcli.InstallScoop:
			pl.Steps = []Step{{Argv: []string{"scoop", "update", "vulnetix"}}}
		default:
			pl.Steps = []Step{{Argv: []string{path, "update"}}}
		}
		pl.Params["method"] = string(method)
		return pl, ""
	case products.Sensor:
		path, ok := m.look("vulnetix-sensor")
		if !ok {
			return nil, "the runtime sensor is not installed"
		}
		pl.Steps = []Step{{Argv: []string{path, "guard-check"}}}
		pl.Notes = []string{"the sensor updates itself; this runs its guard check and reports"}
		return pl, ""
	}
	return nil, "that product is upgraded by the Vulnetix service, not on the host"
}

func planProductUninstall(_ context.Context, c *call) (*Plan, string) {
	m := c.m
	pl := &Plan{Params: map[string]string{"product": c.p["product"]}}
	switch c.p["product"] {
	case products.CLI:
		path, ok := m.look("vulnetix")
		if !ok {
			return nil, "the Vulnetix CLI is not installed"
		}
		method, _ := vulnetixcli.DetectInstall(path, nil)
		switch method {
		case vulnetixcli.InstallBrew:
			pl.Steps = []Step{{Argv: []string{"brew", "uninstall", "vulnetix"}}}
		case vulnetixcli.InstallScoop:
			pl.Steps = []Step{{Argv: []string{"scoop", "uninstall", "vulnetix"}}}
		default:
			want := filepath.Join(m.o.UserHome, ".local", "bin", "vulnetix")
			real, _ := filepath.EvalSymlinks(path)
			if real != want && path != want {
				return nil, "the CLI was not installed by belai or a package manager; remove it on the host"
			}
			pl.Steps = []Step{{Remove: want}}
		}
		return pl, ""
	case products.Sensor:
		// A locked profile refuses uninstall without a one-time code from the
		// console. It appears only in the hand-off command the person runs
		// (one device, one use, a day at most); params say one was given.
		cmd := "sudo vulnetix-sensor uninstall"
		if code := c.p["code"]; code != "" {
			cmd += " --code " + code
			pl.Params["code"] = "given"
		}
		pl.Handoff = &Handoff{Command: cmd, Reason: "needs_root"}
		return pl, ""
	}
	if c.p["code"] != "" {
		return nil, "code is for the sensor only"
	}
	return nil, "use product_configure to turn that product off on the host"
}

func planProductConfigure(_ context.Context, c *call) (*Plan, string) {
	m := c.m
	path, ok := m.look("vulnetix")
	if !ok {
		return nil, "the Vulnetix CLI is not installed"
	}
	var on []string
	if c.p["on"] != "" {
		on = strings.Split(c.p["on"], ",")
	}
	pl := &Plan{Params: map[string]string{"product": c.p["product"], "on": c.p["on"], "purge": c.p["purge"],
		"remove_credentials": c.p["remove_credentials"], "scope": c.p["scope"], "path": c.p["path"]}}
	switch c.p["product"] {
	case products.PackageFirewall:
		if c.p["scope"] == "project" || c.p["path"] != "" {
			return nil, "the package firewall is configured for the user only"
		}
		if c.p["purge"] == "true" && len(on) > 0 {
			return nil, "purge turns every ecosystem off; it cannot be combined with on"
		}
		for _, eco := range on {
			sub, ok := pkgfwWriters[eco]
			if !ok {
				return nil, "the package firewall cannot configure " + eco + " on a host"
			}
			pl.Steps = append(pl.Steps, Step{Argv: []string{path, "--disable-memory", "package-firewall", sub}})
		}
		off := []string{path, "--disable-memory", "package-firewall", "uninstall"}
		if len(on) == 0 {
			off = append(off, "--all")
		} else {
			off = append(off, "--except", strings.Join(on, ","))
		}
		if c.p["purge"] == "true" {
			off = append(off, "--purge")
		}
		if c.p["remove_credentials"] == "true" {
			off = append(off, "--remove-credentials")
		}
		pl.Steps = append(pl.Steps, Step{Argv: off})
		for _, rel := range pkgfwFiles {
			pl.Files = append(pl.Files, fileState(filepath.Join(m.o.UserHome, rel)))
		}
		return pl, ""
	case products.AIFirewall:
		if c.p["purge"] != "" || c.p["remove_credentials"] != "" {
			return nil, "purge and remove_credentials are package firewall options"
		}
		scope := c.p["scope"]
		if scope == "" {
			scope = "user"
		}
		dir := ""
		if scope == "project" {
			if c.p["path"] == "" {
				return nil, "a project scope names the trusted repository path"
			}
			dir = c.p["path"]
		} else if c.p["path"] != "" {
			return nil, "a path is for the project scope only"
		}
		for _, id := range on {
			if !has(aifwClients, id) {
				return nil, "the AI firewall cannot configure client " + id
			}
		}
		if len(on) > 0 {
			pl.Steps = append(pl.Steps, Step{Argv: append(append([]string{path, "--disable-memory", "ai-firewall", "install"}, on...), "--scope", scope), Dir: dir})
		}
		off := []string{path, "--disable-memory", "ai-firewall", "uninstall"}
		if len(on) == 0 {
			off = append(off, "--all")
		} else {
			off = append(off, "--except", strings.Join(on, ","))
		}
		pl.Steps = append(pl.Steps, Step{Argv: off, Dir: dir})
		for _, id := range on {
			if aifwProjectDefault[id] != (scope == "project") {
				pl.Notes = append(pl.Notes, "client "+id+" is installed outside its default scope; uninstall removes it only at its default scope")
			}
		}
		pl.Files = append(pl.Files, fileState(filepath.Join(m.o.UserHome, ".claude", "settings.json")))
		return pl, ""
	}
	return nil, "product_configure is for the package firewall and the AI firewall"
}

func planProductAuth(_ context.Context, c *call) (*Plan, string) {
	path, ok := c.m.look("vulnetix")
	if !ok {
		return nil, "the Vulnetix CLI is not installed"
	}
	// The plan does not depend on whether a grant came with the action, so a
	// preview made without one still matches the run that carries it.
	return &Plan{Params: map[string]string{"product": products.CLI},
		Steps: []Step{{Argv: []string{path, "auth", "login", "--noninteractive", "--store", "keyring"}, Env: slicesClone(grantVars), Timeout: 120}},
		Notes: []string{"without a vault grant holding an ApiKey or a SigV4 pair this hands off to a person: vulnetix auth login (needs_browser)"}}, ""
}

// runProductAuth signs the CLI in with the grant, or hands off to a person
// when the action carries none.
func runProductAuth(ctx context.Context, c *call, pl *Plan) result {
	if !grantComplete(grantEnv(c)) {
		return handoff("vulnetix auth login", "needs_browser")
	}
	return runSteps(ctx, c, pl)
}

func slicesClone(s []string) []string { return append([]string(nil), s...) }

// grantPairs are the credential pairs `vulnetix auth login --noninteractive`
// reads from its environment: an org-scoped ApiKey, or a SigV4 secret. Both
// come from the environment only, never argv.
var grantPairs = [][2]string{
	{"VULNETIX_API_KEY", "VULNETIX_ORG_ID"},
	{"VVD_ORG", "VVD_SECRET"},
}

// grantVars are every variable product_auth may take from the vault grant.
var grantVars = []string{"VULNETIX_API_KEY", "VULNETIX_ORG_ID", "VVD_ORG", "VVD_SECRET"}

// grantComplete reports whether the names hold at least one whole pair.
func grantComplete(names []string) bool {
	for _, p := range grantPairs {
		if has(names, p[0]) && has(names, p[1]) {
			return true
		}
	}
	return false
}

// grantEnv names the grant's variables product_auth uses.
func grantEnv(c *call) []string {
	var out []string
	for _, s := range c.grant.Secrets(c.m.o.Now()) {
		if has(grantVars, s.Env) && !has(out, s.Env) {
			out = append(out, s.Env)
		}
	}
	sortStrings(out)
	return out
}

// grantValues are the env assignments for the child, from the grant.
func grantValues(c *call, names []string) []string {
	var out []string
	for _, s := range c.grant.Secrets(c.m.o.Now()) {
		if has(names, s.Env) {
			out = append(out, s.Env+"="+s.Value)
		}
	}
	return out
}

// fileState pins a file's content.
func fileState(path string) FileState {
	data, err := os.ReadFile(path)
	if err != nil {
		return FileState{Path: path, SHA256: "absent"}
	}
	sum := sha256.Sum256(data)
	return FileState{Path: path, SHA256: hex.EncodeToString(sum[:])}
}

// runSteps runs a plan's steps in order, then its hand-off if it has one.
func runSteps(ctx context.Context, c *call, pl *Plan) result {
	for i, s := range pl.Steps {
		if stopped, _ := c.m.o.Stopped(); stopped {
			return result{state: stateCancelled, err: "the factory was stopped before step " + fmt.Sprint(i+1)}
		}
		var err error
		switch {
		case s.Download != nil:
			if s.Backup != "" {
				if berr := backup(s.Download.To, s.Backup); berr != nil {
					return failed(fmt.Sprintf("step %d: the current binary could not be kept as %s", i+1, filepath.Base(s.Backup)))
				}
				c.line(ctx, "kept the current binary as "+homeRel(c.m.o.UserHome, s.Backup))
			}
			err = c.download(ctx, s.Download)
		case s.Remove != "":
			err = os.Remove(s.Remove)
			if err == nil {
				c.line(ctx, "removed "+homeRel(c.m.o.UserHome, s.Remove))
			}
		case len(s.Argv) > 0:
			err = c.exec(ctx, s)
		}
		if err != nil {
			return failed(fmt.Sprintf("step %d: %s", i+1, err.Error()))
		}
	}
	if pl.Handoff != nil {
		return handoff(pl.Handoff.Command, pl.Handoff.Reason)
	}
	return done("")
}

// exec runs one argv: no shell, the scrubbed environment plus the grant's
// variables for this child alone, its own process group, output scrubbed
// line by line.
func (c *call) exec(ctx context.Context, s Step) error {
	timeout := stepTimeout
	if s.Timeout > 0 {
		timeout = time.Duration(s.Timeout) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Argv[0], s.Argv[1:]...)
	cmd.Dir = s.Dir
	cmd.Env = append(proc.ScrubbedEnv(), grantValues(c, s.Env)...)
	proc.SetProcessGroup(cmd)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	start := time.Now()
	c.line(ctx, "run "+strings.Join(displayArgv(c.m.o.UserHome, s.Argv), " "))
	if err := cmd.Start(); err != nil {
		pw.Close()
		cmd.Env = nil
		return errors.New("the program could not start")
	}
	go func() { _ = cmd.Wait(); pw.Close() }()
	sc := bufio.NewScanner(pr)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		c.line(ctx, sc.Text())
	}
	_, _ = io.Copy(io.Discard, pr)
	// The child is gone; drop its environment, which held the grant.
	cmd.Env = nil
	if ctx.Err() != nil {
		return errors.New("timed out")
	}
	if code := cmd.ProcessState.ExitCode(); code != 0 {
		return fmt.Errorf("exit %d", code)
	}
	c.line(ctx, "ok in "+elapsed(time.Since(start)))
	return nil
}

func displayArgv(home string, argv []string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		out[i] = homeRel(home, a)
	}
	return out
}

// download fetches a release asset and checksums.txt, verifies the asset's
// sha256 against its line, and writes it to d.To atomically, mode 0755. The
// provenance (URL and sha256) is reported in the action's lines.
func (c *call) download(ctx context.Context, d *Download) error {
	sums, err := c.fetch(ctx, d.Checksums, 1<<20)
	if err != nil {
		return fmt.Errorf("checksums.txt: %w", err)
	}
	want := ""
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == d.Asset {
			want = strings.ToLower(f[0])
		}
	}
	if len(want) != 64 {
		return errors.New("checksums.txt has no entry for " + d.Asset)
	}
	body, err := c.fetch(ctx, d.URL, maxDownload)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	sum := sha256.Sum256(body)
	got := hex.EncodeToString(sum[:])
	if got != want {
		return errors.New("checksum mismatch: the asset was not installed")
	}
	if err := os.MkdirAll(filepath.Dir(d.To), 0o755); err != nil {
		return errors.New("the target directory could not be made")
	}
	tmp := d.To + ".new"
	if err := os.WriteFile(tmp, body, 0o755); err != nil {
		return errors.New("the asset could not be written")
	}
	if err := os.Rename(tmp, d.To); err != nil {
		_ = os.Remove(tmp)
		return errors.New("the asset could not be moved into place")
	}
	c.line(ctx, "provenance "+d.URL+" sha256 "+got)
	c.line(ctx, "installed "+homeRel(c.m.o.UserHome, d.To))
	return nil
}

func (c *call) fetch(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.New("bad URL")
	}
	resp, err := c.m.o.HTTP.Do(req)
	if err != nil {
		return nil, errors.New("unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, errors.New("read failed")
	}
	if int64(len(b)) > limit {
		return nil, errors.New("too large")
	}
	return b, nil
}
