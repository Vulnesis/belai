package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/vulnetix/belai/internal/factorylink"
)

// Keleustes host management with real binaries (keleustes
// docs/gaps/host-management.md §8.2, items 1 to 9). It runs when
// KELEUSTES_BIN names a built keleustes whose command line has the `host`
// subcommand (keleustes docs/gaps/host-proto-request.md B3), and skips
// otherwise. `just e2e-host` runs it.
//
// The host runs under a temporary HOME, so the Vulnetix CLI, the package and
// AI firewall files, the git config and the clone land there and never in the
// developer's own home. The real `vulnetix` (VULNETIX_BIN, else the one on
// PATH) is linked into that HOME's ~/.local/bin. Steps that need a Vulnetix
// organisation key (VULNETIX_E2E_ORG_KEY and VULNETIX_E2E_ORG_ID) assert the
// unauthenticated path without them, and the sensor step (5) runs only as
// root in a systemd container with KELEUSTES_E2E_SENSOR=1.

// hostCLI skips the test unless keleustes has the host subcommands.
func hostCLI(t *testing.T, k *keleustes) {
	t.Helper()
	if _, err := k.try("host", "--help"); err != nil {
		t.Skip("this keleustes has no `host` subcommand yet")
	}
}

// managedHost is one belai rc joined to Keleustes with host management on,
// under its own HOME.
type managedHost struct {
	rcHost
	user string // the host's HOME
	exe  string // the belai binary the daemon runs (a copy)
	log  string
}

// startManagedRC joins a fresh belai home and runs a copy of belai as
// `belai rc` with the host gate given, HOME set to user and env appended.
func startManagedRC(t *testing.T, k *keleustes, label, modelURL, manage, user, settings string, env ...string) managedHost {
	t.Helper()
	h := managedHost{rcHost: rcHost{label: label, home: t.TempDir(), project: t.TempDir()}, user: user}
	if settings != "" {
		if err := os.WriteFile(filepath.Join(h.home, "settings.json"), []byte(settings), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A copy, so belai_upgrade replaces this host's binary and never the
	// suite's shared one.
	h.exe = filepath.Join(t.TempDir(), "bin", "belai")
	copyFile(t, belaiBin, h.exe, 0o755)
	benv := belaiEnv(modelURL, h.home, append([]string{"BELAI_PROVIDER=openai", "HOME=" + user,
		"PATH=" + filepath.Join(user, ".local", "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent/keleustes-e2e"}, env...)...)
	connect := exec.Command(h.exe, "connect", k.kel("token", "new", "--label", label))
	connect.Env = benv
	if out, err := connect.CombinedOutput(); err != nil {
		t.Fatalf("belai connect: %v\n%s", err, out)
	}
	rc := exec.Command(h.exe, "rc", "--dir", h.project, "--keleustes-manage="+manage)
	rc.Env, rc.Dir = benv, h.project
	rlog, _ := os.Create(filepath.Join(t.TempDir(), label+"-rc.log"))
	h.log = rlog.Name()
	rc.Stdout, rc.Stderr = rlog, rlog
	if err := rc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// rc_restart re-execs in place, so the process to stop keeps the pid.
		_ = rc.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = rc.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = rc.Process.Kill()
			<-done
		}
		if t.Failed() {
			b, _ := os.ReadFile(rlog.Name())
			t.Logf("belai rc log:\n%s", tail(string(b), 8000))
		}
	})
	return h
}

func copyFile(t *testing.T, from, to string, mode os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, b, mode); err != nil {
		t.Fatal(err)
	}
}

type hostProduct struct {
	Product       string `json:"product"`
	State         string `json:"state"`
	Version       string `json:"version"`
	Authenticated bool   `json:"authenticated"`
	Running       bool   `json:"running"`
}

type hostRepo struct {
	Path      string `json:"path"`
	ForgeHost string `json:"forge_host"`
	Owner     string `json:"owner"`
	Name      string `json:"name"`
	Trusted   bool   `json:"trusted"`
}

type hostInventory struct {
	Belai struct {
		Version string `json:"version"`
	} `json:"belai"`
	Tools []struct {
		Name string `json:"name"`
		Ok   bool   `json:"ok"`
	} `json:"tools"`
	Products       []hostProduct `json:"products"`
	Repos          []hostRepo    `json:"repos"`
	SettingsSha256 string        `json:"settings_sha256"`
	Manage         struct {
		HostActions []string `json:"host_actions"`
		ManageLevel string   `json:"manage_level"`
	} `json:"manage"`
}

func (i hostInventory) product(id string) hostProduct {
	for _, p := range i.Products {
		if p.Product == id {
			return p
		}
	}
	return hostProduct{}
}

type hostUpdate struct {
	State          string `json:"state"`
	Error          string `json:"error"`
	PreviewJSON    string `json:"preview_json"`
	PreviewSha256  string `json:"preview_sha256"`
	ResultJSON     string `json:"result_json"`
	HandoffCommand string `json:"handoff_command"`
	HandoffReason  string `json:"handoff_reason"`
	Code           string `json:"code"`
}

func (k *keleustes) inventory(t *testing.T, node string) hostInventory {
	t.Helper()
	return k.inventoryWhen(t, node, 90*time.Second, func(hostInventory) bool { return true })
}

// inventoryWhen polls the last inventory until ok accepts it.
func (k *keleustes) inventoryWhen(t *testing.T, node string, d time.Duration, ok func(hostInventory) bool) hostInventory {
	t.Helper()
	var inv hostInventory
	deadline := time.Now().Add(d)
	for {
		inv = hostInventory{}
		out, err := k.try("host", "inventory", node)
		if err == nil && json.Unmarshal([]byte(out), &inv) == nil && inv.Belai.Version != "" && ok(inv) {
			return inv
		}
		if time.Now().After(deadline) {
			if inv.Belai.Version == "" {
				t.Skipf("no inventory from %s (is the Host service served?): %v %s", node, err, out)
			}
			t.Fatalf("the inventory never matched; last: %s", tail(out, 3000))
		}
		time.Sleep(time.Second)
	}
}

// act runs one host action and returns its final update.
func (k *keleustes) act(t *testing.T, node, kind string, args ...string) hostUpdate {
	t.Helper()
	out, _ := k.try(append([]string{"host", "act", node, kind, "--wait", "120"}, args...)...)
	var u hostUpdate
	if err := json.Unmarshal([]byte(out), &u); err != nil {
		t.Fatalf("host act %s: %v\n%s", kind, err, out)
	}
	return u
}

// provision runs a provision kind as a person does: a dry run on the host,
// then the real action against that preview with the host name typed.
func (k *keleustes) provision(t *testing.T, node, kind string, params ...string) (dry, run hostUpdate) {
	t.Helper()
	var args []string
	for _, p := range params {
		args = append(args, "--param", p)
	}
	dry = k.act(t, node, kind, append(args, "--dry-run")...)
	if dry.State != "done" {
		return dry, dry
	}
	run = k.act(t, node, kind, append(args, "--preview", dry.PreviewSha256, "--confirm", node)...)
	return dry, run
}

func TestKeleustesHostManagement(t *testing.T) {
	k := startKeleustes(t)
	hostCLI(t, k)
	model := newKeleustesModel(t)
	user := t.TempDir()
	cli := vulnetixBin()
	if cli != "" {
		// The real CLI, reachable as ~/.local/bin/vulnetix in the host's HOME.
		if err := os.MkdirAll(filepath.Join(user, ".local", "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(cli, filepath.Join(user, ".local", "bin", "vulnetix")); err != nil {
			t.Fatal(err)
		}
	}
	forgeHost, ca := gitForge(t, "acme", "web")
	rel := releaseFixture(t)
	settings := fmt.Sprintf(`{"workspace_dirs":["~/code"],"forges":{%q:"gitea"}}`, strings.Split(forgeHost, ":")[0])
	h := startManagedRC(t, k, "e2e-host", model.URL, "provision", user, settings,
		"BELAI_E2E_RELEASES="+rel.base,
		"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.sslCAInfo", "GIT_CONFIG_VALUE_0="+ca)
	node := h.label

	// 1. Inventory: belai's version, the tools, the gate.
	inv := k.inventory(t, node)
	t.Run("1 inventory", func(t *testing.T) {
		if inv.Manage.ManageLevel != "provision" || len(inv.Manage.HostActions) == 0 {
			t.Fatalf("manage = %+v", inv.Manage)
		}
		if inv.Belai.Version != "dev" {
			t.Errorf("belai version = %q, want the suite's dev build", inv.Belai.Version)
		}
		var git bool
		for _, tl := range inv.Tools {
			git = git || (tl.Name == "git" && tl.Ok)
		}
		if !git {
			t.Errorf("the inventory does not show git: %+v", inv.Tools)
		}
	})

	// 2. CLI: the real vulnetix in the temp HOME probes installed and signed
	// out; product_auth without a vault key hands off to a person
	// (needs_browser), with one it signs in.
	t.Run("2 cli", func(t *testing.T) {
		if cli == "" {
			t.Skip("no vulnetix CLI (set VULNETIX_BIN)")
		}
		if u := k.act(t, node, "product_probe", "--param", "product=cli"); u.State != "done" {
			t.Fatalf("probe = %+v", u)
		}
		inv := k.inventoryWhen(t, node, 60*time.Second, func(i hostInventory) bool { return i.product("cli").State != "absent" && i.product("cli").State != "" })
		if p := inv.product("cli"); p.Authenticated || p.Version == "" {
			t.Fatalf("cli = %+v, want installed and signed out", p)
		}
		if os.Getenv("VULNETIX_E2E_ORG_KEY") == "" || os.Getenv("VULNETIX_E2E_ORG_ID") == "" {
			_, run := k.provision(t, node, "product_auth", "product=cli")
			if run.State != "needs_human" || run.HandoffReason != "needs_browser" || !strings.Contains(run.HandoffCommand, "vulnetix auth login") {
				t.Fatalf("product_auth without a key = %+v", run)
			}
			return
		}
		k.vaultKey(t, "VULNETIX_API_KEY", os.Getenv("VULNETIX_E2E_ORG_KEY"))
		k.vaultKey(t, "VULNETIX_ORG_ID", os.Getenv("VULNETIX_E2E_ORG_ID"))
		if _, run := k.provision(t, node, "product_auth", "product=cli"); run.State != "done" {
			t.Fatalf("product_auth = %+v", run)
		}
		k.act(t, node, "product_probe", "--param", "product=cli")
		k.inventoryWhen(t, node, 60*time.Second, func(i hostInventory) bool { return i.product("cli").Authenticated })
	})
	signedIn := os.Getenv("VULNETIX_E2E_ORG_KEY") != "" && os.Getenv("VULNETIX_E2E_ORG_ID") != ""

	// 3. Package firewall: npm and pypi in the temp HOME. Signed in, the
	// files change and turning one off restores it; signed out the CLI
	// refuses and nothing is written.
	t.Run("3 package firewall", func(t *testing.T) {
		if cli == "" {
			t.Skip("no vulnetix CLI (set VULNETIX_BIN)")
		}
		npmrc, pip := filepath.Join(user, ".npmrc"), filepath.Join(user, ".config", "pip", "pip.conf")
		dry, run := k.provision(t, node, "product_configure", "product=package_firewall", "on=npm,pypi")
		if dry.State != "done" || !strings.Contains(dry.PreviewJSON, "package-firewall") || strings.Contains(dry.PreviewJSON, user) {
			t.Fatalf("preview = %+v", dry)
		}
		if !signedIn {
			if run.State != "failed" {
				t.Fatalf("signed out = %+v, want the CLI's refusal", run)
			}
			for _, f := range []string{npmrc, pip} {
				if _, err := os.Stat(f); err == nil {
					t.Errorf("%s written while signed out", f)
				}
			}
			t.Log("signed out: the CLI refused (set VULNETIX_E2E_ORG_KEY and VULNETIX_E2E_ORG_ID for the configured path)")
			return
		}
		if run.State != "done" {
			t.Fatalf("configure = %+v", run)
		}
		for _, f := range []string{npmrc, pip} {
			if _, err := os.Stat(f); err != nil {
				t.Errorf("%s not written: %v", f, err)
			}
		}
		if _, run := k.provision(t, node, "product_configure", "product=package_firewall", "on=npm"); run.State != "done" {
			t.Fatalf("pypi off = %+v", run)
		}
		if b, _ := os.ReadFile(pip); strings.Contains(string(b), "vulnetix") {
			t.Errorf("pip.conf still points at the firewall: %s", b)
		}
	})

	// 4. AI firewall: client claude-code (user scope) in the temp HOME.
	t.Run("4 ai firewall", func(t *testing.T) {
		if cli == "" {
			t.Skip("no vulnetix CLI (set VULNETIX_BIN)")
		}
		dry, run := k.provision(t, node, "product_configure", "product=ai_firewall", "on=claude-code", "scope=user")
		if dry.State != "done" || !strings.Contains(dry.PreviewJSON, "ai-firewall") {
			t.Fatalf("preview = %+v", dry)
		}
		settingsJSON := filepath.Join(user, ".claude", "settings.json")
		if !signedIn {
			if run.State != "failed" {
				t.Fatalf("signed out = %+v, want the CLI's refusal", run)
			}
			if _, err := os.Stat(settingsJSON); err == nil {
				t.Errorf("%s written while signed out", settingsJSON)
			}
			t.Log("signed out: the CLI refused (set VULNETIX_E2E_ORG_KEY and VULNETIX_E2E_ORG_ID for the configured path)")
			return
		}
		if run.State != "done" {
			t.Fatalf("configure = %+v", run)
		}
		cmd := exec.Command(cli, "ai-firewall", "status", "-o", "json")
		cmd.Env = append(os.Environ(), "HOME="+user)
		out, err := cmd.Output()
		if err != nil || !strings.Contains(string(out), "claude-code") {
			t.Fatalf("ai-firewall status: %v %s", err, out)
		}
	})

	// 5. Sensor: root only, in a systemd container.
	t.Run("5 sensor", func(t *testing.T) {
		if os.Getenv("KELEUSTES_E2E_SENSOR") != "1" || os.Geteuid() != 0 || runtime.GOOS != "linux" {
			t.Skip("the sensor step runs as root in a systemd container with KELEUSTES_E2E_SENSOR=1 (nightly)")
		}
		if _, err := os.Stat("/run/systemd/system"); err != nil {
			t.Skip("systemd is not running here")
		}
		_, run := k.provision(t, node, "product_install", "product=sensor", "profile=default", "version="+envOr("VULNETIX_E2E_SENSOR_VERSION", "v0.9.3"))
		if run.State != "needs_human" || run.HandoffReason != "needs_root" {
			t.Fatalf("install = %+v, want the needs_root hand-off", run)
		}
		rootRun(t, user, run.HandoffCommand)
		k.act(t, node, "product_probe", "--param", "product=sensor")
		k.inventoryWhen(t, node, 120*time.Second, func(i hostInventory) bool { return i.product("sensor").State == "active" })
		_, run = k.provision(t, node, "product_uninstall", "product=sensor")
		if run.State != "needs_human" || run.HandoffReason != "needs_root" {
			t.Fatalf("uninstall = %+v", run)
		}
		rootRun(t, user, run.HandoffCommand)
		k.act(t, node, "product_probe", "--param", "product=sensor")
		k.inventoryWhen(t, node, 120*time.Second, func(i hostInventory) bool { return i.product("sensor").State == "absent" })
	})

	// 6. Config: config_set agents.max_workers=2 changes settings.json; a
	// stale if_match is refused.
	t.Run("6 config", func(t *testing.T) {
		sha := k.inventory(t, node).SettingsSha256
		u := k.act(t, node, "config_set", "--param", "key=agents.max_workers", "--param", "value=2", "--if-match", sha)
		if u.State != "done" {
			t.Fatalf("config_set = %+v", u)
		}
		b, _ := os.ReadFile(filepath.Join(h.home, "settings.json"))
		if !strings.Contains(string(b), `"max_workers": 2`) {
			t.Fatalf("settings.json = %s", b)
		}
		u = k.act(t, node, "config_set", "--param", "key=agents.max_workers", "--param", "value=3", "--if-match", sha)
		if !refused(u) || !strings.Contains(u.Error, "settings changed") {
			t.Fatalf("stale if_match = %+v", u)
		}
	})

	// 7. Repos: clone a bare repository a local https forge serves into
	// ~/code/<name> at depth 1; it is trusted and the inventory shows it with
	// its owner and name. A second clone into the same place is a no-op,
	// and a clone whose target holds something else is refused.
	t.Run("7 repos", func(t *testing.T) {
		dry, run := k.provision(t, node, "repo_clone", "forge_host="+forgeHost, "owner=acme", "name=web", "depth=1")
		if dry.State != "done" || !strings.Contains(dry.PreviewJSON, "~/code/web") || !strings.Contains(dry.PreviewJSON, "--depth") {
			t.Fatalf("preview = %+v", dry)
		}
		if run.State != "done" {
			t.Fatalf("clone = %+v", run)
		}
		dir := filepath.Join(user, "code", "web")
		out, err := exec.Command("git", "-C", dir, "rev-list", "--count", "HEAD").Output()
		if err != nil || strings.TrimSpace(string(out)) != "1" {
			t.Fatalf("depth 1 clone has %q commits: %v", out, err)
		}
		k.act(t, node, "inventory_refresh")
		inv := k.inventoryWhen(t, node, 60*time.Second, func(i hostInventory) bool {
			for _, r := range i.Repos {
				if r.Path == "~/code/web" {
					return true
				}
			}
			return false
		})
		for _, r := range inv.Repos {
			if r.Path == "~/code/web" && (r.Owner != "acme" || r.Name != "web" || !r.Trusted) {
				t.Fatalf("repo row = %+v", r)
			}
		}
		if err := os.MkdirAll(filepath.Join(user, "code", "api"), 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(filepath.Join(user, "code", "api", "notes"), []byte("x"), 0o644)
		if u := k.act(t, node, "repo_clone", "--param", "forge_host="+forgeHost, "--param", "owner=acme", "--param", "name=api", "--dry-run"); !refused(u) || !strings.Contains(u.Error, "not a git checkout") {
			t.Fatalf("occupied target = %+v", u)
		}
	})

	// 8. belai upgrade: a direct install from a local release fixture with
	// checksums.txt. A bad checksum is refused; the good one installs, and
	// after rc_restart the link comes back on the new version.
	t.Run("8 belai upgrade", func(t *testing.T) {
		_, run := k.provision(t, node, "belai_upgrade", "version="+rel.bad)
		if run.State != "failed" || !strings.Contains(run.Error+run.ResultJSON, "checksum") {
			t.Fatalf("bad checksum = %+v", run)
		}
		if b, _ := os.ReadFile(h.exe); sha256Hex(b) != sha256Hex(mustRead(t, belaiBin)) {
			t.Fatal("a refused upgrade replaced the binary")
		}
		dry, run := k.provision(t, node, "belai_upgrade", "version="+rel.good)
		if dry.State != "done" || run.State != "done" {
			t.Fatalf("upgrade = %+v / %+v", dry, run)
		}
		if b, _ := os.ReadFile(h.exe); sha256Hex(b) != rel.goodSum {
			t.Fatal("the upgrade did not install the release asset")
		}
		_, run = k.provision(t, node, "rc_restart", "force_after_s=30", "expect_version="+rel.good)
		if run.State != "done" && run.State != "running" {
			t.Fatalf("rc_restart = %+v", run)
		}
		k.inventoryWhen(t, node, 120*time.Second, func(i hostInventory) bool {
			return strings.TrimPrefix(i.Belai.Version, "v") == strings.TrimPrefix(rel.good, "v")
		})
	})

	// 9. Rules: with the kill switch on, every mutating kind is refused by
	// Keleustes before it leaves, the host's own control file says stopped
	// (so belai refuses on its side too), and the audit chain verifies with
	// every host.action.* entry.
	t.Run("9 rules", func(t *testing.T) {
		k.kel("host", "stop", "--reason", "e2e")
		defer k.kel("host", "resume")
		mutating := map[string][]string{
			"config_set":        {"key=agents.max_workers", "value=3"},
			"project_prefs_set": {"path=" + h.project, "key=agents.enabled", "value=false"},
			"agents_set":        {"path=" + h.project, "profile=belai:pr-reviewer", "state=off"},
			"repo_trust":        {"path=~/code/web"},
			"repo_untrust":      {"path=~/code/web"},
			"worktree_drop":     {"path=~/x"},
			"session_prune":     nil,
			"product_install":   {"product=cli", "method=direct", "version=v1.0.0"},
			"product_upgrade":   {"product=cli"},
			"product_uninstall": {"product=cli"},
			"product_configure": {"product=package_firewall", "on=npm"},
			"product_auth":      {"product=cli"},
			"belai_upgrade":     {"version=" + rel.good},
			"rc_restart":        {"force_after_s=30"},
			"repo_clone":        {"forge_host=" + forgeHost, "owner=acme", "name=web"},
			"shell_exec":        {`argv_json=["true"]`},
		}
		for kind, params := range mutating {
			var args []string
			for _, p := range params {
				args = append(args, "--param", p)
			}
			for _, dry := range []bool{true, false} {
				a := args
				if dry {
					a = append(append([]string{}, args...), "--dry-run")
				}
				if u := k.act(t, node, kind, a...); u.Code != "kill_switch" {
					t.Errorf("%s (dry %v) under stop = %+v, want the kill switch", kind, dry, u)
				}
			}
		}
		deadline := time.Now().Add(60 * time.Second)
		for {
			if stopped, _ := factorylink.FactoryStopped(h.home); stopped {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the host's control file never said stopped")
			}
			time.Sleep(time.Second)
		}
		out, err := k.try("host", "verify")
		if err != nil || !strings.Contains(out, `"ok":true`) {
			t.Errorf("audit verify: %v %s", err, out)
		}
	})
}

// refused reports a refusal by belai (state refused) or by Keleustes (code).
func refused(u hostUpdate) bool { return u.State == "refused" || u.Code != "" }

func vulnetixBin() string {
	if p := os.Getenv("VULNETIX_BIN"); p != "" {
		return p
	}
	if p, err := exec.LookPath("vulnetix"); err == nil {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		return p
	}
	return ""
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// vaultKey stores a vault key of the vulnetix provider in Keleustes.
func (k *keleustes) vaultKey(t *testing.T, env, value string) {
	t.Helper()
	cmd := exec.Command(k.bin, "--data", k.data, "sessions", "vault-key", "--provider", "vulnetix", "--env", env)
	cmd.Env, cmd.Stdin = k.env, strings.NewReader(value)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("vault-key %s: %v %s", env, err, out)
	}
}

// rootRun runs a hand-off command as the person would, as root.
func rootRun(t *testing.T, user, command string) {
	t.Helper()
	cmd := exec.Command("sh", "-c", strings.ReplaceAll(command, "sudo ", ""))
	cmd.Env = append(os.Environ(), "HOME="+user)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hand-off %q: %v\n%s", command, err, out)
	}
}

// gitForge serves a bare repository owner/name over https (git
// http-backend behind a TLS test server) and returns its host:port and the
// server certificate as a CA file for git.
func gitForge(t *testing.T, owner, name string) (string, string) {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	bare := filepath.Join(root, owner, name+".git")
	work := t.TempDir()
	env := append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test")
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = dir, env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	if err := os.MkdirAll(filepath.Dir(bare), 0o755); err != nil {
		t.Fatal(err)
	}
	git(root, "init", "-q", "--bare", "-b", "main", bare)
	git(work, "init", "-q", "-b", "main")
	for _, s := range []string{"one", "two", "three"} {
		if err := os.WriteFile(filepath.Join(work, "README.md"), []byte(s+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		git(work, "add", "README.md")
		git(work, "commit", "--no-gpg-sign", "-q", "-m", s)
	}
	git(work, "push", "-q", bare, "main")
	srv := httptest.NewTLSServer(&cgi.Handler{Path: gitPath, Args: []string{"http-backend"},
		Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_CONFIG_NOSYSTEM=1"}})
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "forge-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	return strings.TrimPrefix(srv.URL, "https://"), ca
}

// release is a local belai release fixture: good is a version whose asset is
// a belai built with that version and listed in checksums.txt, bad one whose
// checksums.txt does not match its asset.
type release struct {
	base, good, bad, goodSum string
}

func releaseFixture(t *testing.T) release {
	t.Helper()
	r := release{good: "v9.9.9-e2e", bad: "v9.9.8-e2e"}
	dir := t.TempDir()
	asset := fmt.Sprintf("belai-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		asset += ".exe"
	}
	bin := filepath.Join(dir, r.good, asset)
	build := exec.Command("go", "build", "-o", bin, "-ldflags", "-X github.com/vulnetix/belai/internal/version.Version="+r.good, "./cmd/belai")
	build.Dir = moduleRoot()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the release fixture: %v\n%s", err, out)
	}
	r.goodSum = sha256Hex(mustRead(t, bin))
	if err := os.WriteFile(filepath.Join(dir, r.good, "checksums.txt"), []byte(r.goodSum+"  "+asset+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	copyFile(t, bin, filepath.Join(dir, r.bad, asset), 0o644)
	if err := os.WriteFile(filepath.Join(dir, r.bad, "checksums.txt"), []byte(strings.Repeat("0", 64)+"  "+asset+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	t.Cleanup(srv.Close)
	r.base = srv.URL
	return r
}
