package hostmgmt

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/products"
	"github.com/vulnetix/belai/internal/vaultenv"
)

func TestMain(m *testing.M) {
	vaultenv.SkipProtect = true
	os.Exit(m.Run())
}

// fakeTransport records what the node sends.
type fakeTransport struct {
	mu      sync.Mutex
	updates []*nodev1.HostActionUpdate
	reports []*nodev1.HostInventory
	fail    bool
}

func (f *fakeTransport) Report(_ context.Context, in *nodev1.HostInventory) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reports = append(f.reports, in)
	return nil
}

func (f *fakeTransport) Actions(context.Context, *nodev1.HostActionsRequest) (nodev1.Host_ActionsClient, error) {
	return nil, errNoTransport
}

func (f *fakeTransport) Progress(_ context.Context, in *nodev1.HostActionUpdate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return fmt.Errorf("down")
	}
	f.updates = append(f.updates, in)
	return nil
}

func (f *fakeTransport) of(id string) []*nodev1.HostActionUpdate {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*nodev1.HostActionUpdate
	for _, u := range f.updates {
		if u.GetActionId() == id {
			out = append(out, u)
		}
	}
	return out
}

type env struct {
	t        *testing.T
	home     string // belai home
	user     string // user home
	bin      string // stub programs
	offered  string // an offered directory
	ft       *fakeTransport
	m        *Manager
	o        Options
	stopped  bool
	blackout bool
	prefs    []string
	drained  time.Duration
	reexec   int
	rec      *audit.Recorder
	n        int
}

func newEnv(t *testing.T, level Level, mut ...func(*Options)) *env {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stubs")
	}
	root := t.TempDir()
	e := &env{t: t, home: filepath.Join(root, "belai"), user: filepath.Join(root, "user"), bin: filepath.Join(root, "bin"), ft: &fakeTransport{}}
	for _, d := range []string{e.home, e.user, e.bin} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	e.offered = filepath.Join(e.user, "src", "api")
	if err := os.MkdirAll(e.offered, 0o700); err != nil {
		t.Fatal(err)
	}
	e.offered, _ = filepath.EvalSymlinks(e.offered)
	e.user, _ = filepath.EvalSymlinks(e.user)
	t.Setenv("BELAI_HOME", e.home)
	t.Setenv("HOME", e.user)
	t.Setenv("BELAI_WORKTREES_DIR", filepath.Join(e.user, "worktrees"))
	rec, err := audit.Open(e.home, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	audit.SetDefault(rec)
	t.Cleanup(func() { audit.SetDefault(nil); rec.Close() })
	e.rec = rec
	look := func(name string) (string, error) {
		if filepath.IsAbs(name) {
			return name, nil
		}
		p := filepath.Join(e.bin, name)
		if _, err := os.Stat(p); err != nil {
			return "", exec.ErrNotFound
		}
		return p, nil
	}
	e.o = Options{
		Home: e.home, UserHome: e.user, Level: level, Version: "1.2.3", Exe: filepath.Join(e.bin, "belai"),
		LookPath: look, GOOS: "linux", GOARCH: "amd64",
		Prober:   &products.Prober{Run: products.ExecRunner, LookPath: look, Home: e.user, GOOS: "linux", Getenv: func(string) string { return "" }, Now: time.Now},
		Stopped:  func() (bool, string) { return e.stopped, "incident" },
		Blackout: func() bool { return e.blackout },
		Providers: func() []*nodev1.ProviderFact {
			return []*nodev1.ProviderFact{{Provider: "anthropic", KeyPresent: true}}
		},
		Hooks: Hooks{
			Dirs:   func() []string { return []string{e.offered} },
			Limits: func() Limits { return Limits{MaxSessions: 3, MaxWorkers: 4} },
			SetProjectPrefs: func(dir string, set map[string]any, unset []string) (string, string) {
				// rc's setProjectPrefs is the real one (rc/hostmgmt_test.go);
				// this records the call and writes the same file.
				var why string
				err := config.MutateProjectPrefs(dir, func(p *config.ProjectPrefs) {
					for k, v := range set {
						if err := p.SetFlat(k, v); err != nil {
							why = err.Error()
						}
					}
					for _, k := range unset {
						_ = p.UnsetFlat(k)
					}
				})
				if err != nil {
					why = err.Error()
				}
				e.prefs = append(e.prefs, dir)
				return "set", why
			},
			Drain:  func(_ context.Context, d time.Duration) bool { e.drained = d; return false },
			Reexec: func() error { e.reexec++; return nil },
		},
	}
	for _, f := range mut {
		f(&e.o)
	}
	e.m, err = New(e.o)
	if err != nil {
		t.Fatal(err)
	}
	e.m.t = e.ft
	return e
}

// act sends one action and runs it, returning its updates.
func (e *env) act(a *nodev1.HostAction) []*nodev1.HostActionUpdate {
	e.t.Helper()
	if a.Id == "" {
		e.n++
		a.Id = fmt.Sprintf("act-%d", e.n)
	}
	if a.Class == "" {
		a.Class = string(ClassOf(a.Kind))
	}
	if a.Origin == nil {
		a.Origin = &nodev1.HostOrigin{Actor: "owner", Surface: "fleet.host/config"}
	}
	e.m.Receive(context.Background(), a)
	e.m.RunPending(context.Background())
	return e.ft.of(a.Id)
}

func last(us []*nodev1.HostActionUpdate) *nodev1.HostActionUpdate {
	if len(us) == 0 {
		return &nodev1.HostActionUpdate{}
	}
	return us[len(us)-1]
}

func (e *env) wantRefused(us []*nodev1.HostActionUpdate, sub string) {
	e.t.Helper()
	u := last(us)
	if u.GetState() != stateRefused || !strings.Contains(u.GetError(), sub) {
		e.t.Fatalf("got %s %q, want refused with %q", u.GetState(), u.GetError(), sub)
	}
	if len(us) != 1 {
		e.t.Fatalf("a refusal sent %d updates", len(us))
	}
}

// events reads the audit stream.
func (e *env) events() []audit.Event {
	e.t.Helper()
	f, err := os.Open(e.rec.Path())
	if err != nil {
		e.t.Fatal(err)
	}
	defer f.Close()
	var out []audit.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var ev audit.Event
		if json.Unmarshal(sc.Bytes(), &ev) == nil {
			out = append(out, ev)
		}
	}
	return out
}

func (e *env) auditFor(id string) []audit.Event {
	var out []audit.Event
	for _, ev := range e.events() {
		if ev.Data["action"] == id {
			out = append(out, ev)
		}
	}
	return out
}

func (e *env) stub(name, body string) {
	e.t.Helper()
	script := "#!/bin/sh\ncase \"$*\" in\n" + body + "\n*) echo \"unknown: $*\" >&2; exit 1;;\nesac\n"
	if err := os.WriteFile(filepath.Join(e.bin, name), []byte(script), 0o755); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) writeSettings(s string) string {
	e.t.Helper()
	p := filepath.Join(e.home, "settings.json")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		e.t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestUnknownKindRefusedAndAuditedWithOrigin(t *testing.T) {
	e := newEnv(t, LevelProvision)
	us := e.act(&nodev1.HostAction{Kind: "format_disk", Class: "provision",
		Origin: &nodev1.HostOrigin{Actor: "owner", Surface: "fleet.host/provision", PlanId: "p1"}, PlanRunId: "r1", Step: 2})
	e.wantRefused(us, "does not run that kind")
	evs := e.auditFor(us[0].GetActionId())
	if len(evs) != 1 || evs[0].Kind != string(audit.HostActionRefused) || evs[0].Actor != "owner" ||
		evs[0].Data["surface"] != "fleet.host/provision" || evs[0].Data["plan"] != "p1" || evs[0].Data["plan_run"] != "r1" || evs[0].Data["step"] != "2" {
		t.Fatalf("audit = %+v", evs)
	}
}

func TestClassMismatchRefused(t *testing.T) {
	e := newEnv(t, LevelProvision)
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "config_set", Class: "read", Params: map[string]string{"key": "model", "value": "m"}}), "class mismatch")
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "rc_restart", Class: "config"}), "class mismatch")
}

func TestManageOffRefusesEverything(t *testing.T) {
	e := newEnv(t, LevelOff)
	for _, k := range Kinds() {
		us := e.act(&nodev1.HostAction{Kind: k})
		e.wantRefused(us, "host management is off")
		if len(e.auditFor(us[0].GetActionId())) != 1 {
			t.Fatalf("%s: no audit line", k)
		}
	}
}

func TestReadGateRefusesConfigAndProvision(t *testing.T) {
	e := newEnv(t, LevelRead)
	sha := e.writeSettings(`{}`)
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "config_set", IfMatch: sha, Params: map[string]string{"key": "agents.max_workers", "value": "2"}}), "the host gate is read")
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "rc_restart"}), "the host gate is read")
	if u := last(e.act(&nodev1.HostAction{Kind: "log_tail"})); u.GetState() != stateDone {
		t.Fatalf("log_tail = %s %s", u.GetState(), u.GetError())
	}
	c := newEnv(t, LevelConfig)
	c.wantRefused(c.act(&nodev1.HostAction{Kind: "product_probe", Class: "provision", Params: map[string]string{"product": "cli"}}), "class mismatch")
	c.wantRefused(c.act(&nodev1.HostAction{Kind: "belai_upgrade"}), "the host gate is config")
}

func TestKillSwitchRefusesMutatingAndUnaskedReads(t *testing.T) {
	e := newEnv(t, LevelProvision)
	sha := e.writeSettings(`{}`)
	e.stopped = true
	us := e.act(&nodev1.HostAction{Kind: "config_set", IfMatch: sha, Params: map[string]string{"key": "agents.max_workers", "value": "2"}})
	e.wantRefused(us, "the factory is stopped")
	if ev := e.auditFor(us[0].GetActionId()); len(ev) != 1 || ev[0].Data["control"] != "stopped" {
		t.Fatalf("audit = %+v", ev)
	}
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "product_install", DryRun: true, Params: map[string]string{"product": "cli"}}), "the factory is stopped")
	// A read from a plan or a workflow is refused; one a person clicked runs.
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "log_tail", Origin: &nodev1.HostOrigin{Actor: "owner", PlanId: "p1"}}), "the factory is stopped")
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "log_tail", Origin: &nodev1.HostOrigin{Actor: "workflow"}}), "the factory is stopped")
	if u := last(e.act(&nodev1.HostAction{Kind: "log_tail"})); u.GetState() != stateDone {
		t.Fatalf("a person's read under stop = %s %s", u.GetState(), u.GetError())
	}
}

func TestBlackoutRefusesA2AConfig(t *testing.T) {
	e := newEnv(t, LevelConfig)
	sha := e.writeSettings(`{}`)
	e.blackout = true
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "config_set", IfMatch: sha, Params: map[string]string{"key": "a2a.enabled", "value": "false"}}), "A2A blackout")
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "config_set", IfMatch: sha, Params: map[string]string{"key": "sync.remote_prompts", "value": "false"}}), "A2A blackout")
	if u := last(e.act(&nodev1.HostAction{Kind: "config_set", IfMatch: sha, Params: map[string]string{"key": "agents.max_workers", "value": "2"}})); u.GetState() != stateDone {
		t.Fatalf("an unrelated key under blackout = %s %s", u.GetState(), u.GetError())
	}
}

func TestRemoteKeysTightenOnly(t *testing.T) {
	e := newEnv(t, LevelConfig)
	set := func(key, value string) *nodev1.HostActionUpdate {
		sha, _, _ := settingsSHA256()
		return last(e.act(&nodev1.HostAction{Kind: "config_set", IfMatch: sha, Params: map[string]string{"key": key, "value": value}}))
	}
	e.writeSettings(`{}`)
	if u := set("guardrails", "false"); u.GetState() != stateRefused || !strings.Contains(u.GetError(), "tighten only") {
		t.Fatalf("loosen guardrails = %s %s", u.GetState(), u.GetError())
	}
	if u := set("sandbox.mode", "required"); u.GetState() != stateDone {
		t.Fatalf("tighten sandbox = %s %s", u.GetState(), u.GetError())
	}
	if u := set("sandbox.mode", "auto"); u.GetState() != stateRefused {
		t.Fatalf("loosen sandbox = %s", u.GetState())
	}
	if u := set("agents.max_workers", "65"); u.GetState() != stateRefused {
		t.Fatalf("out of range = %s", u.GetState())
	}
	g := newEnv(t, LevelConfig, func(o *Options) { o.Gates.AllowGuardrailsOff = true })
	g.writeSettings(`{"a2a":{"enabled":false},"guardrails":true}`)
	sha, _, _ := settingsSHA256()
	if u := last(g.act(&nodev1.HostAction{Kind: "config_set", IfMatch: sha, Params: map[string]string{"key": "guardrails", "value": "false"}})); u.GetState() != stateDone {
		t.Fatalf("loosen with --web-allow-guardrails-off = %s %s", u.GetState(), u.GetError())
	}
	sha, _, _ = settingsSHA256()
	if u := last(g.act(&nodev1.HostAction{Kind: "config_set", IfMatch: sha, Params: map[string]string{"key": "a2a.enabled", "value": "true"}})); u.GetState() != stateRefused {
		t.Fatalf("a2a loosened = %s", u.GetState())
	}
}

func TestConfigSetIfMatchBackupAndNeverRemote(t *testing.T) {
	e := newEnv(t, LevelConfig)
	sha := e.writeSettings(`{"model":"a"}`)
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "config_set", IfMatch: strings.Repeat("0", 64), Params: map[string]string{"key": "model", "value": "b"}}), "settings changed on host")
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "config_set", Params: map[string]string{"key": "model", "value": "b"}}), "if_match")
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "config_set", IfMatch: sha, Params: map[string]string{"key": "providers.anthropic.base_url", "value": "https://evil.example"}}), "never changed remotely")
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "config_set", IfMatch: sha, Params: map[string]string{"key": "hooks.allowed_programs", "value": "sh"}}), "never changed remotely")
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "config_set", IfMatch: sha, Params: map[string]string{"key": "update_check", "value": "false"}}), "never changed remotely")
	us := e.act(&nodev1.HostAction{Id: "set-1", Kind: "config_set", IfMatch: sha, Params: map[string]string{"key": "model", "value": "b"}})
	if u := last(us); u.GetState() != stateDone {
		t.Fatalf("config_set = %s %s", u.GetState(), u.GetError())
	}
	s, _ := config.LoadGlobal()
	if s.Model != "b" {
		t.Fatalf("model = %q", s.Model)
	}
	if b, err := os.ReadFile(filepath.Join(e.home, "settings.json.bak.set-1")); err != nil || string(b) != `{"model":"a"}` {
		t.Fatalf("backup = %q %v", b, err)
	}
	if us[0].GetState() != stateAccepted {
		t.Fatal("the first update is not the ack")
	}
}

func TestParamsOutsideRootsRefused(t *testing.T) {
	e := newEnv(t, LevelConfig, func(o *Options) { o.Gates.WebProjectSettings = true })
	outside := t.TempDir()
	link := filepath.Join(e.offered, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	set := func(path string) []*nodev1.HostActionUpdate {
		return e.act(&nodev1.HostAction{Kind: "project_prefs_set", Params: map[string]string{"path": path, "key": "caveman", "value": "true"}})
	}
	e.wantRefused(set(e.offered+"/../../etc"), "may not hold ..")
	e.wantRefused(set(link), "not a directory this host offers")
	e.wantRefused(set(outside), "not a directory this host offers")
	e.wantRefused(set("relative/dir"), "absolute")
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "project_prefs_set", Params: map[string]string{"path": e.offered, "key": "caveman", "value": "true", "argv": "x"}}), "unknown parameter")
	if u := last(set(e.offered)); u.GetState() != stateDone {
		t.Fatalf("inside = %s %s", u.GetState(), u.GetError())
	}
	if len(e.prefs) != 1 || e.prefs[0] != e.offered {
		t.Fatalf("prefs hook calls = %v", e.prefs)
	}
	// Without --web-project-settings the write is refused.
	n := newEnv(t, LevelConfig)
	n.wantRefused(n.act(&nodev1.HostAction{Kind: "project_prefs_set", Params: map[string]string{"path": n.offered, "key": "caveman", "value": "true"}}), "--web-project-settings")
	// repo_trust only under workspace_dirs.
	e.writeSettings(`{"workspace_dirs":["~/ws"]}`)
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "repo_trust", Params: map[string]string{"path": e.offered}}), "under workspace_dirs")
}

func TestAgentsSetWritesTheRepoSwitch(t *testing.T) {
	e := newEnv(t, LevelConfig, func(o *Options) { o.Gates.WebProjectSettings = true })
	us := e.act(&nodev1.HostAction{Kind: "agents_set", Params: map[string]string{"path": e.offered, "profile": "belai:builder", "state": "off"}})
	if u := last(us); u.GetState() != stateDone {
		t.Fatalf("agents_set = %s %s", u.GetState(), u.GetError())
	}
	if !config.BuiltinAgentOff(e.offered, "belai:builder") {
		t.Fatal("the switch is not off")
	}
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "agents_set", Params: map[string]string{"path": e.offered, "profile": "belai:nope", "state": "off"}}), "no built-in agent profile")
	inv := e.m.Inventory(context.Background(), false)
	var found bool
	for _, r := range inv.Repos {
		for _, a := range r.Agents {
			found = found || (a.Id == "belai:builder" && a.State == "off")
		}
	}
	if !found {
		t.Fatal("the inventory does not report the switch")
	}
}

const canary = "sk-ant-CANARY-0123456789abcdefghijklmnop"

func TestSecretCanaryNeverLeaves(t *testing.T) {
	e := newEnv(t, LevelProvision)
	t.Setenv("ANTHROPIC_API_KEY", canary)
	e.writeSettings(`{"providers":{"anthropic":{"api_key":"` + canary + `"}},"mcp":{"servers":{"x":{"command":"x","env":{"TOKEN":"` + canary + `"},"headers":{"Authorization":"Bearer ` + canary + `"}}}}}`)
	credDir := filepath.Join(e.user, ".vulnetix")
	_ = os.MkdirAll(credDir, 0o700)
	_ = os.WriteFile(filepath.Join(credDir, "credentials.json"), []byte(`{"apiKey":"`+canary+`"}`), 0o600)
	vaultenv.Default.Conceal("ANTHROPIC_API_KEY", canary)
	_ = os.MkdirAll(filepath.Join(e.home, "rc"), 0o700)
	_ = os.WriteFile(filepath.Join(e.home, "rc", "rc.log"), []byte("12:00:00 started\n12:00:01 key "+canary+" seen\n"), 0o600)

	inv := e.m.Inventory(context.Background(), true)
	b, _ := protojson.Marshal(inv)
	if strings.Contains(string(b), canary) || strings.Contains(string(b), "CANARY") {
		t.Fatal("the inventory carries the canary")
	}
	if len(inv.Mcp) != 2 || inv.Mcp[1].Name != "x" || inv.Mcp[1].KeysBound[0] != "TOKEN" {
		t.Fatalf("mcp = %+v", inv.Mcp)
	}
	get := last(e.act(&nodev1.HostAction{Kind: "config_get", Params: map[string]string{"scope": "global"}}))
	if get.GetState() != stateDone || strings.Contains(get.GetResultJson(), "CANARY") {
		t.Fatalf("config_get leaked or failed: %s %s", get.GetState(), get.GetResultJson())
	}
	if !strings.Contains(get.GetResultJson(), `"present":true`) {
		t.Fatalf("config_get does not mark the key present: %s", get.GetResultJson())
	}
	tail := last(e.act(&nodev1.HostAction{Kind: "log_tail", Params: map[string]string{"lines": "10"}}))
	if tail.GetState() != stateDone || strings.Contains(tail.GetResultJson(), "CANARY") || !strings.Contains(tail.GetResultJson(), "[vault:ANTHROPIC_API_KEY]") {
		t.Fatalf("log_tail = %s", tail.GetResultJson())
	}
	data, _ := os.ReadFile(e.rec.Path())
	if strings.Contains(string(data), "CANARY") {
		t.Fatal("the audit log carries the canary")
	}
}

func TestProductAuthGrantOnlyInTheChild(t *testing.T) {
	e := newEnv(t, LevelProvision)
	envFile := filepath.Join(t.TempDir(), "env")
	e.stub("vulnetix", `"auth login --noninteractive --store keyring") env > `+envFile+`; echo "logged in with $VULNETIX_API_KEY";;`)
	key := "vk-CANARY-abcdefghijklmnopqrstuvwxyz"
	org := "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	vault := &nodev1.VaultGrant{GrantId: "g1", ExpiresAtMs: time.Now().Add(time.Minute).UnixMilli(), Secrets: []*nodev1.VaultSecret{
		{Provider: "vulnetix", Env: "VULNETIX_API_KEY", Value: key}, {Provider: "vulnetix", Env: "VULNETIX_ORG_ID", Value: org}}}
	dry := last(e.act(&nodev1.HostAction{Kind: "product_auth", DryRun: true, Params: map[string]string{"product": "cli"}}))
	if dry.GetState() != stateDone || strings.Contains(dry.GetPreviewJson(), "CANARY") {
		t.Fatalf("dry run = %s %s", dry.GetState(), dry.GetPreviewJson())
	}
	us := e.act(&nodev1.HostAction{Id: "auth-1", Kind: "product_auth", Vault: vault, PreviewSha256: dry.GetPreviewSha256(), Params: map[string]string{"product": "cli"}})
	if u := last(us); u.GetState() != stateDone {
		t.Fatalf("product_auth = %s %s", u.GetState(), u.GetError())
	}
	child, _ := os.ReadFile(envFile)
	if !strings.Contains(string(child), "VULNETIX_API_KEY="+key) || !strings.Contains(string(child), "VULNETIX_ORG_ID="+org) {
		t.Fatal("the child did not get the grant")
	}
	if os.Getenv("VULNETIX_API_KEY") != "" {
		t.Fatal("the grant reached this process's environment")
	}
	for _, u := range us {
		b, _ := protojson.Marshal(u)
		if strings.Contains(string(b), "CANARY") {
			t.Fatalf("an update carries the key: %s", b)
		}
	}
	rec, _ := os.ReadFile(filepath.Join(e.home, "rc", "hostactions", "auth-1.json"))
	if strings.Contains(string(rec), "CANARY") || strings.Contains(string(rec), `"vault":`) {
		t.Fatal("the queue record carries the grant")
	}
	// Without a grant it hands off to a person with a browser.
	nb := last(e.act(&nodev1.HostAction{Kind: "product_auth", PreviewSha256: dry.GetPreviewSha256(), Params: map[string]string{"product": "cli"}}))
	if nb.GetState() != stateNeedsHuman || nb.GetHandoffReason() != "needs_browser" || nb.GetHandoffCommand() != "vulnetix auth login" {
		t.Fatalf("no grant = %+v", nb)
	}
}

func TestRecipeDryRunsAreDeterministic(t *testing.T) {
	e := newEnv(t, LevelProvision)
	e.stub("vulnetix", `"--disable-memory package-firewall npm") echo ok;;
"--disable-memory package-firewall pypi") echo ok;;
"--disable-memory package-firewall uninstall --except npm,pypi") echo ok;;`)
	params := map[string]string{"product": "package_firewall", "on": "pypi,npm"}
	a := last(e.act(&nodev1.HostAction{Kind: "product_configure", DryRun: true, Params: params}))
	b := last(e.act(&nodev1.HostAction{Kind: "product_configure", DryRun: true, Params: map[string]string{"product": "package_firewall", "on": "npm,pypi"}}))
	if a.GetPreviewSha256() == "" || a.GetPreviewSha256() != b.GetPreviewSha256() || a.GetPreviewJson() != b.GetPreviewJson() {
		t.Fatalf("previews differ:\n%s\n%s", a.GetPreviewJson(), b.GetPreviewJson())
	}
	if strings.Contains(a.GetPreviewJson(), e.user) {
		t.Fatalf("the preview is not home-relative: %s", a.GetPreviewJson())
	}
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "product_configure", Params: params}), "needs a preview")
	// A file the plan pins changed: the confirmed preview is stale.
	_ = os.WriteFile(filepath.Join(e.user, ".npmrc"), []byte("x"), 0o600)
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "product_configure", PreviewSha256: a.GetPreviewSha256(), Params: params}), "preview stale")
	fresh := last(e.act(&nodev1.HostAction{Kind: "product_configure", DryRun: true, Params: params}))
	run := e.act(&nodev1.HostAction{Kind: "product_configure", PreviewSha256: fresh.GetPreviewSha256(), Params: params})
	if u := last(run); u.GetState() != stateDone {
		t.Fatalf("configure = %s %s", u.GetState(), u.GetError())
	}
	// Ecosystems without a writer are refused.
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "product_configure", DryRun: true, Params: map[string]string{"product": "package_firewall", "on": "oci"}}), "cannot configure")
	f := newEnv(t, LevelProvision)
	for _, k := range []map[string]string{{"product": "sensor", "version": "v4.24.35", "profile": "0b6f2c1e-6a1d-4c5e-9f0a-3d2b1c4e5f60"}, {"product": "cli", "method": "direct", "version": "v4.24.37"}} {
		x := last(f.act(&nodev1.HostAction{Kind: "product_install", DryRun: true, Params: k}))
		y := last(f.act(&nodev1.HostAction{Kind: "product_install", DryRun: true, Params: k}))
		if x.GetState() != stateDone || x.GetPreviewSha256() != y.GetPreviewSha256() {
			t.Fatalf("install %v: %s %s / %s", k, x.GetState(), x.GetError(), y.GetPreviewSha256())
		}
	}
}

func TestSensorInstallHandsOffForRoot(t *testing.T) {
	e := newEnv(t, LevelProvision)
	e.stub("vulnetix-sensor", `"--version") echo 0.9.3;;`)
	p := map[string]string{"product": "sensor", "profile": "0b6f2c1e-6a1d-4c5e-9f0a-3d2b1c4e5f60"}
	dry := last(e.act(&nodev1.HostAction{Kind: "product_install", DryRun: true, Params: p}))
	us := e.act(&nodev1.HostAction{Kind: "product_install", PreviewSha256: dry.GetPreviewSha256(), Params: p})
	u := last(us)
	if u.GetState() != stateNeedsHuman || u.GetHandoffReason() != "needs_root" || u.GetHandoffCommand() != "sudo vulnetix-sensor enroll --from-cli-login --profile 0b6f2c1e-6a1d-4c5e-9f0a-3d2b1c4e5f60" {
		t.Fatalf("sensor install = %+v", u)
	}
	if ev := e.auditFor(u.GetActionId()); ev[len(ev)-1].Kind != string(audit.HostActionNeedsHuman) || ev[len(ev)-1].Data["reason"] != "needs_root" {
		t.Fatalf("audit = %+v", ev)
	}
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "product_install", DryRun: true, Params: map[string]string{"product": "sensor", "profile": "p 1"}}), "profile")
}

func TestDirectCLIInstallVerifiesTheChecksum(t *testing.T) {
	asset := []byte("#!/bin/sh\necho 4.24.37\n")
	sum := sha256.Sum256(asset)
	good := hex.EncodeToString(sum[:])
	sums := good
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch filepath.Base(r.URL.Path) {
		case "checksums.txt":
			fmt.Fprintf(w, "%s  vulnetix-linux-amd64\n", sums)
		case "vulnetix-linux-amd64":
			_, _ = w.Write(asset)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	e := newEnv(t, LevelProvision, func(o *Options) { o.CLIReleases = srv.URL })
	p := map[string]string{"product": "cli", "method": "direct", "version": "v4.24.37"}
	dry := last(e.act(&nodev1.HostAction{Kind: "product_install", DryRun: true, Params: p}))
	sums = strings.Repeat("0", 64)
	bad := last(e.act(&nodev1.HostAction{Kind: "product_install", PreviewSha256: dry.GetPreviewSha256(), Params: p}))
	if bad.GetState() != stateFailed || !strings.Contains(bad.GetError(), "checksum mismatch") {
		t.Fatalf("bad checksum = %s %s", bad.GetState(), bad.GetError())
	}
	target := filepath.Join(e.user, ".local", "bin", "vulnetix")
	if _, err := os.Stat(target); err == nil {
		t.Fatal("a binary with a bad checksum was installed")
	}
	sums = good
	us := e.act(&nodev1.HostAction{Kind: "product_install", PreviewSha256: dry.GetPreviewSha256(), Params: p})
	if u := last(us); u.GetState() != stateDone {
		t.Fatalf("install = %s %s", u.GetState(), u.GetError())
	}
	var lines []string
	for _, u := range us {
		lines = append(lines, u.GetLines()...)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "provenance "+srv.URL+"/v4.24.37/vulnetix-linux-amd64 sha256 "+good) {
		t.Fatalf("lines = %v", lines)
	}
	if b, _ := os.ReadFile(target); string(b) != string(asset) {
		t.Fatal("the binary was not written")
	}
}

func TestReplayedActionIsNotRunTwice(t *testing.T) {
	e := newEnv(t, LevelProvision)
	count := filepath.Join(t.TempDir(), "count")
	e.stub("tool", `"go") echo x >> `+count+`;;`)
	e.o.Shell = true
	e.m.o.Shell = true
	argv := `["tool","go"]`
	dry := last(e.act(&nodev1.HostAction{Kind: "shell_exec", DryRun: true, Params: map[string]string{"argv_json": argv}}))
	a := &nodev1.HostAction{Id: "shell-1", Kind: "shell_exec", Class: "shell", PreviewSha256: dry.GetPreviewSha256(),
		Params: map[string]string{"argv_json": argv}, Origin: &nodev1.HostOrigin{Actor: "owner"}}
	e.act(a)
	e.act(a)
	// A restart: a new manager on the same home answers from the queue.
	m2, err := New(e.o)
	if err != nil {
		t.Fatal(err)
	}
	m2.t = e.ft
	m2.Receive(context.Background(), a)
	m2.RunPending(context.Background())
	if b, _ := os.ReadFile(count); strings.Count(string(b), "x") != 1 {
		t.Fatalf("ran %d times", strings.Count(string(b), "x"))
	}
	us := e.ft.of("shell-1")
	if len(us) < 3 || us[0].GetSeq() != 1 || last(us).GetState() != stateDone {
		t.Fatalf("updates = %v", us)
	}
}

func TestUndeliveredUpdatesAreResent(t *testing.T) {
	e := newEnv(t, LevelRead)
	e.ft.fail = true
	e.act(&nodev1.HostAction{Id: "r-1", Kind: "preflight"})
	e.ft.fail = false
	e.m.flushUnsent(context.Background())
	us := e.ft.of("r-1")
	if len(us) != 2 || us[0].GetSeq() != 1 || us[1].GetSeq() != 2 {
		t.Fatalf("resent = %v", us)
	}
}

func TestRestartDrainsThenReexecs(t *testing.T) {
	e := newEnv(t, LevelProvision)
	dry := last(e.act(&nodev1.HostAction{Kind: "rc_restart", DryRun: true, Params: map[string]string{"force_after_s": "30"}}))
	us := e.act(&nodev1.HostAction{Id: "restart-1", Kind: "rc_restart", PreviewSha256: dry.GetPreviewSha256(), Params: map[string]string{"force_after_s": "30"}})
	if e.drained != 30*time.Second || e.reexec != 1 {
		t.Fatalf("drain %v, reexec %d", e.drained, e.reexec)
	}
	steps := []string{}
	for _, u := range us {
		steps = append(steps, u.GetState()+"/"+u.GetStep())
	}
	if strings.Join(steps, " ") != "accepted/rc_restart running/drain running/reexec done/rc_restart" {
		t.Fatalf("updates = %v", steps)
	}
	// A real re-exec never returns: the new process finds the action
	// running and settles it.
	r := &record{ID: "restart-2", Kind: "rc_restart", State: stateRunning, Received: time.Now(), Action: []byte(`{"id":"restart-2","kind":"rc_restart"}`)}
	_ = e.m.q.put(r)
	if _, err := New(e.o); err != nil {
		t.Fatal(err)
	}
	got, _ := e.m.q.get("restart-2")
	if got.State != stateDone {
		t.Fatalf("restart left %s", got.State)
	}
}

func TestShellExecGates(t *testing.T) {
	e := newEnv(t, LevelProvision)
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "shell_exec", DryRun: true, Params: map[string]string{"argv_json": `["ls"]`}}), "--keleustes-shell")
	c := newEnv(t, LevelConfig, func(o *Options) { o.Shell = true })
	c.wantRefused(c.act(&nodev1.HostAction{Kind: "shell_exec", DryRun: true, Params: map[string]string{"argv_json": `["ls"]`}}), "needs provision")
	if has(e.m.advertised(), "shell_exec") || !has(c.m.advertised(), "shell_exec") {
		t.Fatal("shell_exec is advertised without --keleustes-shell")
	}
}

func TestInventoryFacts(t *testing.T) {
	e := newEnv(t, LevelConfig)
	e.stub("git", `"--version") echo "git version 2.47.1";;`)
	inv := e.m.Inventory(context.Background(), false)
	if inv.Belai.Version != "1.2.3" || inv.Belai.Root != "~/../belai" && !strings.HasSuffix(inv.Belai.Root, "belai") {
		t.Fatalf("belai = %+v", inv.Belai)
	}
	if inv.Manage.ManageLevel != "config" || len(inv.Manage.HostActions) == 0 || inv.Limits.MaxWorkers != 4 {
		t.Fatalf("manage = %+v limits = %+v", inv.Manage, inv.Limits)
	}
	var git *nodev1.ToolFact
	for _, f := range inv.Tools {
		if f.Name == "git" {
			git = f
		}
	}
	if git == nil || !git.Ok || git.Version != "2.47.1" {
		t.Fatalf("git = %+v", git)
	}
	if len(inv.Repos) != 1 || inv.Repos[0].Path != "~/src/api" {
		t.Fatalf("repos = %+v", inv.Repos)
	}
	if len(inv.Products) != 4 || len(inv.BuiltinAgents) == 0 {
		t.Fatalf("products %d, builtins %d", len(inv.Products), len(inv.BuiltinAgents))
	}
}

// restartedWith runs recover for a running restart whose marker expects
// `expect`, as the process the re-exec started.
func restartedWith(t *testing.T, e *env, id, expect string, withPrev bool) (*record, string) {
	t.Helper()
	exe := e.o.Exe
	if err := os.WriteFile(exe, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	mk := restartMarker{ActionID: id, Expect: expect, Exe: exe}
	if withPrev {
		mk.Prev = filepath.Join(filepath.Dir(exe), "belai.prev")
		if err := os.WriteFile(mk.Prev, []byte("old"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.m.writeMarker(mk); err != nil {
		t.Fatal(err)
	}
	_ = e.m.q.put(&record{ID: id, Kind: "rc_restart", State: stateRunning, Received: time.Now(),
		Action: []byte(`{"id":"` + id + `","kind":"rc_restart"}`)})
	m, err := New(e.o)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := m.q.get(id)
	var u nodev1.HostActionUpdate
	if n := len(got.Updates); n > 0 {
		_ = protojson.Unmarshal(got.Updates[n-1].Update, &u)
	}
	if _, err := os.Stat(m.markerPath()); !os.IsNotExist(err) {
		t.Fatalf("marker left behind: %v", err)
	}
	b, _ := os.ReadFile(exe)
	return got, u.GetError() + "|" + string(b)
}

func TestRestartExpectedVersionIsDone(t *testing.T) {
	e := newEnv(t, LevelProvision)
	got, out := restartedWith(t, e, "restart-ok", "v1.2.3", true)
	if got.State != stateDone || !strings.HasSuffix(out, "|new") {
		t.Fatalf("state %s, %s", got.State, out)
	}
}

func TestRestartVersionMismatchRollsBack(t *testing.T) {
	e := newEnv(t, LevelProvision)
	before := e.reexec
	got, out := restartedWith(t, e, "restart-bad", "v9.9.9", true)
	if got.State != stateFailed || !strings.Contains(out, "version mismatch") ||
		!strings.Contains(out, "rolled back to belai.prev") || !strings.HasSuffix(out, "|old") {
		t.Fatalf("state %s, %s", got.State, out)
	}
	if e.reexec != before+1 {
		t.Fatalf("re-exec into the restored binary: %d", e.reexec-before)
	}
}

func TestRestartMismatchWithoutBackupFails(t *testing.T) {
	e := newEnv(t, LevelProvision)
	got, out := restartedWith(t, e, "restart-nobak", "v9.9.9", false)
	if got.State != stateFailed || !strings.Contains(out, "no belai.prev") || !strings.HasSuffix(out, "|new") {
		t.Fatalf("state %s, %s", got.State, out)
	}
}

func TestRestartTakesExpectVersion(t *testing.T) {
	e := newEnv(t, LevelProvision)
	dry := last(e.act(&nodev1.HostAction{Kind: "rc_restart", DryRun: true, Params: map[string]string{"expect_version": "1.2.4"}}))
	if !strings.Contains(dry.GetPreviewJson(), `"expect_version":"v1.2.4"`) {
		t.Fatalf("preview = %s", dry.GetPreviewJson())
	}
	e.wantRefused(e.act(&nodev1.HostAction{Kind: "rc_restart", DryRun: true, Params: map[string]string{"expect_version": "nope; rm"}}), "release version")
}

// A SigV4 pair signs the CLI in the same way, from the child's environment
// only; half a pair (or one of each) still hands off to a person.
func TestProductAuthSigV4Grant(t *testing.T) {
	e := newEnv(t, LevelProvision)
	envFile := filepath.Join(t.TempDir(), "env")
	e.stub("vulnetix", `"auth login --noninteractive --store keyring") env > `+envFile+`; echo "logged in";;`)
	secret := "sv4-CANARY-abcdefghijklmnopqrstuvwxyz"
	org := "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	grant := func(id string, s ...*nodev1.VaultSecret) *nodev1.VaultGrant {
		return &nodev1.VaultGrant{GrantId: id, ExpiresAtMs: time.Now().Add(time.Minute).UnixMilli(), Secrets: s}
	}
	dry := last(e.act(&nodev1.HostAction{Kind: "product_auth", DryRun: true, Params: map[string]string{"product": "cli"}}))
	run := func(id string, g *nodev1.VaultGrant) *nodev1.HostActionUpdate {
		return last(e.act(&nodev1.HostAction{Id: id, Kind: "product_auth", Vault: g, PreviewSha256: dry.GetPreviewSha256(), Params: map[string]string{"product": "cli"}}))
	}
	half := run("auth-half", grant("g0",
		&nodev1.VaultSecret{Provider: "vulnetix", Env: "VVD_SECRET", Value: secret},
		&nodev1.VaultSecret{Provider: "vulnetix", Env: "VULNETIX_ORG_ID", Value: org}))
	if half.GetState() != stateNeedsHuman {
		t.Fatalf("a mixed half pair = %s, want a hand-off", half.GetState())
	}
	if u := run("auth-sigv4", grant("g1",
		&nodev1.VaultSecret{Provider: "vulnetix", Env: "VVD_ORG", Value: org},
		&nodev1.VaultSecret{Provider: "vulnetix", Env: "VVD_SECRET", Value: secret})); u.GetState() != stateDone {
		t.Fatalf("product_auth = %s %s", u.GetState(), u.GetError())
	}
	child, _ := os.ReadFile(envFile)
	if !strings.Contains(string(child), "VVD_SECRET="+secret) || !strings.Contains(string(child), "VVD_ORG="+org) {
		t.Fatal("the child did not get the SigV4 grant")
	}
	if os.Getenv("VVD_SECRET") != "" {
		t.Fatal("the grant reached this process's environment")
	}
	data, _ := os.ReadFile(e.rec.Path())
	if strings.Contains(string(data), "CANARY") {
		t.Fatal("the audit log carries the secret")
	}
}
