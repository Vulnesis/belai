package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/vulnetix/belai/internal/a2a"
	"github.com/vulnetix/belai/internal/a2alink"
	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/harness"
	"github.com/vulnetix/belai/internal/harnessdetect"
	"github.com/vulnetix/belai/internal/harnessrun"
	"github.com/vulnetix/belai/internal/headless"
	"github.com/vulnetix/belai/internal/httpclient"
	"github.com/vulnetix/belai/internal/posture"
	"github.com/vulnetix/belai/internal/rolemanager"
	"github.com/vulnetix/belai/internal/run"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/sessionsync"
	"github.com/vulnetix/belai/internal/trustgate"
	"github.com/vulnetix/belai/internal/version"
)

// runRCHarnessCLI implements the hidden `belai rc-harness`: one third-party
// harness (Claude Code, Codex, ...) run in its own interactive TUI on a
// pseudo-terminal, with prompts typed into it and its native transcript
// mirrored to Keleustes (docs/harness-sessions.md). The rc daemon starts it;
// the first prompt arrives on stdin and a vault grant, if any, on the
// descriptor GrantFDEnv names.
func runRCHarnessCLI(ctx context.Context, args []string, stdin io.Reader, stderr io.Writer) int {
	fs := flag.NewFlagSet("rc-harness", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dispatch := fs.String("dispatch", "", "the dispatch id")
	sid := fs.String("session-id", "", "the belai session id")
	id := fs.String("harness", "", "the registry id of the harness")
	mode := fs.String("mode", "", "one of the harness's own permission modes")
	model := fs.String("model", "", "a model id for the harness")
	resume := fs.String("resume", "", "a native session id to resume")
	keys := fs.String("keys", harnessrun.KeysOwnLogin, "vault key mode: own_login, handoff or always")
	controls := fs.Bool("controls", false, "take stop, interrupt and keys from Keleustes (belai rc --web-controls)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *sid == "" || *dispatch == "" || *id == "" {
		fmt.Fprintln(stderr, "belai rc-harness: -session-id, -dispatch and -harness are required (the rc daemon starts this)")
		return 2
	}
	if !harnessrun.ValidKeyMode(*keys) {
		fmt.Fprintf(stderr, "belai rc-harness: unknown key mode %q\n", *keys)
		return 2
	}
	prompt, err := io.ReadAll(io.LimitReader(stdin, sessionsync.MaxPromptBytes+1))
	if err != nil {
		fmt.Fprintln(stderr, "belai rc-harness: read prompt:", err)
		return 1
	}
	grant, err := readSessionGrant()
	if err != nil {
		fmt.Fprintln(stderr, "belai rc-harness:", err)
		return 1
	}
	var g harnessrun.Grant
	if grant != nil {
		g = grant
	}
	if err := runRCHarness(ctx, rcHarnessArgs{dispatch: *dispatch, sid: *sid, id: *id, mode: *mode, model: *model,
		resume: *resume, keys: *keys, controls: *controls, prompt: sessionsync.CleanPrompt(string(prompt)), grant: g}, stderr); err != nil {
		fmt.Fprintln(stderr, "belai rc-harness:", err)
		return 1
	}
	return 0
}

type rcHarnessArgs struct {
	dispatch, sid, id, mode, model, resume, keys, prompt string
	controls                                             bool
	grant                                                harnessrun.Grant
}

func runRCHarness(ctx context.Context, a rcHarnessArgs, stderr io.Writer) error {
	if !harnessrun.Supported {
		return errors.New("harness sessions are not supported on this platform")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	// The daemon checked the directory; check again where the work happens.
	st, err := trustgate.Check(cwd)
	if err != nil {
		return fmt.Errorf("check trust for %s: %w", cwd, err)
	}
	if !st.Trusted {
		return fmt.Errorf("%s is not trusted on this host", cwd)
	}
	h, ok := harness.ByID(a.id)
	if !ok || !h.Launch.MayLaunch() {
		return fmt.Errorf("%q is not a harness this host can run", a.id)
	}
	userHome, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	found := harnessdetect.Detect(ctx, harnessdetect.Options{Home: userHome, Path: os.Getenv("PATH"),
		LoginPath: harnessdetect.LoginPath(ctx), Registry: []harness.Harness{h}})
	if len(found) == 0 || !found[0].Launchable() || found[0].Launch == nil {
		return fmt.Errorf("%s is not installed and working on this host", h.Name)
	}
	// The profile as checked on this host: its version pin held and, for a
	// vendor-docs profile, the installed binary's help named its flags.
	h.Launch = found[0].Launch
	home, prof := rcKeleustes()
	if prof == nil {
		return errors.New("this host has not joined a Keleustes server")
	}
	be, err := factorylink.ActiveBackend(home, "harness")
	if err != nil {
		return err
	}
	defer be.Close()
	// Every harness start, prompt, key, hand-off and stop is a host audit fact,
	// uploaded to Keleustes's ledger like the daemon's own.
	if a, err := factorylink.ActiveAudit(home); err == nil {
		host := sessionsync.Host{Hostname: sessionsync.Hostname(), OS: runtime.GOOS, BelaiVersion: version.Version}
		if s := sessionsync.StartAuditOn(context.Background(), a, headless.HostID(), host, home); s != nil {
			defer s.Close(5 * time.Second)
		}
		defer a.Close()
	}
	eff, err := config.Resolve(cwd, os.Getenv, config.Settings{})
	if err != nil {
		return fmt.Errorf("load settings: %w", err)
	}
	settings := eff.Settings
	sqlite, _ := exec.LookPath("sqlite3")
	cfg := harnessrun.Config{
		SessionID: a.sid, DispatchID: a.dispatch, Harness: h, Bin: found[0].Path, Version: found[0].Version,
		Cwd: cwd, Home: userHome, Mode: a.mode, Model: a.model, Resume: a.resume, Prompt: a.prompt,
		HostID: headless.HostID(), Mirror: be, Controls: a.controls, RemotePrompts: settings.SyncRemotePromptsEnabled(),
		Stopped: func() (bool, string) { return factorylink.FactoryStopped(home) },
		KeyMode: a.keys, Grant: a.grant, SQLite: sqlite, Log: stderr,
		Admit:      rcHarnessAdmit(cwd, settings, stderr),
		Dir:        filepath.Join(home, "harness", a.sid),
		Ledger:     filepath.Join(home, "harness", "ledgers", a.sid+".jsonl"),
		TimingFile: filepath.Join(home, "harness", "timing.jsonl"),
	}
	if exe, err := os.Executable(); err == nil {
		cfg.Exe = exe
	}
	// A2A rides on the session only when a2a.enabled is on and the host's
	// classifier can screen what peers send (KindPeer); otherwise the bridge
	// is not wired and the harness has no A2A.
	if settings.A2AEnabled() && h.Launch.MCP != nil && cfg.Exe != "" {
		if link := rcHarnessA2A(ctx, cwd, a.sid, h.ID, settings, stderr); link != nil {
			defer link.Close()
			la := harnessrun.LinkA2A{L: link}
			if relay, err := factorylink.ActiveA2A(home); err == nil {
				defer relay.Close()
				la.Directory = rcHarnessDirectory(relay)
			}
			cfg.A2A = la
			cfg.OnStart = func(s *harnessrun.Session) { s.AttachLink(link) }
		}
	}
	if c, err := factorylink.ActiveClient(home); err == nil {
		defer c.Close()
		cfg.Screen = func(ctx context.Context) (harnessrun.ScreenStream, error) {
			conn, err := c.Conn(ctx)
			if err != nil {
				return nil, err
			}
			return nodev1.NewScreenClient(conn).Stream(ctx)
		}
	}
	return harnessrun.Run(ctx, cfg)
}

// rcHarnessClassifier resolves the host's security classifier for a harness
// session: the configuration a pipeline or the A2A endpoint runs it with.
func rcHarnessClassifier(cwd string, settings config.Settings) (run.Config, error) {
	if err := run.PreloadClassifier(run.ResolveSecurityClassifier(settings.Classifier)); err != nil {
		return run.Config{}, fmt.Errorf("classifier: %w", err)
	}
	resolver, err := newResolver(cwd)
	if err != nil {
		return run.Config{}, err
	}
	p, m := workerModel("", "", settings, config.LoadState)
	rc, err := run.ResolveWithSource(m, p, os.Getenv, resolver)
	if err == nil {
		rc, err = withClassifier(rc, settings, resolver)
	}
	if err != nil {
		return run.Config{}, fmt.Errorf("no classifier provider: %w", err)
	}
	return rc, nil
}

// rcHarnessPolicy is the posture a harness session runs under: the defaults
// with the project's overrides.
func rcHarnessPolicy(cwd string) posture.Policy {
	projectPol, _ := posture.Load(cwd)
	return posture.Defaults().Override(projectPol)
}

// rcHarnessAdmit is the session's prompt admission: every prompt typed into
// the harness is classified with the host's classifier and posture, as a
// belai session classifies a cloud or Keleustes prompt. Without a classifier
// it refuses every prompt.
func rcHarnessAdmit(cwd string, settings config.Settings, stderr io.Writer) func(context.Context, string) (string, error) {
	rc, err := rcHarnessClassifier(cwd, settings)
	if err != nil {
		fmt.Fprintln(stderr, "rc-harness: prompts refused:", err)
		why := "no security classifier: " + sanitize.Line(err.Error(), 120)
		return func(context.Context, string) (string, error) { return "", errors.New(why) }
	}
	cache, _ := rolemanager.LoadCache(rolemanager.DefaultCachePath())
	pipe := run.NewPipeline(rc, httpclient.Default(), cache)
	pol := rcHarnessPolicy(cwd)
	return func(ctx context.Context, text string) (string, error) {
		dec, err := pipe.Admit(ctx, sanitize.Text(text), "harness prompt", pol)
		if err != nil {
			return "", err
		}
		if dec.Action == rolemanager.ActionWarn {
			return "WARN", nil
		}
		return string(dec.Sentinel), nil
	}
}

// rcHarnessA2A opens the session's A2A endpoint with the host's classifier,
// or nil (A2A unavailable) when no classifier can be resolved.
func rcHarnessA2A(ctx context.Context, cwd, sid, profile string, settings config.Settings, stderr io.Writer) *a2alink.Link {
	rc, err := rcHarnessClassifier(cwd, settings)
	if err != nil {
		fmt.Fprintln(stderr, "rc-harness: A2A off:", err)
		return nil
	}
	l := headless.OpenA2A(ctx, headless.Params{Cfg: rc, Client: httpclient.Default(), Posture: rcHarnessPolicy(cwd), Workdir: cwd,
		Settings: settings, SessionID: sid}, profile, "", nil)
	return l
}

// runHarnessHookCLI is `belai harness-hook`: a harness hook forwarding its
// event to the session; it never blocks or steers the harness.
func runHarnessHookCLI(ctx context.Context, args []string, stdin io.Reader) int {
	fs := flag.NewFlagSet("harness-hook", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	sock := fs.String("sock", "", "the harness session socket")
	event := fs.String("event", "", "the hook event name")
	if fs.Parse(args) != nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return harnessrun.HookMain(ctx, *sock, *event, stdin)
}

// runA2AMCPCLI is `belai a2a-mcp`: the stdio MCP server a harness session's
// harness runs for its A2A tools.
func runA2AMCPCLI(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) int {
	fs := flag.NewFlagSet("a2a-mcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	sock := fs.String("sock", "", "the harness session socket")
	if fs.Parse(args) != nil {
		return 2
	}
	return harnessrun.MCPMain(ctx, *sock, stdin, stdout)
}

// rcHarnessDirectory lists Keleustes's live sessions for the bridge's peers
// tool. Titles are other models' text: one cleaned line each.
func rcHarnessDirectory(relay *factorylink.A2ARelay) func(context.Context) ([]harnessrun.Peer, error) {
	return func(ctx context.Context) ([]harnessrun.Peer, error) {
		ps, err := relay.Peers(ctx, "", 200)
		if err != nil {
			return nil, err
		}
		out := make([]harnessrun.Peer, 0, len(ps))
		for _, p := range ps {
			out = append(out, harnessrun.Peer{ID: agentIDOf(p.GetAgentId()),
				Display: sanitize.Line(p.GetNodeName()+" · "+p.GetTitle(), 160), Profile: sanitize.Ident(p.GetAgent(), 64),
				Repo: sanitize.Line(p.GetRepo(), 128), Branch: sanitize.Line(p.GetBranch(), 200), Seen: p.GetUpdatedAtMs()})
		}
		return out, nil
	}
}

// agentIDOf keeps a "<nodeId>:<sessionId>" agent id only when both halves are
// ids; anything else becomes "" (and is not addressable).
func agentIDOf(s string) string {
	if !a2a.ValidAgentID(s) {
		return ""
	}
	return s
}
