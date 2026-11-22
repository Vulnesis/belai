package harnessrun

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vulnetix/belai/internal/harness"
	"github.com/vulnetix/belai/internal/proc"
)

// SockEnv names the per-session socket for the hook and bridge commands.
const SockEnv = "BELAI_HARNESS_SOCK"

// Wiring is what a launch adds for the bridge and the hooks: argv values for
// harness.Values and extra environment.
type Wiring struct {
	MCPFile, MCPJSON, MCPCmd, SettingsFile string
	Env                                    []string
	// A2A reports whether the bridge is wired.
	A2A bool
}

// bridgeArgv is the bridge's command line: belai a2a-mcp --sock <sock>.
func bridgeArgv(exe, sock string) []string { return []string{exe, "a2a-mcp", "--sock", sock} }

// shq quotes s for a POSIX shell.
func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Wire writes the per-session files under dir (0700, belai's own) and
// returns the wiring. The harness's own config files are never written. a2a
// false leaves the bridge out (A2A disabled, or no classifier).
func Wire(l *harness.Launch, dir, exe, sock string, a2a bool) (Wiring, error) {
	var w Wiring
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return w, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return w, err
	}
	args := bridgeArgv(exe, sock)
	if m := l.MCP; m != nil && a2a {
		switch m.Dialect {
		case "claude", "copilot":
			server := map[string]any{"command": args[0], "args": args[1:]}
			if m.Dialect == "copilot" {
				server["type"], server["tools"] = "local", []string{"*"}
			}
			cfg := map[string]any{"mcpServers": map[string]any{"belai": server}}
			if m.How == "flag-json" {
				b, err := json.Marshal(cfg)
				if err != nil {
					return w, err
				}
				w.MCPJSON = string(b)
			} else {
				w.MCPFile = filepath.Join(dir, "mcp.json")
				if err := writeJSON(w.MCPFile, cfg); err != nil {
					return w, err
				}
			}
		case "codex":
			q := make([]string, len(args)-1)
			for i, a := range args[1:] {
				q[i] = strconv.Quote(a)
			}
			w.MCPCmd = "mcp_servers.belai={command=" + strconv.Quote(args[0]) + ",args=[" + strings.Join(q, ",") + "]}"
		case "goose":
			for _, a := range args {
				if strings.ContainsAny(a, " \t\"'") {
					return w, errors.New("goose splits its extension command on spaces; the belai path has one")
				}
			}
			w.MCPCmd = strings.Join(args, " ")
		case "opencode":
			w.MCPFile = filepath.Join(dir, "opencode.json")
			if err := writeJSON(w.MCPFile, map[string]any{"mcp": map[string]any{"belai": map[string]any{
				"type": "local", "command": args, "enabled": true}}}); err != nil {
				return w, err
			}
		default:
			return w, errors.New("no bridge config for dialect " + m.Dialect)
		}
		if m.How == "env-file" {
			w.Env = append(w.Env, m.Env+"="+w.MCPFile)
		}
		w.A2A = true
	}
	if h := l.Hooks; h != nil && h.Dialect == "claude" {
		hook := func(ev string) []map[string]any {
			cmd := shq(exe) + " harness-hook --sock " + shq(sock) + " --event " + ev
			return []map[string]any{{"hooks": []map[string]any{{"type": "command", "command": cmd}}}}
		}
		w.SettingsFile = filepath.Join(dir, "settings.json")
		if err := writeJSON(w.SettingsFile, map[string]any{"hooks": map[string]any{
			"Stop": hook("Stop"), "Notification": hook("Notification"), "UserPromptSubmit": hook("UserPromptSubmit"),
		}}); err != nil {
			return w, err
		}
	}
	return w, nil
}

// ownEnvPrefixes are belai's own variables: none reaches a harness.
var ownEnvPrefixes = []string{"BELAI_", "VULNETIX_", "KELEUSTES_"}

// Env is the harness's environment: belai's scrubbed tool environment
// (credential-shaped names removed) without belai's own variables, with a
// colour terminal, the bin's directory first on PATH, the socket, and the
// wiring's extras. No vault grant value is ever added.
func Env(base []string, bin, sock string, extra []string) []string {
	if base == nil {
		base = proc.ScrubbedEnv()
	}
	var out []string
	path := ""
	for _, kv := range base {
		k, v, _ := strings.Cut(kv, "=")
		own := false
		for _, p := range ownEnvPrefixes {
			if strings.HasPrefix(k, p) {
				own = true
			}
		}
		if parentSession(k) {
			continue
		}
		switch {
		case own, k == "TERM", k == "COLORTERM":
		case k == "PATH":
			path = v
		default:
			out = append(out, kv)
		}
	}
	if d := filepath.Dir(bin); d != "" && d != "." {
		path = strings.Trim(d+string(os.PathListSeparator)+path, string(os.PathListSeparator))
	}
	out = append(out, "PATH="+path, "TERM=xterm-256color", "COLORTERM=truecolor", SockEnv+"="+sock)
	return append(out, extra...)
}

// maxSock is below the shortest sun_path limit (104 on macOS).
const maxSock = 100

// sockPath is the per-session socket: in the session's own directory when
// the path fits a unix socket address, else in a fresh 0700 directory under
// $XDG_RUNTIME_DIR (or the temp directory), removed at the end.
func sockPath(dir string) (string, func(), error) {
	if p := filepath.Join(dir, "sock"); len(p) < maxSock {
		return p, func() {}, nil
	}
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" || !filepath.IsAbs(base) {
		base = os.TempDir()
	}
	d, err := os.MkdirTemp(base, "belai-h-")
	if err != nil {
		return "", nil, err
	}
	p := filepath.Join(d, "sock")
	if len(p) >= maxSock {
		os.RemoveAll(d)
		return "", nil, errors.New("no directory short enough for the session socket")
	}
	return p, func() { _ = os.RemoveAll(d) }, nil
}

// parentSession reports a variable that marks the process as running inside
// another agent's session (belai rc started from a Claude Code or Codex
// shell). A harness session is a top-level session of its own: with these
// set, Claude Code treats itself as a child and keeps no transcript.
func parentSession(k string) bool {
	switch k {
	case "CLAUDECODE", "CLAUDE_PID", "CLAUDE_EFFORT", "CODEX_THREAD_ID", "CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED":
		return true
	}
	for _, p := range []string{"CLAUDE_CODE_SESSION", "CLAUDE_CODE_CHILD", "CLAUDE_CODE_ENTRYPOINT", "CLAUDE_CODE_MESSAGING",
		"CLAUDE_CODE_BRIDGE", "CLAUDE_CODE_EXECPATH", "CLAUDE_CODE_SSE_PORT"} {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}
