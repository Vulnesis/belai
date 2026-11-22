package forgejob

// The forge job (keleustes docs/gaps/forges-proto-request.md, section 2):
// one gh, glab or tea call for a named host, for a Keleustes connection
// that routes through this node. Payload:
//
//	{"cli": "gh"|"glab"|"tea", "host": "<host[:port]>", "args": [...], "stdin": "..."|null}
//
// Every field is untrusted. The argv is checked against a closed table per
// CLI and the host is forced, never taken from an argument:
//
//   - gh: the github job's allowlist (rc.checkGHArgs, passed in), then
//     `--hostname <host>` forced after `api`; any other command runs with
//     GH_HOST=<host> and a -R/--repo naming another host is refused.
//   - glab: `api` only, a closed flag table, `--hostname <host>` forced;
//     --input only from stdin, no -F @file, one API path.
//   - tea: `api` only, a closed flag table, `-l <login>` forced to the tea
//     login this host holds for <host>; -d only @-, no -F @file, no -o.
//
// The CLI runs as one argv with no shell, in a fresh empty directory, with
// the scrubbed environment, no prompt, no pager and its own process group.
// The answer is {"stdout","stderr","exit","truncated"}, as the github job's.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vulnetix/belai/internal/proc"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/vaultenv"
)

// KindForge is the job kind.
const KindForge = "forge"

// Limits on a forge job.
const (
	maxArgs     = 64
	maxArgBytes = 8 << 10
	maxStdin    = 1 << 20
	maxOutput   = 1 << 20
	maxEndpoint = 2048
)

// ForgeRequest is a checked forge payload.
type ForgeRequest struct {
	CLI   string
	Host  string
	Args  []string
	Stdin string
}

// Result is one CLI run.
type Result struct {
	Stdout, Stderr string
	Exit           int
	Truncated      bool
}

// Exec runs prog with args, stdin and env in dir (runCLI unless a test
// replaces it).
var Exec = runCLI

// TeaLogin names the tea login this host holds for host (teaLoginFor unless
// a test replaces it).
var TeaLogin = teaLoginFor

// ParseForge decodes and checks a forge payload. checkGH is the github
// job's gh allowlist. The second result is the refusal ("" to run).
func ParseForge(payload string, checkGH func([]string) string) (ForgeRequest, string) {
	var p struct {
		CLI   string   `json:"cli"`
		Host  string   `json:"host"`
		Args  []string `json:"args"`
		Stdin *string  `json:"stdin"`
	}
	dec := json.NewDecoder(strings.NewReader(payload))
	dec.DisallowUnknownFields()
	if dec.Decode(&p) != nil {
		return ForgeRequest{}, `the forge job's payload is not {"cli", "host", "args", "stdin"}`
	}
	r := ForgeRequest{CLI: p.CLI, Host: strings.ToLower(p.Host), Args: p.Args}
	if p.Stdin != nil {
		r.Stdin = *p.Stdin
	}
	if _, ok := helpers[r.CLI]; !ok {
		return r, "a forge job runs gh, glab or tea"
	}
	if !hostRe.MatchString(r.Host) || len(r.Host) > 253 {
		return r, "the forge job's host is not a host name"
	}
	if len(r.Stdin) > maxStdin {
		return r, "the forge job's stdin is too large"
	}
	if len(r.Args) == 0 || len(r.Args) > maxArgs {
		return r, fmt.Sprintf("a forge job runs %s with 1 to %d arguments", r.CLI, maxArgs)
	}
	if r.Args[0] == r.CLI {
		return r, "a forge job's args follow the CLI; they do not name it"
	}
	for _, a := range r.Args {
		if len(a) > maxArgBytes || !utf8.ValidString(a) || strings.ContainsRune(a, 0) {
			return r, "a forge job's argument is too long or not text"
		}
		if a == "--" {
			return r, "a forge job may not end the CLI's flags with --"
		}
	}
	var why string
	switch r.CLI {
	case "gh":
		if why = checkGH(r.Args); why == "" {
			r.Args, why = forceGHHost(r.Args, r.Host)
		}
	case "glab":
		r.Args, why = checkAPI(r.Args, r.Host, glabFlags, "--hostname")
	case "tea":
		r.Args, why = checkAPI(r.Args, r.Host, teaFlags, "-l")
	}
	return r, why
}

// flagRule is how one CLI flag is checked: whether it takes a value, and
// the value check (nil: any text).
type flagRule struct {
	value bool
	check func(v string) string
	// forced flags are dropped from the caller's argv and set by the job.
	forced bool
}

var methods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}

func checkMethod(v string) string {
	if !slices.Contains(methods, strings.ToUpper(v)) {
		return "the forge job's method is not GET, HEAD, POST, PUT, PATCH or DELETE"
	}
	return ""
}

// credHeaders would replace the CLI's own credentials.
var credHeaders = []string{"authorization", "private-token", "job-token", "cookie", "proxy-authorization"}

func checkHeader(v string) string {
	name, _, ok := strings.Cut(v, ":")
	if !ok || strings.ContainsAny(v, "\r\n") {
		return "a forge job's header is not Name: value"
	}
	if slices.Contains(credHeaders, strings.ToLower(strings.TrimSpace(name))) {
		return "a forge job may not set a credential header"
	}
	return ""
}

func stdinOnly(v string) string {
	if v != "-" {
		return "a forge job's --input may only read the job's stdin (-)"
	}
	return ""
}

func dataStdinOnly(v string) string {
	if v != "@-" {
		return "a forge job's -d may only read the job's stdin (@-)"
	}
	return ""
}

// typedField is key=value where an @ value reads a file: only @- is taken.
func typedField(v string) string {
	k, fv, ok := strings.Cut(v, "=")
	if !ok || k == "" {
		return "a forge job's field is not key=value"
	}
	if strings.HasPrefix(fv, "@") && fv != "@-" {
		return "a forge job's field may only read the job's stdin (@-)"
	}
	return ""
}

func rawField(v string) string {
	if k, _, ok := strings.Cut(v, "="); !ok || k == "" {
		return "a forge job's field is not key=value"
	}
	return ""
}

// glabFlags is `glab api`'s closed flag table.
var glabFlags = map[string]flagRule{
	"--hostname": {value: true, forced: true},
	"-X":         {value: true, check: checkMethod}, "--method": {value: true, check: checkMethod},
	"-H": {value: true, check: checkHeader}, "--header": {value: true, check: checkHeader},
	"-f": {value: true, check: rawField}, "--raw-field": {value: true, check: rawField},
	"-F": {value: true, check: typedField}, "--field": {value: true, check: typedField},
	"--input": {value: true, check: stdinOnly},
	"-i":      {}, "--include": {}, "--paginate": {}, "--silent": {},
}

// teaFlags is `tea api`'s closed flag table (no -o: it writes a file).
var teaFlags = map[string]flagRule{
	"-l": {value: true, forced: true}, "--login": {value: true, forced: true},
	"-X": {value: true, check: checkMethod}, "--method": {value: true, check: checkMethod},
	"-H": {value: true, check: checkHeader}, "--header": {value: true, check: checkHeader},
	"-f": {value: true, check: rawField}, "--field": {value: true, check: rawField},
	"-F": {value: true, check: typedField}, "--Field": {value: true, check: typedField},
	"-d": {value: true, check: dataStdinOnly}, "--data": {value: true, check: dataStdinOnly},
	"-i": {}, "--include": {},
}

// checkEndpoint checks an API path: no scheme or host, no parent
// directory, no home or Windows path.
func checkEndpoint(e string) string {
	switch {
	case e == "" || len(e) > maxEndpoint:
		return "a forge job names one API path"
	case strings.Contains(e, "://") || strings.HasPrefix(e, "//"):
		return "a forge job's API path may not name a host"
	case strings.HasPrefix(e, "~") || strings.ContainsAny(e, "\\\r\n\t "):
		return "a forge job's API path is not a path"
	}
	path, _, _ := strings.Cut(e, "?")
	if dec, err := url.PathUnescape(path); err != nil || slices.Contains(strings.Split(dec, "/"), "..") {
		return "a forge job's API path may not name a parent directory"
	}
	return ""
}

// checkAPI checks a glab or tea argv against its flag table and forces the
// host flag (hostFlag): the caller's value is dropped and the job's set.
// glab's is the host; tea's is resolved at run time (Argv), so a
// placeholder marks it here.
func checkAPI(args []string, host string, table map[string]flagRule, hostFlag string) ([]string, string) {
	if args[0] != "api" {
		return nil, "a forge job runs only the api command of " + map[string]string{"--hostname": "glab", "-l": "tea"}[hostFlag]
	}
	out := []string{"api", hostFlag, host}
	endpoint := ""
	for i := 1; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			if endpoint != "" {
				return nil, "a forge job names one API path"
			}
			if why := checkEndpoint(a); why != "" {
				return nil, why
			}
			endpoint = a
			continue
		}
		name, value, inline := strings.Cut(a, "=")
		if !strings.HasPrefix(a, "--") {
			// -Xvalue is -X value; a short flag never carries "=" here.
			name, value, inline = a, "", false
			if len(a) > 2 {
				name, value, inline = a[:2], strings.TrimPrefix(a[2:], "="), true
			}
		}
		rule, ok := table[name]
		if !ok {
			return nil, "a forge job may not pass " + sanitize.Ident(name, 32)
		}
		if !rule.value {
			if inline {
				return nil, "a forge job's " + name + " takes no value"
			}
			out = append(out, name)
			continue
		}
		if !inline {
			if i+1 >= len(args) {
				return nil, "a forge job's " + name + " needs a value"
			}
			i++
			value = args[i]
		}
		if rule.forced {
			if hostFlag == "--hostname" && !strings.EqualFold(value, host) {
				return nil, "a forge job runs for " + host + " only"
			}
			continue
		}
		if rule.check != nil {
			if why := rule.check(value); why != "" {
				return nil, why
			}
		}
		out = append(out, name, value)
	}
	if endpoint == "" {
		return nil, "a forge job names one API path"
	}
	return append(out, endpoint), ""
}

// forceGHHost forces gh onto host: `--hostname <host>` right after `api`
// (a different --hostname is refused), GH_HOST for any other command (set
// by Run), and a -R/--repo naming another host is refused.
func forceGHHost(args []string, host string) ([]string, string) {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, value, inline := strings.Cut(a, "=")
		if strings.HasPrefix(a, "-R") && len(a) > 2 {
			name, value, inline = "-R", strings.TrimPrefix(a[2:], "="), true
		}
		if args[0] == "api" && (i == 1 || i == len(args)-1) && !strings.HasPrefix(a, "-") && !ghValueFlags[args[i-1]] {
			if why := checkEndpoint(a); why != "" {
				return nil, why
			}
		}
		switch name {
		case "--hostname":
			if !inline {
				if i+1 >= len(args) {
					return nil, "gh --hostname needs a value"
				}
				i++
				value = args[i]
			}
			if args[0] != "api" || !strings.EqualFold(value, host) {
				return nil, "a forge job runs for " + host + " only"
			}
			continue
		case "-R", "--repo":
			if !inline {
				if i+1 >= len(args) {
					return nil, "gh " + name + " needs a value"
				}
				value = args[i+1]
			}
			if segs := strings.Split(value, "/"); len(segs) >= 3 && !strings.EqualFold(segs[0], host) {
				return nil, "a forge job runs for " + host + " only"
			}
		}
		out = append(out, a)
	}
	if out[0] == "api" {
		out = append([]string{"api", "--hostname", host}, out[1:]...)
	}
	return out, ""
}

// ghValueFlags are gh api flags whose value is the next argument.
var ghValueFlags = map[string]bool{
	"-X": true, "--method": true, "-H": true, "--header": true, "-f": true, "--raw-field": true,
	"-F": true, "--field": true, "--input": true, "-q": true, "--jq": true, "-t": true, "--template": true,
	"--hostname": true, "--cache": true, "-p": true, "--preview": true,
}

// envKeep are the credential variables each CLI reads itself, kept through
// the scrub (gh as for the github job; glab and tea read their own config).
var envKeep = map[string][]string{
	"gh": {"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"},
}

// hostEnv are variables that choose a CLI's host or repository (its config
// directory stays: the logins the advert lists live there).
var hostEnv = []string{"GH_HOST", "GH_REPO", "GITLAB_HOST", "GITLAB_URI", "GL_HOST", "GITLAB_REPO",
	"GITEA_SERVER_URL", "GITEA_SERVER_TOKEN", "GITEA_INSTANCE_INSECURE"}

// Argv is the argv the job runs: tea's login resolved for the host.
func (r ForgeRequest) Argv(ctx context.Context) ([]string, string) {
	if r.CLI != "tea" {
		return r.Args, ""
	}
	name, ok := TeaLogin(ctx, r.Host)
	if !ok {
		return nil, "this host has no tea login for " + r.Host
	}
	out := slices.Clone(r.Args)
	out[2] = name
	return out, ""
}

// Run runs a checked forge job and shapes the answer. A refusal is the
// second result; err is a failure to run.
func Run(ctx context.Context, r ForgeRequest) (json.RawMessage, string, error) {
	args, why := r.Argv(ctx)
	if why != "" {
		return nil, why, nil
	}
	env := []string{"NO_COLOR=1", "CLICOLOR=0", "PAGER=cat", "GIT_TERMINAL_PROMPT=0"}
	switch r.CLI {
	case "gh":
		env = append(env, "GH_HOST="+r.Host, "GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1", "GH_SPINNER_DISABLED=1", "GH_PAGER=")
	case "glab":
		env = append(env, "NO_PROMPT=1", "GLAB_NO_PROMPT=1", "GLAB_CHECK_UPDATE=false", "GLAB_SEND_TELEMETRY=false", "GLAB_PAGER=cat")
	}
	// Inherited variables that would point the CLI at another host or repo
	// are dropped; the job's own are set after.
	base := slices.DeleteFunc(proc.ScrubEnvKeeping(os.Environ(), envKeep[r.CLI]), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		return slices.Contains(hostEnv, strings.ToUpper(name))
	})
	res, err := Exec(ctx, r.CLI, args, r.Stdin, append(base, env...))
	if err != nil {
		return nil, "", err
	}
	out, err := json.Marshal(map[string]any{
		"stdout": vaultenv.Default.Scrub(res.Stdout), "stderr": vaultenv.Default.Scrub(res.Stderr),
		"exit": res.Exit, "truncated": res.Truncated,
	})
	return out, "", err
}

// runCLI runs prog with no shell in a fresh empty directory that is removed
// after, in its own process group, each output stream capped.
func runCLI(ctx context.Context, prog string, args []string, stdin string, env []string) (Result, error) {
	exe, err := exec.LookPath(prog)
	if err != nil {
		return Result{}, errors.New(prog + " is not installed on this host")
	}
	dir, err := os.MkdirTemp("", "belai-forge-job-")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(dir)
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	stdout, stderr := &capped{max: maxOutput}, &capped{max: maxOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	proc.SetProcessGroup(cmd)
	cmd.Cancel = func() error { return proc.Kill(cmd.Process.Pid) }
	cmd.WaitDelay = 5 * time.Second
	err = cmd.Run()
	res := Result{Stdout: strings.ToValidUTF8(stdout.String(), "�"), Stderr: strings.ToValidUTF8(stderr.String(), "�"),
		Truncated: stdout.cut || stderr.cut}
	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		return res, errors.New(prog + " ran past the job's deadline")
	case errors.As(err, &exit):
		res.Exit = exit.ExitCode()
	case err != nil:
		return res, errors.New(prog + " could not be started")
	}
	return res, nil
}

// capped keeps the first max bytes written.
type capped struct {
	bytes.Buffer
	max int
	cut bool
}

func (b *capped) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room < len(p) {
		b.cut = true
		if room > 0 {
			b.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// teaLoginFor reads `tea login list -o json` and names the login whose URL
// is on host.
func teaLoginFor(ctx context.Context, host string) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	res, err := Exec(ctx, "tea", []string{"login", "list", "-o", "json"}, "", proc.ScrubbedEnv())
	if err != nil || res.Exit != 0 {
		return "", false
	}
	return teaLoginIn(res.Stdout, host)
}

// teaLoginIn picks host's login from tea's JSON list (keys in any case).
func teaLoginIn(list, host string) (string, bool) {
	var raw []map[string]any
	if json.Unmarshal([]byte(strings.TrimSpace(list)), &raw) != nil {
		return "", false
	}
	for _, m := range raw {
		var name, u string
		for k, v := range m {
			s, _ := v.(string)
			switch strings.ToLower(k) {
			case "name":
				name = s
			case "url":
				u = s
			}
		}
		pu, err := url.Parse(u)
		if err != nil || !strings.EqualFold(pu.Host, host) || name == "" || sanitize.Ident(name, 64) != name {
			continue
		}
		return name, true
	}
	return "", false
}
