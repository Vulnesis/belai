package rc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/forgejob"
	"github.com/vulnetix/belai/internal/libraryjob"
	"github.com/vulnetix/belai/internal/proc"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/vaultenv"
)

// Keleustes jobs (docs/keleustes.md#jobs): work the desktop Software Factory
// asks a capable node to do for it, because Keleustes itself runs no `gh`
// and calls no model. A job arrives on the node link; the daemon answers it
// through Jobs.Complete. Every field of a job is untrusted.
//
//   - "github": {"args": [...], "stdin": "..."} runs `gh` with those
//     arguments, as one argv with no shell, in an empty scratch directory,
//     and answers {"stdout", "stderr", "exit"}. Only while gh is signed in.
//   - "model": {"task": "draft"|"classify"|"avatar"|"systemone", ...} runs a
//     single non-interactive call of this host's provider plumbing
//     (Options.ModelJob), with the job's vault grant as that call's
//     provider keys, and answers the task's result.
//   - "teleport": {"task": "teleport_upload", "teleportId", "sessionId",
//     "toNode"} bundles a session of this host for another node and uploads
//     it with Teleport.Upload (factoryteleport.go).
//   - "library": {"task": "convert", "kind": "agent", "format", "name",
//     "files"} converts a foreign agent definition with agentimport in a
//     private staging directory and answers the profile (internal/libraryjob).
//   - "knowledge_search": a KnowledgeSearchRequest (proto3 JSON) answered from
//     this host's knowledge indexes, read only, no model (factoryknowledge.go).
//   - "init_draft": an InitDraftRequest; one call of this host's model drafts an
//     AGENTS.md from the repository map's facts, written nowhere
//     (factoryinitdraft.go, Options.InitDraft).
//
// Any other kind is refused.

// Job kinds.
const (
	jobKindGitHub   = "github"
	jobKindModel    = "model"
	jobKindTeleport = "teleport"
)

// factoryJobKinds are the Keleustes job kinds this daemon runs, advertised
// in Capabilities.job_kinds: Keleustes sends a forge job only to a node
// that lists "forge" and falls back to the github job for github.com.
var factoryJobKinds = []string{jobKindGitHub, jobKindModel, jobKindTeleport, forgejob.KindPush, forgejob.KindForge, libraryjob.Kind,
	jobKindKnowledgeSearch, jobKindInitDraft}

// Limits on a job.
const (
	maxFactoryJobs = 4
	// maxGHArgs and maxGHArgBytes bound a github job's argv; maxGHStdin its
	// standard input.
	maxGHArgs     = 64
	maxGHArgBytes = 8 << 10
	maxGHStdin    = 1 << 20
	// maxGHOutput caps each of stdout and stderr in the answer.
	maxGHOutput = 1 << 20
	// defaultJobTimeout applies when a job names no deadline; maxJobTimeout
	// is the longest any job runs, whatever its deadline says.
	defaultJobTimeout = 90 * time.Second
	maxJobTimeout     = 10 * time.Minute
	maxModelPayload   = 256 << 10
)

// GHResult is one gh run's outcome.
type GHResult struct {
	Stdout, Stderr string
	Exit           int
	// Truncated says an output stream was cut at maxGHOutput.
	Truncated bool
}

// handleFactoryJob takes one Keleustes job and answers it in the background.
// The frame is acked when this returns, so a replay never runs a job twice.
func (d *Daemon) handleFactoryJob(ctx context.Context, j *nodev1.Job) {
	id := j.GetId()
	grant := factorylink.GrantFrom(j.GetVault(), time.Now())
	if grant != nil {
		// The daemon holds a key now: no same-user process may read its memory.
		vaultenv.Protect()
	}
	// facts are the audit's ids for this job (a forge job's host and CLI).
	facts := map[string]string{"dispatch": "job", "kind": jobKindWord(j.GetKind()), "via": "keleustes"}
	refuse := func(why string) {
		grant.Drop()
		d.logf("refused keleustes job %s (%s): %s", short(sanitizeName(id)), sanitize.Ident(j.GetKind(), 32), why)
		facts["status"] = jobRefused
		audit.Emit(audit.Fact{Kind: audit.HostDispatch, ActorKind: audit.ActorWeb, Data: facts})
		d.reportJob(ctx, &nodev1.JobResult{JobId: id, Status: jobRefused, Error: why})
	}
	if id == "" || sanitize.Ident(id, 64) != id {
		grant.Drop()
		return // nothing to report against
	}
	if c := d.factoryControl(); c.Stopped {
		facts["reason"] = "kill_switch"
		refuse(factorylink.StoppedReason(c))
		return
	}
	timeout, why := jobTimeout(j.GetDeadlineMs(), time.Now())
	if why != "" {
		refuse(why)
		return
	}
	var run func(ctx context.Context) (json.RawMessage, string, error)
	switch j.GetKind() {
	case jobKindGitHub:
		args, stdin, why := parseGHJob(j.GetPayloadJson())
		if why != "" {
			refuse(why)
			return
		}
		if !d.o.GHAuthenticated(ctx) {
			go d.factoryAttention(context.WithoutCancel(ctx), "gh_login", "reauth_needed", "github.com")
			refuse("gh is not signed in on this host")
			return
		}
		run = func(ctx context.Context) (json.RawMessage, string, error) { return d.runGitHubJob(ctx, args, stdin) }
	case jobKindModel:
		if d.o.ModelJob == nil {
			refuse("this host runs no model jobs")
			return
		}
		task, payload, why := parseModelJob(j.GetPayloadJson())
		if why != "" {
			refuse(why)
			return
		}
		run = func(ctx context.Context) (json.RawMessage, string, error) {
			return d.o.ModelJob(ctx, task, payload, grant)
		}
	case forgejob.KindPush:
		req, why := forgejob.ParsePush(j.GetPayloadJson())
		if why == "" && !d.o.ForgeSignedIn(ctx, req.CLI, req.Host) {
			why = "this host has no signed-in " + req.CLI + " login for " + req.Host
		}
		if why != "" {
			refuse(why)
			return
		}
		run = func(ctx context.Context) (json.RawMessage, string, error) { return forgejob.Push(ctx, req) }
	case forgejob.KindForge:
		// One checked gh, glab or tea call, the host forced (forgejob.ParseForge).
		req, why := forgejob.ParseForge(j.GetPayloadJson(), checkGHArgs)
		if why == "" {
			facts["forge"], facts["tool"] = req.Host, req.CLI
			if !d.o.ForgeSignedIn(ctx, req.CLI, req.Host) {
				why = "this host has no signed-in " + req.CLI + " login for " + req.Host
			}
		}
		if why != "" {
			refuse(why)
			return
		}
		run = func(ctx context.Context) (json.RawMessage, string, error) { return forgejob.Run(ctx, req) }
	case libraryjob.Kind:
		// Converting a foreign agent definition: files in, a profile out,
		// nothing installed and nothing executed (WP9).
		req, why := libraryjob.Parse(j.GetPayloadJson())
		if why != "" {
			refuse(why)
			return
		}
		run = func(context.Context) (json.RawMessage, string, error) { return libraryjob.Convert(req) }
	case jobKindKnowledgeSearch:
		run, why = d.runKnowledgeSearchJob(j.GetPayloadJson())
	case jobKindInitDraft:
		run, why = d.runInitDraftJob(j.GetPayloadJson(), grant)
	case jobKindTeleport:
		req, why := parseTeleportJob(j.GetPayloadJson())
		if why != "" {
			refuse(why)
			return
		}
		run = func(ctx context.Context) (json.RawMessage, string, error) { return d.teleportUpload(ctx, req) }
	default:
		refuse("this Belai does not run that kind of job; update Belai on the host")
		return
	}
	if run == nil {
		refuse(why) // knowledge_search, init_draft: a payload their parser refused
		return
	}
	select {
	case d.jobSlot <- struct{}{}:
	default:
		refuse(fmt.Sprintf("this host is already running %d Keleustes jobs", maxFactoryJobs))
		return
	}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		defer func() { <-d.jobSlot }()
		// The grant lives as long as this job and no longer.
		defer grant.Drop()
		jctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		out, why, err := run(jctx)
		res := &nodev1.JobResult{JobId: id}
		switch {
		case err != nil:
			res.Status, res.Error = jobFailed, clip(vaultenv.Default.Scrub(err.Error()))
			if jctx.Err() != nil && ctx.Err() == nil {
				res.Error = "the job ran past its deadline"
			}
		case why != "":
			res.Status, res.Error = jobRefused, clip(why)
		default:
			res.Status, res.OutputJson = jobOK, string(out)
		}
		d.logf("keleustes job %s (%s): %s", short(sanitizeName(id)), j.GetKind(), res.Status)
		facts["status"] = res.Status
		audit.Emit(audit.Fact{Kind: audit.HostDispatch, ActorKind: audit.ActorWeb, Data: facts})
		d.reportJob(ctx, res)
	}()
}

// jobKindWord is a job's kind for the audit log: a kind this host runs, or
// "unknown" (the kind is Keleustes's, so only a known word is kept).
func jobKindWord(k string) string {
	if slices.Contains(factoryJobKinds, k) {
		return k
	}
	return "unknown"
}

// reportJob reports a job's outcome, retried like a dispatch's.
func (d *Daemon) reportJob(ctx context.Context, res *nodev1.JobResult) {
	d.complete(ctx, res)
}

// jobTimeout is how long a job may run given its deadline (unix ms, 0 for
// none), or why it cannot start.
func jobTimeout(deadlineMs int64, now time.Time) (time.Duration, string) {
	if deadlineMs <= 0 {
		return defaultJobTimeout, ""
	}
	left := time.UnixMilli(deadlineMs).Sub(now)
	if left <= 0 {
		return 0, "the job's deadline passed before it arrived"
	}
	return min(left, maxJobTimeout), ""
}

// parseGHJob reads a github job's payload and checks its arguments.
func parseGHJob(payload string) ([]string, string, string) {
	var p struct {
		Args  []string `json:"args"`
		Stdin *string  `json:"stdin"`
	}
	if json.Unmarshal([]byte(payload), &p) != nil {
		return nil, "", "the github job's payload is not {\"args\": [...], \"stdin\": ...}"
	}
	if why := checkGHArgs(p.Args); why != "" {
		return nil, "", why
	}
	stdin := ""
	if p.Stdin != nil {
		stdin = *p.Stdin
	}
	if len(stdin) > maxGHStdin {
		return nil, "", "the github job's stdin is too large"
	}
	return p.Args, stdin, ""
}

// ghCommands are the gh commands a job may run. Everything that reads or
// writes gh's own credentials or configuration (auth, config, alias,
// extension, secret, ssh-key, gpg-key), runs code or a remote shell
// (extension, codespace), opens a browser, or uploads local files (gist) is
// absent.
var ghCommands = map[string]bool{
	"api": true, "pr": true, "issue": true, "repo": true, "run": true, "workflow": true,
	"release": true, "label": true, "search": true, "status": true, "cache": true,
	"ruleset": true, "project": true,
}

// ghRefusedSub are subcommands refused even under an allowed command: they
// run git with caller-controlled arguments, push or upload local files, or
// add keys.
var ghRefusedSub = map[string]bool{
	"repo clone": true, "repo sync": true, "repo fork": true, "repo create": true, "repo deploy-key": true,
	"repo set-default": true, "pr checkout": true, "release upload": true, "release download": true,
	"run download": true, "run watch": true,
}

// ghFileFlags read a local file named by their value. Only "-" (the job's
// stdin) is accepted for them.
var ghFileFlags = map[string]bool{
	"--input": true, "--body-file": true, "--notes-file": true, "--template": true,
	"--source": true, "--file": true,
}

// checkGHArgs checks a github job's argv: a gh invocation of an allowed
// command, each argument a single string (there is no shell to split or
// expand it), no end-of-flags marker (after which gh passes arguments to
// git), no flag that reads a local file except from stdin, and no argument
// naming a path outside the scratch directory the job runs in.
func checkGHArgs(args []string) string {
	if len(args) == 0 || len(args) > maxGHArgs {
		return fmt.Sprintf("a github job runs gh with 1 to %d arguments", maxGHArgs)
	}
	if args[0] == "gh" {
		return "a github job's args follow gh; they do not name it"
	}
	if !ghCommands[args[0]] {
		return "gh " + sanitize.Ident(args[0], 32) + " is not a command a github job may run"
	}
	if len(args) > 1 && ghRefusedSub[args[0]+" "+args[1]] {
		return "gh " + args[0] + " " + sanitize.Ident(args[1], 32) + " is not a command a github job may run"
	}
	for i, a := range args {
		if len(a) > maxGHArgBytes || !utf8.ValidString(a) || strings.ContainsRune(a, 0) {
			return "a github job's argument is too long or not text"
		}
		if a == "--" {
			return "a github job may not end gh's flags with --"
		}
		name, value, hasValue := strings.Cut(a, "=")
		if strings.HasPrefix(a, "--") && ghFileFlags[name] {
			v := value
			if !hasValue {
				if i+1 >= len(args) {
					return "gh " + name + " needs a value"
				}
				v = args[i+1]
			}
			if v != "-" {
				return "gh " + name + " may only read the job's stdin (-)"
			}
		}
		if a == "-F" || name == "--field" || (strings.HasPrefix(a, "-F") && len(a) > 2) {
			if why := checkGHField(args, i, args[0]); why != "" {
				return why
			}
		}
		// The endpoint of `gh api` (first or last) is an API path and may
		// start with "/".
		if args[0] == "api" && (i == 1 || i == len(args)-1) && !strings.HasPrefix(a, "-") && !isFlagValue(args, i) {
			if hasDotDot(a) {
				return "a github job's argument may not name a parent directory"
			}
			continue
		}
		if localPath(a) {
			return "a github job's argument may not name a path on this host"
		}
	}
	return ""
}

// checkGHField checks a -F/--field flag at args[i]. Under api, workflow and
// run it is a typed field whose "@file" value reads a file: only "@-" (stdin)
// is accepted. Under pr and issue it is --body-file: only "-".
func checkGHField(args []string, i int, cmd string) string {
	a := args[i]
	var v string
	switch {
	case strings.HasPrefix(a, "--field="):
		v = strings.TrimPrefix(a, "--field=")
	case strings.HasPrefix(a, "-F") && len(a) > 2:
		v = strings.TrimPrefix(a[2:], "=")
	default:
		if i+1 >= len(args) {
			return "gh " + a + " needs a value"
		}
		v = args[i+1]
	}
	switch cmd {
	case "api", "workflow", "run":
		if _, fv, ok := strings.Cut(v, "="); ok && strings.HasPrefix(fv, "@") && fv != "@-" {
			return "a github job's field may only read the job's stdin (@-)"
		}
	default:
		if v != "-" {
			return "gh -F may only read the job's stdin (-)"
		}
	}
	return ""
}

// localPath reports whether an argument, or the value of a key=value or
// --flag=value argument, names a path on this host outside the scratch
// directory: absolute, under a home directory, a Windows drive or share, or
// through a parent directory.
func localPath(a string) bool {
	cands := []string{a}
	if _, v, ok := strings.Cut(a, "="); ok {
		cands = append(cands, v)
		if _, fv, ok := strings.Cut(v, "@"); ok {
			cands = append(cands, fv)
		}
	}
	if _, v, ok := strings.Cut(a, "@"); ok {
		cands = append(cands, v)
	}
	for _, c := range cands {
		if strings.HasPrefix(c, "/") || strings.HasPrefix(c, "~") || strings.HasPrefix(c, `\`) ||
			(len(c) >= 2 && c[1] == ':' && (c[0]|0x20) >= 'a' && (c[0]|0x20) <= 'z') || hasDotDot(c) {
			return true
		}
	}
	return false
}

func hasDotDot(s string) bool {
	for _, seg := range strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == '\\' || r == '=' || r == '@' }) {
		if seg == ".." {
			return true
		}
	}
	return s == ".."
}

// runGitHubJob runs gh and shapes the answer Keleustes reads.
func (d *Daemon) runGitHubJob(ctx context.Context, args []string, stdin string) (json.RawMessage, string, error) {
	res, err := d.o.GH(ctx, args, stdin)
	if err != nil {
		return nil, "", err
	}
	out, err := json.Marshal(map[string]any{
		"stdout": vaultenv.Default.Scrub(res.Stdout), "stderr": vaultenv.Default.Scrub(res.Stderr),
		"exit": res.Exit, "truncated": res.Truncated,
	})
	return out, "", err
}

// ghEnvKeep are the credential variables gh itself reads, kept through the
// environment scrub so a host signed in that way runs its jobs too.
var ghEnvKeep = []string{"GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN"}

// runGH runs `gh args...` with no shell, in a fresh empty directory that is
// removed after, with a scrubbed environment (only gh's own credentials
// kept), no prompts, no pager and no colour, its own process group, and each
// output stream capped.
func runGH(ctx context.Context, args []string, stdin string) (GHResult, error) {
	exe, err := exec.LookPath("gh")
	if err != nil {
		return GHResult{}, errors.New("gh is not installed on this host")
	}
	dir, err := os.MkdirTemp("", "belai-gh-job-")
	if err != nil {
		return GHResult{}, err
	}
	defer os.RemoveAll(dir)
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Dir = dir
	cmd.Env = append(proc.ScrubEnvKeeping(os.Environ(), ghEnvKeep),
		"GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1", "GH_SPINNER_DISABLED=1", "NO_COLOR=1",
		"CLICOLOR=0", "GH_PAGER=", "PAGER=cat", "GIT_TERMINAL_PROMPT=0")
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr cappedBuffer
	stdout.max, stderr.max = maxGHOutput, maxGHOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	proc.SetProcessGroup(cmd)
	cmd.Cancel = func() error { return proc.Kill(cmd.Process.Pid) }
	cmd.WaitDelay = 5 * time.Second
	err = cmd.Run()
	res := GHResult{Stdout: strings.ToValidUTF8(stdout.String(), "�"), Stderr: strings.ToValidUTF8(stderr.String(), "�"),
		Truncated: stdout.cut || stderr.cut}
	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		return res, errors.New("gh ran past the job's deadline")
	case errors.As(err, &exit):
		res.Exit = exit.ExitCode()
	case err != nil:
		return res, errors.New("gh could not be started")
	}
	return res, nil
}

// cappedBuffer keeps the first max bytes written and drops the rest.
type cappedBuffer struct {
	bytes.Buffer
	max int
	cut bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room < len(p) {
		b.cut = true
		if room > 0 {
			b.Buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// Model job tasks.
const (
	ModelTaskDraft     = "draft"
	ModelTaskClassify  = "classify"
	ModelTaskAvatar    = "avatar"
	ModelTaskSystemOne = "systemone"
)

// parseModelJob reads a model job's task and keeps its payload for the task.
func parseModelJob(payload string) (string, json.RawMessage, string) {
	if len(payload) > maxModelPayload {
		return "", nil, "the model job's payload is too large"
	}
	var p struct {
		Task string `json:"task"`
	}
	if json.Unmarshal([]byte(payload), &p) != nil {
		return "", nil, "the model job's payload is not a JSON object with a task"
	}
	switch p.Task {
	case ModelTaskDraft, ModelTaskClassify, ModelTaskAvatar, ModelTaskSystemOne:
	default:
		return "", nil, "this Belai does not run that model task; update Belai on the host"
	}
	return p.Task, json.RawMessage(payload), ""
}

// factoryControl is the Keleustes control state the link last reported.
func (d *Daemon) factoryControl() factorylink.Control {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.control
}

// setFactoryControl records the control state and logs a change.
func (d *Daemon) setFactoryControl(c factorylink.Control) {
	d.mu.Lock()
	prev := d.control
	d.control = c
	d.mu.Unlock()
	if prev.Stopped != c.Stopped {
		if c.Stopped {
			d.logf("keleustes stopped the factory%s: no dispatch, job or remote prompt is taken until it resumes", reasonSuffix(c.Reason))
		} else {
			d.logf("keleustes resumed the factory")
		}
	}
	if prev.A2ABlackout != c.A2ABlackout {
		if c.A2ABlackout {
			d.logf("keleustes A2A blackout on%s: no A2A is relayed", reasonSuffix(c.Reason))
		} else {
			d.logf("keleustes A2A blackout lifted")
		}
	}
}

func reasonSuffix(r string) string {
	if r == "" {
		return ""
	}
	return " (" + r + ")"
}

// ghValueFlags are gh api flags whose value is the next argument.
var ghValueFlags = map[string]bool{
	"-X": true, "--method": true, "-H": true, "--header": true, "-f": true, "--raw-field": true,
	"-F": true, "--field": true, "--input": true, "-q": true, "--jq": true, "-t": true, "--template": true,
	"--hostname": true, "--cache": true, "-p": true, "--preview": true,
}

// isFlagValue reports whether args[i] is the value of the flag before it.
func isFlagValue(args []string, i int) bool { return i > 0 && ghValueFlags[args[i-1]] }
