package hostmgmt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/products"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/vaultenv"
)

// Class is an action's class (docs/gaps/host-management.md §6.1).
type Class string

// The classes.
const (
	ClassRead      Class = "read"
	ClassConfig    Class = "config"
	ClassProvision Class = "provision"
	ClassShell     Class = "shell"
)

// need is the host gate a class needs.
func (c Class) need() Level {
	switch c {
	case ClassRead:
		return LevelRead
	case ClassConfig:
		return LevelConfig
	}
	return LevelProvision
}

// kind is one row of the closed kind table.
type kind struct {
	class  Class
	params map[string]param
	// plan computes what a config, provision or shell action will do. It is
	// deterministic for the same inputs and host state, and its JSON is the
	// preview. It returns the refusal reason instead when the action cannot
	// run here.
	plan func(ctx context.Context, c *call) (*Plan, string)
	// run does the work. A kind with a plan gets it.
	run func(ctx context.Context, c *call, pl *Plan) result
	// blackout reports whether the action is refused while the A2A blackout
	// is on.
	blackout func(c *call) bool
}

// param is one parameter's validator: it returns the canonical value or the
// reason the value is refused. required parameters must be present.
type param struct {
	required bool
	check    func(c *call, v string) (string, error)
}

// kinds is the closed table. Keleustes sends exactly these parameter names.
var kinds map[string]kind

func init() {
	kinds = map[string]kind{
		"inventory_refresh": {class: ClassRead, run: runInventoryRefresh},
		"product_probe":     {class: ClassRead, params: ps("product!", pProduct), run: runProductProbe},
		"preflight":         {class: ClassRead, run: runPreflight},
		"config_get":        {class: ClassRead, params: ps("scope", pEnum("global", "project"), "path", pOfferedDir), run: runConfigGet},
		"log_tail":          {class: ClassRead, params: ps("lines", pInt(1, maxLogLines)), run: runLogTail},

		"config_set": {class: ClassConfig, params: ps("key!", pKey, "value!", pValue), plan: planConfigSet, run: runConfigSet,
			blackout: func(c *call) bool { return blackoutKey(c.p["key"]) }},
		"project_prefs_set": {class: ClassConfig, params: ps("path!", pOfferedDir, "key!", pPrefKey, "value", pValue), plan: planProjectPrefs, run: runProjectPrefs,
			blackout: func(c *call) bool { return blackoutKey(c.p["key"]) }},
		"agents_set": {class: ClassConfig, params: ps("path!", pOfferedDir, "profile!", pBuiltinProfile, "state!", pEnum("on", "off", "inherit")),
			plan: planAgentsSet, run: runProjectPrefs},
		"repo_trust":    {class: ClassConfig, params: ps("path!", pWorkspacePath), plan: planRepoTrust, run: runRepoTrust},
		"repo_untrust":  {class: ClassConfig, params: ps("path!", pAnyDir), plan: planRepoUntrust, run: runRepoUntrust},
		"worktree_drop": {class: ClassConfig, params: ps("path!", pWorktreePath), plan: planWorktreeDrop, run: runWorktreeDrop},
		"session_prune": {class: ClassConfig, plan: planSessionPrune, run: runSessionPrune},

		"product_install": {class: ClassProvision, params: ps("product!", pProduct, "method", pEnum("brew", "scoop", "direct"),
			"version", pVersion, "profile", pUUID), plan: planProductInstall, run: runSteps},
		"product_upgrade":   {class: ClassProvision, params: ps("product!", pProduct), plan: planProductUpgrade, run: runSteps},
		"product_uninstall": {class: ClassProvision, params: ps("product!", pProduct, "code", pUninstallCode), plan: planProductUninstall, run: runSteps},
		"product_configure": {class: ClassProvision, params: ps("product!", pProduct, "on", pIdentList, "purge", pBool,
			"remove_credentials", pBool, "scope", pEnum("user", "project"), "path", pOfferedDir), plan: planProductConfigure, run: runSteps},
		"product_auth":  {class: ClassProvision, params: ps("product!", pEnum(products.CLI)), plan: planProductAuth, run: runProductAuth},
		"belai_upgrade": {class: ClassProvision, params: ps("version", pVersion), plan: planBelaiUpgrade, run: runSteps},
		"rc_restart":    {class: ClassProvision, params: ps("force_after_s", pInt(0, 3600), "expect_version", pVersion), plan: planRCRestart, run: runRCRestart},
		"repo_clone": {class: ClassProvision, params: ps("forge_host!", pHost, "owner!", pOwner, "name!", pIdent, "depth", pInt(1, 100000)),
			plan: planRepoClone, run: runRepoClone},

		"shell_exec": {class: ClassShell, params: ps("argv_json!", pArgvJSON), plan: planShell, run: runShell},
	}
}

// ps builds a parameter table from name, validator pairs; a trailing "!"
// marks a required parameter.
func ps(pairs ...any) map[string]param {
	out := map[string]param{}
	for i := 0; i+1 < len(pairs); i += 2 {
		name := pairs[i].(string)
		req := strings.HasSuffix(name, "!")
		out[strings.TrimSuffix(name, "!")] = param{required: req, check: pairs[i+1].(func(*call, string) (string, error))}
	}
	return out
}

// Kinds lists the kinds this host executes, for HostManage.host_actions.
func Kinds() []string {
	out := make([]string, 0, len(kinds))
	for k := range kinds {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ClassOf is the class this host runs kind as; "" for an unknown kind.
func ClassOf(k string) Class { return kinds[k].class }

// call is one action being worked on.
type call struct {
	m     *Manager
	a     *nodev1.HostAction
	p     map[string]string
	grant *factorylink.Grant
	// pending lines for the next update, and the bytes sent so far.
	lines []string
	bytes int
	trunc bool
}

// result is how an action ended.
type result struct {
	state      string
	err        string
	resultJSON string
	command    string
	reason     string
}

func done(resultJSON string) result { return result{state: stateDone, resultJSON: resultJSON} }
func failed(why string) result      { return result{state: stateFailed, err: why} }
func handoff(command, reason string) result {
	return result{state: stateNeedsHuman, command: command, reason: reason}
}

// Plan is what an action will do, and its preview.
type Plan struct {
	Kind    string            `json:"kind"`
	Params  map[string]string `json:"params,omitempty"`
	Steps   []Step            `json:"steps,omitempty"`
	Files   []FileState       `json:"files,omitempty"`
	Changes []Change          `json:"changes,omitempty"`
	Handoff *Handoff          `json:"handoff,omitempty"`
	Notes   []string          `json:"notes,omitempty"`
}

// Step is one fixed program run, download or file removal.
type Step struct {
	Argv []string `json:"argv,omitempty"`
	Dir  string   `json:"dir,omitempty"`
	// Env names the variables the step gets from the action's vault grant;
	// never a value.
	Env      []string  `json:"env,omitempty"`
	Download *Download `json:"download,omitempty"`
	Remove   string    `json:"remove,omitempty"`
	// Backup, when set, is where the replaced file is kept (belai.prev).
	Backup string `json:"backup,omitempty"`
	// Timeout is the step's cap in seconds.
	Timeout int `json:"timeout_s,omitempty"`
}

// Download fetches a release asset and its checksums.txt, verifies the
// asset's sha256 and writes it to To.
type Download struct {
	URL       string `json:"url"`
	Checksums string `json:"checksums"`
	Asset     string `json:"asset"`
	To        string `json:"to"`
}

// FileState pins a file's content as it was planned against.
type FileState struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Change is one settings or preference change.
type Change struct {
	Key  string `json:"key"`
	From string `json:"from"`
	To   string `json:"to"`
}

// Handoff is a step only a person can do on the host.
type Handoff struct {
	Command string `json:"command"`
	Reason  string `json:"reason"`
}

// preview renders the plan as the person sees it (paths home-relative) and
// its sha256.
func (pl *Plan) preview(home string) (string, string) {
	d := *pl
	rel := func(s string) string {
		if home != "" && (s == home || strings.HasPrefix(s, home+"/")) {
			return "~" + strings.TrimPrefix(s, home)
		}
		return s
	}
	d.Steps = make([]Step, len(pl.Steps))
	for i, s := range pl.Steps {
		s.Dir, s.Remove, s.Backup = rel(s.Dir), rel(s.Remove), rel(s.Backup)
		argv := make([]string, len(s.Argv))
		for j, a := range s.Argv {
			argv[j] = rel(a)
		}
		s.Argv = argv
		if s.Download != nil {
			dl := *s.Download
			dl.To = rel(dl.To)
			s.Download = &dl
		}
		d.Steps[i] = s
	}
	d.Files = make([]FileState, len(pl.Files))
	for i, f := range pl.Files {
		d.Files[i] = FileState{Path: rel(f.Path), SHA256: f.SHA256}
	}
	if pl.Handoff != nil {
		h := *pl.Handoff
		h.Command = rel(h.Command)
		d.Handoff = &h
	}
	b, _ := json.Marshal(d)
	sum := sha256.Sum256(b)
	return string(b), hex.EncodeToString(sum[:])
}

// person reports whether a person asked for the action directly: the owner,
// from a click, not a plan, run or workflow.
func person(a *nodev1.HostAction) bool {
	o := a.GetOrigin()
	return o.GetActor() == "owner" && a.GetPlanRunId() == "" && o.GetPlanId() == "" && o.GetRunId() == "" && o.GetWorkflowId() == ""
}

// gate decides whether the action may run on this host. It returns the kind,
// the validated parameters, the refusal reason and the control word for the
// audit ("stopped" while the factory is stopped).
func (m *Manager) gate(c *call) (kind, string, string) {
	a := c.a
	k, ok := kinds[a.GetKind()]
	if !ok {
		return k, "this host does not run that kind of action (update Belai, or the kind is not one Keleustes may send)", ""
	}
	if Class(a.GetClass()) != k.class {
		return k, fmt.Sprintf("class mismatch: this host runs %s as %s", a.GetKind(), k.class), ""
	}
	if m.o.Level == LevelOff {
		return k, "host management is off on this host (belai rc --keleustes-manage=off)", ""
	}
	if m.o.Level < k.class.need() {
		return k, fmt.Sprintf("the host gate is %s; %s needs %s (belai rc --keleustes-manage)", m.o.Level, a.GetKind(), k.class.need()), ""
	}
	if k.class == ClassShell && !m.o.Shell {
		return k, "shell actions are off on this host (belai rc --keleustes-shell)", ""
	}
	if stopped, why := m.o.Stopped(); stopped {
		if k.class != ClassRead || !person(a) {
			msg := "the factory is stopped"
			if why != "" {
				msg += ": " + sanitize.Line(why, 200)
			}
			return k, msg, "stopped"
		}
	}
	if dl := a.GetDeadlineMs(); dl > 0 && m.o.Now().UnixMilli() > dl {
		return k, "the action's deadline passed before it ran", ""
	}
	c.p = map[string]string{}
	for key, v := range a.GetParams() {
		spec, ok := k.params[key]
		if !ok {
			return k, fmt.Sprintf("unknown parameter %q for %s", sanitize.Ident(key, 40), a.GetKind()), ""
		}
		if v == "" && !spec.required {
			continue
		}
		cv, err := spec.check(c, v)
		if err != nil {
			return k, sanitize.Ident(key, 40) + ": " + sanitize.Line(err.Error(), 200), ""
		}
		c.p[key] = cv
	}
	for key, spec := range k.params {
		if _, ok := c.p[key]; spec.required && !ok {
			return k, key + " is required", ""
		}
	}
	if k.blackout != nil && m.o.Blackout() && k.blackout(c) {
		return k, "refused during the A2A blackout: this change is tighten-only while it is on", ""
	}
	return k, "", ""
}

// process runs one action from the queue to its final update.
func (m *Manager) process(ctx context.Context, a *nodev1.HostAction) {
	c := &call{m: m, a: a}
	if a.GetKind() == "product_auth" {
		c.grant = factorylink.GrantFrom(a.GetVault(), m.o.Now())
		if c.grant != nil {
			vaultenv.Protect()
		}
	}
	defer c.grant.Drop()
	k, why, control := m.gate(c)
	if why != "" {
		m.refuse(ctx, c, why, control)
		return
	}
	var pl *Plan
	if k.plan != nil {
		pl, why = k.plan(ctx, c)
		if why != "" {
			m.refuse(ctx, c, why, "")
			return
		}
		pl.Kind = a.GetKind()
		preview, sha := pl.preview(m.o.UserHome)
		if a.GetDryRun() {
			m.update(ctx, c, &nodev1.HostActionUpdate{State: stateAccepted}, "")
			m.update(ctx, c, &nodev1.HostActionUpdate{State: stateDone, PreviewJson: preview, PreviewSha256: sha}, "")
			return
		}
		if (k.class == ClassProvision || k.class == ClassShell) && a.GetPreviewSha256() == "" {
			m.refuse(ctx, c, "this action needs a preview: run it as a dry run and confirm that preview", "")
			return
		}
		if p := a.GetPreviewSha256(); p != "" && p != sha {
			m.refuse(ctx, c, "preview stale: the host's plan changed since the preview was made", "")
			return
		}
	}
	m.update(ctx, c, &nodev1.HostActionUpdate{State: stateAccepted}, "")
	res := k.run(ctx, c, pl)
	u := &nodev1.HostActionUpdate{State: res.state, Error: sanitize.Line(res.err, 500), ResultJson: res.resultJSON,
		HandoffCommand: res.command, HandoffReason: res.reason}
	m.update(ctx, c, u, "")
	m.poke()
}

// refuse files a refusal.
func (m *Manager) refuse(ctx context.Context, c *call, why, control string) {
	m.o.Logf("refused keleustes host action %s (%s): %s", c.a.GetId(), sanitize.Ident(c.a.GetKind(), 40), why)
	m.update(ctx, c, &nodev1.HostActionUpdate{State: stateRefused, Error: why}, control)
}

// update sends one update, with the pending lines, and audits a state change.
func (m *Manager) update(ctx context.Context, c *call, u *nodev1.HostActionUpdate, control string) {
	u.Lines = append(c.lines, u.Lines...)
	c.lines = nil
	if u.Step == "" {
		u.Step = sanitize.Ident(c.a.GetKind(), 40)
	}
	m.emit(ctx, c.a.GetId(), u)
	switch u.GetState() {
	case stateAccepted, stateRefused, stateNeedsHuman, stateDone, stateFailed, stateCancelled:
		why := u.GetError()
		if u.GetState() == stateNeedsHuman {
			why = u.GetHandoffReason()
		}
		m.audit(c.a, u.GetState(), why, control)
	}
}

// maxActionBytes caps the lines one action sends; maxUpdateLines one update.
const (
	maxActionBytes = 64 << 10
	maxUpdateLines = 200
)

// line adds one output line, scrubbed and capped, and sends a running update
// when a batch is full.
func (c *call) line(ctx context.Context, s string) {
	if c.trunc {
		return
	}
	s = sanitize.Line(vaultenv.Default.Scrub(s), 1000)
	if c.bytes+len(s) > maxActionBytes {
		c.trunc = true
		c.lines = append(c.lines, "(output truncated at 64 KiB)")
		return
	}
	c.bytes += len(s)
	c.lines = append(c.lines, s)
	if len(c.lines) >= maxUpdateLines {
		c.m.update(ctx, c, &nodev1.HostActionUpdate{State: stateRunning}, "")
	}
}

// audit records a state change as host.action.*, with the origin.
func (m *Manager) audit(a *nodev1.HostAction, state, why, control string) {
	var k audit.Kind
	switch state {
	case stateAccepted:
		k = audit.HostActionAccepted
	case stateRefused:
		k = audit.HostActionRefused
	case stateNeedsHuman:
		k = audit.HostActionNeedsHuman
	default:
		k = audit.HostActionFinished
	}
	o := a.GetOrigin()
	actor := audit.ActorWeb
	if person(a) {
		actor = audit.ActorHuman
	}
	data := map[string]string{
		"action": a.GetId(), "kind": a.GetKind(), "class": string(ClassOf(a.GetKind())),
		"surface": o.GetSurface(), "run": o.GetRunId(), "workflow": o.GetWorkflowId(), "plan": o.GetPlanId(),
		"plan_run": a.GetPlanRunId(), "digest": paramsDigest(a.GetParams()), "preview": a.GetPreviewSha256(),
		"reason": why, "control": control,
	}
	if a.GetPlanRunId() != "" {
		data["step"] = strconv.Itoa(int(a.GetStep()))
	}
	if k == audit.HostActionFinished {
		data["state"] = state
	}
	if a.GetKind() == "shell_exec" {
		data["tool"] = shellTool(a.GetParams()["argv_json"])
	}
	for key, v := range data {
		if v == "" {
			delete(data, key)
		}
	}
	audit.Emit(audit.Fact{Kind: k, ActorKind: actor, Actor: sanitize.Ident(o.GetActor(), 64), Outcome: state, Data: data})
}

// paramsDigest is the sha256 of the params as sorted key=value lines.
func paramsDigest(p map[string]string) string {
	if len(p) == 0 {
		return ""
	}
	keys := make([]string, 0, len(p))
	for k := range p {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		fmt.Fprintf(h, "%s=%s\n", k, p[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// blackoutKey reports whether a config key is tighten-only during the A2A
// blackout.
func blackoutKey(key string) bool {
	return strings.HasPrefix(key, "a2a.") || strings.HasPrefix(key, "sync.remote_")
}

// resultJSON marshals v, or "{}".
func resultJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// elapsed is a short duration for a line.
func elapsed(d time.Duration) string { return d.Round(100 * time.Millisecond).String() }

// has reports whether s is in list.
func has(list []string, s string) bool { return slices.Contains(list, s) }
