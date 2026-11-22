package harness

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Launch tiers.
const (
	// TierPTY is a terminal harness: belai runs its own interactive TUI in a
	// pseudo-terminal and types prompts into it (belai rc-harness).
	TierPTY = "pty"
	// TierGUI is a desktop or IDE app. It can be opened on a directory and
	// takes no typed input.
	TierGUI = "gui"
)

// Confidence of a launch profile.
const (
	// ConfHost: checked against the installed binary's own --help.
	ConfHost = "H"
	// ConfDocs: from the vendor's documentation, not yet run here.
	ConfDocs = "M"
	// ConfUnverified: partial facts. Detected and listed, never started.
	ConfUnverified = "L"
)

// Native id kinds a profile can preset at launch.
const NativeUUID = "uuid4"

// Launch is how belai starts one harness. Every argv element is a literal or a
// single {placeholder} from a closed set, so nothing a dispatch carries reaches
// the command line except through a validated value.
type Launch struct {
	Tier string `json:"tier"`
	Conf string `json:"conf"`
	// Bins are binary names looked up on PATH, first match wins.
	Bins        []string `json:"bins"`
	VersionArgs []string `json:"version_args,omitempty"`
	// Argv starts a new interactive session. It never holds a print or
	// non-interactive flag (NeverFlags).
	Argv []string `json:"argv,omitempty"`
	// ModelFlag is appended when a model is chosen.
	ModelFlag []string `json:"model_flag,omitempty"`
	// Modes maps the harness's own permission modes onto extra argv. "default"
	// is the harness's default and adds nothing.
	Modes map[string][]string `json:"modes,omitempty"`
	// ResumeArgv resumes the native session {native_id}.
	ResumeArgv []string `json:"resume_argv,omitempty"`
	// NativeID is NativeUUID when the profile presets the harness's session
	// id at launch, so the native transcript is known before its first line.
	NativeID   string      `json:"native_id,omitempty"`
	Transcript *Transcript `json:"transcript,omitempty"`
	// MCP wires the per-session belai A2A bridge. Nil means the profile has
	// no way to add a server for one session without editing a user file, so
	// the session has no A2A.
	MCP *Wire `json:"mcp,omitempty"`
	// Hooks wires the per-session hook settings (Claude --settings).
	Hooks *Wire `json:"hooks,omitempty"`
	Input Input `json:"input,omitzero"`
	Keys  Keys  `json:"keys,omitzero"`
	// QuietMS is how long the screen must be still to read as idle when the
	// transcript says nothing.
	QuietMS int `json:"quiet_ms,omitempty"`
	// Dialogs are the first-run screens the harness puts up before it takes a
	// prompt (a folder trust question). Each is shown to the owner as an ask;
	// belai never answers one itself.
	Dialogs []Dialog `json:"dialogs,omitempty"`
	// NameFlag names the native session ({thread_name}) where the harness takes
	// a name, so it is findable in the harness's own session list.
	NameFlag []string `json:"name_flag,omitempty"`
	// Continuity is how a resume is checked to be the recorded session:
	// "session-id-match" (the native transcript records the resumed id).
	Continuity []string `json:"continuity,omitempty"`
	// Caveats are machine-readable limits of this harness, shown in the picker.
	Caveats []Caveat `json:"caveats,omitempty"`
	// GrantEnv are the only variable names a Keleustes vault key may be
	// handed to this harness under (key mode handoff or always). Never a URL,
	// endpoint, proxy or host variable.
	GrantEnv []string `json:"grant_env,omitempty"`
	// NeverFlags may never appear in a produced argv.
	NeverFlags []string `json:"never_flags,omitempty"`
	// AppBins are the desktop app's binaries, and Open the argv that opens
	// the app on {cwd} (the GUI tier: no typed input, no mirror).
	AppBins []string `json:"app_bins,omitempty"`
	Open    []string `json:"open,omitempty"`
	// Source is where the facts came from (a vendor doc URL, or "host").
	Source string `json:"source,omitempty"`
	// MinVersion is the oldest harness version the profile's facts hold for.
	// A host-checked profile pins the version it was checked on; a probed
	// version below it, or one that cannot be read, is not launched.
	MinVersion string `json:"min_version,omitempty"`
	// HelpArgs print the flags a vendor-docs profile is checked against on
	// the installed binary (default --help).
	HelpArgs []string `json:"help_args,omitempty"`

	// installChecked is set only by CheckInstall, never from JSON: a
	// vendor-docs profile whose every flag the installed binary's help names.
	installChecked bool
}

// Transcript names the harness's own transcript store.
type Transcript struct {
	// Dialect is an agentstore format ("jsonl-claude", "jsonl-codex", ...).
	Dialect string `json:"dialect"`
	// Path is the store, "~/"-relative, with {placeholders}; a glob is allowed
	// in the last segment.
	Path string `json:"path"`
	// Locate says how a session without a preset id is found: "new-file"
	// (the newest file under Path's directory whose recorded cwd matches) or
	// "sqlite-row" (a new session row for the cwd).
	Locate string `json:"locate,omitempty"`
}

// Wire is how a per-session file or value reaches the harness.
type Wire struct {
	// How is "flag-file" (Flag then the file path), "flag-json" (Flag then the
	// JSON inline), "flag-cmd" (Flag then the bridge command line) or
	// "env-file" (Env set to the file path).
	How  string `json:"how"`
	Flag string `json:"flag,omitempty"`
	Env  string `json:"env,omitempty"`
	// Dialect is the config dialect written for the file ("claude", "codex").
	Dialect string `json:"dialect,omitempty"`
}

// Input is how a prompt is typed.
type Input struct {
	// Paste is "bracketed" when the TUI honours DECSET 2004.
	Paste string `json:"paste,omitempty"`
	// Submit is the key that sends the composed prompt (default "enter").
	Submit        string `json:"submit,omitempty"`
	SubmitDelayMS int    `json:"submit_delay_ms,omitempty"`
	// Multiline without bracketed paste: "refuse", "join" or "backslash".
	Multiline string `json:"multiline,omitempty"`
}

// Keys are the session's keys.
type Keys struct {
	Interrupt string `json:"interrupt,omitempty"`
	// Exit is typed in order to quit gracefully: a key name or a literal line.
	Exit []string `json:"exit,omitempty"`
	// Allow are the key names the owner may send from the screen view.
	Allow []string `json:"allow,omitempty"`
}

// Placeholders an argv element may name.
var placeholders = []string{"bin", "thread_name", "native_id", "model", "cwd", "cwd_slug", "sid", "mcp_file", "mcp_json", "mcp_cmd", "settings_file"}

var (
	placeholderRe = regexp.MustCompile(`\{([a-z_]+)\}`)
	// ModelShape is the only shape a model id may take.
	ModelShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$`)
	// NativeIDShape is a native session id or resume target.
	NativeIDShape = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	// ThreadNameShape is a native session name belai passes.
	ThreadNameShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,63}$`)
	caveatShape     = regexp.MustCompile(`^[a-z][a-z0-9_]{1,63}$`)
)

var (
	grantEnvShape = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)
	grantEnvDeny  = regexp.MustCompile(`(_BASE_URL|_URL|_ENDPOINT|_PROXY|_HOST)$|^HTTPS?_PROXY$|^(PATH|HOME|SHELL|LD_.*|DYLD_.*)$`)
)

// GrantEnvName reports whether name may carry a handed-off key: an upper-case
// variable name that is not a URL, endpoint, proxy, host or loader variable.
func GrantEnvName(name string) bool {
	return grantEnvShape.MatchString(name) && !grantEnvDeny.MatchString(name)
}

// KeyBytes are the key names a profile may list, and what each one types.
var KeyBytes = map[string]string{
	"enter": "\r", "esc": "\x1b", "tab": "\t", "up": "\x1b[A", "down": "\x1b[B",
	"left": "\x1b[D", "right": "\x1b[C", "ctrl-c": "\x03", "y": "y", "n": "n",
	"1": "1", "2": "2", "3": "3", "4": "4", "p": "p", "space": " ", "backspace": "\x7f",
}

// Launchable reports whether the profile may be started: a PTY profile whose
// facts were checked against an installed binary, either when it was written
// (ConfHost) or on this host (a vendor-docs profile after CheckInstall).
func (l *Launch) Launchable() bool {
	return l.MayLaunch() && (l.Conf == ConfHost || l.installChecked)
}

// MayLaunch reports whether the profile can become launchable: a PTY profile
// from a host check or vendor docs. A vendor-docs one still needs
// CheckInstall on the installed binary.
func (l *Launch) MayLaunch() bool {
	return l != nil && l.Tier == TierPTY && (l.Conf == ConfHost || l.Conf == ConfDocs) && len(l.Argv) > 0
}

// NeedsInstallCheck reports whether the profile is a vendor-docs PTY profile
// not yet checked against the installed binary.
func (l *Launch) NeedsInstallCheck() bool {
	return l.MayLaunch() && l.Conf == ConfDocs && !l.installChecked
}

// HelpArgv is the argv (after the binary) that prints the harness's flags.
func (l *Launch) HelpArgv() []string {
	if l == nil || len(l.HelpArgs) == 0 {
		return []string{"--help"}
	}
	return slices.Clone(l.HelpArgs)
}

// Flags lists every flag literal the profile can put on a command line:
// argv, resume, model, name and mode lists and the wiring flags, each
// without an "=value" part, sorted and unique.
func (l *Launch) Flags() []string {
	if l == nil {
		return nil
	}
	lists := [][]string{l.Argv, l.ResumeArgv, l.ModelFlag, l.NameFlag}
	for _, m := range l.ModeNames() {
		lists = append(lists, l.Modes[m])
	}
	for _, w := range []*Wire{l.MCP, l.Hooks} {
		if w != nil && w.Flag != "" {
			lists = append(lists, []string{w.Flag})
		}
	}
	var out []string
	for _, list := range lists {
		for _, el := range list {
			if !strings.HasPrefix(el, "-") || el == "-" || el == "--" {
				continue
			}
			f, _, _ := strings.Cut(el, "=")
			if !slices.Contains(out, f) {
				out = append(out, f)
			}
		}
	}
	slices.Sort(out)
	return out
}

// CheckInstall checks a vendor-docs profile against the installed binary's
// help text: every flag the profile can pass must be named there as a whole
// word. It returns a copy that is launchable, or the first missing flag. A
// host-checked profile is returned as it is.
func (l *Launch) CheckInstall(help string) (*Launch, error) {
	if !l.MayLaunch() {
		return nil, errors.New("this harness has no launch profile to check")
	}
	if l.Conf == ConfHost {
		return l, nil
	}
	if strings.TrimSpace(help) == "" {
		return nil, errors.New("the installed binary printed no help")
	}
	for _, f := range l.Flags() {
		if !helpNames(help, f) {
			return nil, fmt.Errorf("the installed binary's help does not name %s", f)
		}
	}
	c := *l
	c.installChecked = true
	return &c, nil
}

// helpNames reports whether help names flag as a whole word: not as the
// prefix of a longer flag ("--mode" in "--model").
func helpNames(help, flag string) bool {
	for i := 0; ; {
		j := strings.Index(help[i:], flag)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(flag)
		before := start == 0 || !flagRune(rune(help[start-1]))
		after := end == len(help) || !flagRune(rune(help[end]))
		if before && after {
			return true
		}
		i = start + 1
	}
}

func flagRune(r rune) bool {
	return r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
}

var (
	minVersionShape = regexp.MustCompile(`^[0-9]{1,6}(\.[0-9]{1,6}){0,3}$`)
	versionIn       = regexp.MustCompile(`[0-9]{1,6}(\.[0-9]{1,6}){1,3}`)
)

// VersionOK checks a probed version line against MinVersion. With a pin, a
// line holding no dotted version is refused: an unknown version is not
// assumed new enough.
func (l *Launch) VersionOK(line string) error {
	if l == nil || l.MinVersion == "" {
		return nil
	}
	got := versionIn.FindString(line)
	if got == "" {
		return fmt.Errorf("the version is unknown; this profile needs %s or later", l.MinVersion)
	}
	if compareVersions(got, l.MinVersion) < 0 {
		return fmt.Errorf("version %s is older than %s, the oldest this profile was checked on", got, l.MinVersion)
	}
	return nil
}

// compareVersions compares dotted numeric versions; missing parts are 0.
func compareVersions(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := range max(len(pa), len(pb)) {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// ModeNames lists the profile's modes, "default" first.
func (l *Launch) ModeNames() []string {
	if l == nil {
		return nil
	}
	var out []string
	for m := range l.Modes {
		if m != "default" {
			out = append(out, m)
		}
	}
	slices.Sort(out)
	if _, ok := l.Modes["default"]; ok || len(out) > 0 {
		out = append([]string{"default"}, out...)
	}
	return out
}

// Validate checks a profile: the tier, known placeholders only, no never-flag
// in any fixed argv, known key names, and wiring shapes.
func (l *Launch) Validate() error {
	if l == nil {
		return nil
	}
	switch l.Tier {
	case TierPTY, TierGUI:
	default:
		return fmt.Errorf("tier %q", l.Tier)
	}
	switch l.Conf {
	case ConfHost, ConfDocs, ConfUnverified:
	default:
		return fmt.Errorf("conf %q", l.Conf)
	}
	if len(l.Bins)+len(l.AppBins) == 0 {
		return errors.New("no bins")
	}
	if l.Tier == TierGUI && (len(l.AppBins) == 0 || len(l.Argv) > 0) {
		return errors.New("a gui profile has app_bins and no argv")
	}
	for _, b := range append(slices.Clone(l.Bins), l.AppBins...) {
		if b == "" || strings.ContainsAny(b, "/\\ \t") {
			return fmt.Errorf("bin %q is not a bare name", b)
		}
	}
	lists := map[string][]string{"argv": l.Argv, "model_flag": l.ModelFlag, "resume_argv": l.ResumeArgv,
		"version_args": l.VersionArgs, "open": l.Open, "name_flag": l.NameFlag}
	for m, a := range l.Modes {
		lists["modes."+m] = a
	}
	for name, list := range lists {
		for _, el := range list {
			for _, m := range placeholderRe.FindAllStringSubmatch(el, -1) {
				if !slices.Contains(placeholders, m[1]) {
					return fmt.Errorf("%s: unknown placeholder {%s}", name, m[1])
				}
			}
			if l.never(el) {
				return fmt.Errorf("%s: %q is a never flag", name, el)
			}
		}
	}
	if l.Tier == TierPTY && l.Conf != ConfUnverified {
		if len(l.Argv) == 0 || l.Argv[0] != "{bin}" {
			return errors.New("argv must start with {bin}")
		}
		if len(l.ResumeArgv) > 0 && l.ResumeArgv[0] != "{bin}" {
			return errors.New("resume_argv must start with {bin}")
		}
	}
	for _, e := range l.GrantEnv {
		if !GrantEnvName(e) {
			return fmt.Errorf("grant_env %q is not a key variable", e)
		}
	}
	if l.MinVersion != "" && !minVersionShape.MatchString(l.MinVersion) {
		return fmt.Errorf("min_version %q is not a dotted version", l.MinVersion)
	}
	for _, el := range l.HelpArgs {
		if placeholderRe.MatchString(el) || l.never(el) {
			return fmt.Errorf("help_args: %q is not a fixed help flag", el)
		}
	}
	if l.NativeID != "" && l.NativeID != NativeUUID {
		return fmt.Errorf("native_id %q", l.NativeID)
	}
	for _, k := range append(append([]string{l.Keys.Interrupt}, l.Keys.Allow...), l.Input.Submit) {
		if k != "" {
			if _, ok := KeyBytes[k]; !ok {
				return fmt.Errorf("unknown key %q", k)
			}
		}
	}
	for _, w := range []*Wire{l.MCP, l.Hooks} {
		if w == nil {
			continue
		}
		switch w.How {
		case "flag-file", "flag-json", "flag-cmd":
			if !strings.HasPrefix(w.Flag, "-") {
				return fmt.Errorf("%s wiring needs a flag", w.How)
			}
		case "env-file":
			if w.Env == "" {
				return errors.New("env-file wiring needs an env name")
			}
		default:
			return fmt.Errorf("wiring %q", w.How)
		}
	}
	for _, c := range l.Caveats {
		if !caveatShape.MatchString(c.Code) || c.Note == "" {
			return fmt.Errorf("caveat %q", c.Code)
		}
	}
	for _, c := range l.Continuity {
		if c != ContinuitySessionID {
			return fmt.Errorf("continuity %q", c)
		}
	}
	if err := l.validateDialogs(); err != nil {
		return err
	}
	switch l.Input.Multiline {
	case "", "refuse", "join", "backslash":
	default:
		return fmt.Errorf("multiline %q", l.Input.Multiline)
	}
	return nil
}

// never reports whether el is, or sets, a never flag ("--flag" or "--flag=v").
func (l *Launch) never(el string) bool {
	for _, f := range l.NeverFlags {
		if el == f || strings.HasPrefix(el, f+"=") {
			return true
		}
	}
	return false
}

// Values fills the placeholders of one launch.
type Values struct {
	Bin, NativeID, Model, Cwd, Sid string
	// ThreadName names the native session (NameFlag); empty leaves it out.
	ThreadName string
	// Mode is one of Modes' keys; "" is "default".
	Mode string
	// Resume starts from ResumeArgv with NativeID as the session to resume.
	Resume bool
	// MCPFile, MCPJSON and MCPCmd carry the bridge wiring; SettingsFile the
	// hook settings. Empty leaves the wiring out.
	MCPFile, MCPJSON, MCPCmd, SettingsFile string
}

// CwdSlug is Claude Code's project directory name for cwd: every "/" and "."
// becomes "-".
func CwdSlug(cwd string) string {
	return strings.NewReplacer("/", "-", ".", "-").Replace(cwd)
}

// Build produces the argv for one launch. The model must have ModelShape and
// the native id NativeIDShape; the mode must be one the profile maps; and the
// result is checked once more against NeverFlags.
func (l *Launch) Build(v Values) ([]string, error) {
	if !l.Launchable() {
		return nil, errors.New("this harness has no verified launch profile")
	}
	if v.Bin == "" || v.Cwd == "" {
		return nil, errors.New("launch needs a binary and a directory")
	}
	if v.Model != "" && !ModelShape.MatchString(v.Model) {
		return nil, fmt.Errorf("model %q is not a model id", v.Model)
	}
	if v.NativeID != "" && !NativeIDShape.MatchString(v.NativeID) {
		return nil, errors.New("the native session id has the wrong shape")
	}
	if v.Sid != "" && !NativeIDShape.MatchString(v.Sid) {
		return nil, errors.New("the session id has the wrong shape")
	}
	vals := map[string]string{"bin": v.Bin, "native_id": v.NativeID, "model": v.Model, "cwd": v.Cwd,
		"cwd_slug": CwdSlug(v.Cwd), "sid": v.Sid, "mcp_file": v.MCPFile, "mcp_json": v.MCPJSON,
		"mcp_cmd": v.MCPCmd, "settings_file": v.SettingsFile, "thread_name": v.ThreadName}
	base := l.Argv
	if v.Resume {
		if len(l.ResumeArgv) == 0 {
			return nil, errors.New("this harness cannot resume a session")
		}
		if v.NativeID == "" {
			return nil, errors.New("resume needs the native session id")
		}
		base = l.ResumeArgv
	}
	var out []string
	add := func(list []string) error {
		for _, el := range list {
			var miss string
			s := placeholderRe.ReplaceAllStringFunc(el, func(m string) string {
				k := m[1 : len(m)-1]
				if vals[k] == "" {
					miss = k
				}
				return vals[k]
			})
			if miss != "" {
				return fmt.Errorf("launch needs {%s}", miss)
			}
			out = append(out, s)
		}
		return nil
	}
	if err := add(base); err != nil {
		return nil, err
	}
	mode := v.Mode
	if mode == "" {
		mode = "default"
	}
	extra, ok := l.Modes[mode]
	if !ok && mode != "default" {
		return nil, fmt.Errorf("mode %q is not one this harness maps", v.Mode)
	}
	if err := add(extra); err != nil {
		return nil, err
	}
	if v.Model != "" {
		if len(l.ModelFlag) == 0 {
			return nil, errors.New("this harness takes no model at launch")
		}
		if err := add(l.ModelFlag); err != nil {
			return nil, err
		}
	}
	if v.ThreadName != "" && len(l.NameFlag) > 0 && !v.Resume {
		if !ThreadNameShape.MatchString(v.ThreadName) {
			return nil, errors.New("the session name has the wrong shape")
		}
		if err := add(l.NameFlag); err != nil {
			return nil, err
		}
	}
	if w := l.MCP; w != nil && strings.HasPrefix(w.How, "flag-") {
		val := map[string]string{"flag-file": v.MCPFile, "flag-json": v.MCPJSON, "flag-cmd": v.MCPCmd}[w.How]
		if val != "" {
			out = append(out, w.Flag, val)
		}
	}
	if w := l.Hooks; w != nil && w.How == "flag-file" && v.SettingsFile != "" {
		out = append(out, w.Flag, v.SettingsFile)
	}
	for _, el := range out {
		if l.never(el) {
			return nil, fmt.Errorf("%q may never be passed to this harness", el)
		}
	}
	return out, nil
}

// Dialog is one screen the harness shows and waits on, and the fixed keys
// each answer sends.
type Dialog struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Match are texts that must all be on the screen (compared without
	// whitespace).
	Match   []string       `json:"match"`
	Options []DialogOption `json:"options"`
}

// DialogOption is one answer.
type DialogOption struct {
	ID    string   `json:"id"`
	Label string   `json:"label"`
	Keys  []string `json:"keys"`
}

func (l *Launch) validateDialogs() error {
	for _, d := range l.Dialogs {
		if !NativeIDShape.MatchString(d.ID) || d.Title == "" || len(d.Match) == 0 || len(d.Options) < 2 {
			return fmt.Errorf("dialog %q is incomplete", d.ID)
		}
		for _, o := range d.Options {
			if !NativeIDShape.MatchString(o.ID) || len(o.Keys) == 0 {
				return fmt.Errorf("dialog %q option %q is incomplete", d.ID, o.ID)
			}
			for _, k := range o.Keys {
				if _, ok := KeyBytes[k]; !ok {
					return fmt.Errorf("dialog %q: unknown key %q", d.ID, k)
				}
			}
		}
	}
	return nil
}

// ContinuitySessionID: a resumed session's native transcript must record the
// resumed id, or the resume is refused as continuity_unverified.
const ContinuitySessionID = "session-id-match"

// Caveat is one machine-readable limit of a harness: a closed code and a
// short note for the owner.
type Caveat struct {
	Code string `json:"code"`
	Note string `json:"note"`
}

// Capabilities are what a launchable profile supports, for the advert.
type Capabilities struct {
	Resume, Kill, Asks, A2A, Name bool
	Continuity                    []string
}

// Caps derives the profile's capabilities. Kill is the process-group stop,
// which belai has on POSIX only.
func (l *Launch) Caps(posix bool) Capabilities {
	if l == nil {
		return Capabilities{}
	}
	return Capabilities{Resume: len(l.ResumeArgv) > 0, Kill: posix && l.Tier == TierPTY, Asks: len(l.Dialogs) > 0,
		A2A: l.MCP != nil, Name: len(l.NameFlag) > 0, Continuity: l.Continuity}
}
