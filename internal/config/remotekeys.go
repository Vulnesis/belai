package config

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// RemoteKeys is the closed table of global settings keys a Keleustes console
// may change on this host (`belai rc --keleustes-manage=config` or higher,
// docs/gaps/host-management.md §5.2). It is a sibling of the ProjectPrefs
// keys: every key has a type and a range, and a mode. A set key takes any
// value in its range. A tighten key only moves towards the safer end; moving
// it back needs the host's own --web-allow-guardrails-off, and an a2a.* key
// never moves back from a console at all.
//
// Anything outside the table is refused. NeverRemote names the keys that are
// refused with a reason of their own, because they route credentials, widen
// what may run, or are the host's final gate.

// RemoteMode is how a console may change a key.
type RemoteMode string

// The modes.
const (
	RemoteSet     RemoteMode = "set"
	RemoteTighten RemoteMode = "tighten"
)

// RemoteType is the value shape a key takes.
type RemoteType string

// The types.
const (
	RemoteBool  RemoteType = "bool"
	RemoteInt   RemoteType = "int"
	RemoteWord  RemoteType = "word"
	RemoteIdent RemoteType = "ident"
	// RemoteURL is an http(s) collector URL with no credentials, query or
	// fragment; empty clears it.
	RemoteURL RemoteType = "url"
	// RemoteEnvRef names a host environment variable ("env:NAME"); empty
	// removes the entry. A secret's value never goes through a console.
	RemoteEnvRef RemoteType = "env_ref"
)

// TelemetryHeaderPrefix starts the key of one OTLP export header
// (telemetry.headers.<Name>, docs/telemetry.md#keleustes).
const TelemetryHeaderPrefix = "telemetry.headers."

// telemetryHeaderName is the shape of an HTTP header name a console may set.
var telemetryHeaderName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)

// envRef is "env:NAME" with an environment variable name.
var envRef = regexp.MustCompile(`^env:[A-Z_][A-Z0-9_]{0,63}$`)

// RemoteKey is one row of the table.
type RemoteKey struct {
	Key  string
	Type RemoteType
	Mode RemoteMode
	// Min and Max bound an int.
	Min, Max int
	// Words are a word key's values, loosest first for a tighten key.
	Words []string
	// Tight is the safer value of a tighten bool.
	Tight bool
	// Always keeps the key tighten-only even on a host that allows guardrails
	// off.
	Always bool
}

// remoteIdent is the shape of an identifier value (a model id).
var remoteIdent = regexp.MustCompile(`^[A-Za-z0-9._:/@-]{1,128}$`)

var remoteKeys = []RemoteKey{
	{Key: "model", Type: RemoteIdent, Mode: RemoteSet},
	{Key: "effort", Type: RemoteWord, Mode: RemoteSet, Words: []string{"low", "medium", "high", "none"}},
	{Key: "agents.enabled", Type: RemoteBool, Mode: RemoteSet},
	{Key: "agents.max_workers", Type: RemoteInt, Mode: RemoteSet, Min: 1, Max: 64},
	{Key: "agents.factory_reserved_workers", Type: RemoteInt, Mode: RemoteSet, Min: 0, Max: 64},
	{Key: "agents.clone", Type: RemoteBool, Mode: RemoteSet},
	{Key: "session_retention_days", Type: RemoteInt, Mode: RemoteSet, Min: 1, Max: 3650},
	{Key: "guardrails", Type: RemoteBool, Mode: RemoteTighten, Tight: true},
	{Key: "ask_permission", Type: RemoteBool, Mode: RemoteTighten, Tight: true},
	{Key: "read_only", Type: RemoteBool, Mode: RemoteTighten, Tight: true},
	{Key: "sandbox.mode", Type: RemoteWord, Mode: RemoteTighten, Words: []string{"off", "auto", "required"}},
	{Key: "sandbox.network", Type: RemoteWord, Mode: RemoteTighten, Words: []string{SandboxNetworkAllow, SandboxNetworkProxy, SandboxNetworkDeny}},
	{Key: "sync.remote_prompts", Type: RemoteBool, Mode: RemoteTighten, Tight: false},
	{Key: "sync.remote_answers", Type: RemoteBool, Mode: RemoteTighten, Tight: false},
	{Key: "sync.hooks", Type: RemoteBool, Mode: RemoteTighten, Tight: false},
	{Key: "a2a.enabled", Type: RemoteBool, Mode: RemoteTighten, Tight: false, Always: true},
	{Key: "a2a.filter", Type: RemoteWord, Mode: RemoteTighten, Words: []string{A2AFilterAll, A2AFilterRepo, A2AFilterOff}, Always: true},
	// OpenTelemetry export (docs/telemetry.md): facts only, never content.
	// Headers are the telemetry.headers.<Name> family (LookupRemoteKey).
	{Key: "telemetry.otlp_endpoint", Type: RemoteURL, Mode: RemoteSet},
	{Key: "telemetry.traces", Type: RemoteBool, Mode: RemoteSet},
	{Key: "telemetry.metrics", Type: RemoteBool, Mode: RemoteSet},
}

// RemoteKeys lists the table in a stable order.
func RemoteKeys() []RemoteKey {
	out := slices.Clone(remoteKeys)
	slices.SortFunc(out, func(a, b RemoteKey) int { return strings.Compare(a.Key, b.Key) })
	return out
}

// LookupRemoteKey returns the row for key.
func LookupRemoteKey(key string) (RemoteKey, bool) {
	for _, k := range remoteKeys {
		if k.Key == key {
			return k, true
		}
	}
	if name, ok := strings.CutPrefix(key, TelemetryHeaderPrefix); ok && telemetryHeaderName.MatchString(name) {
		return RemoteKey{Key: key, Type: RemoteEnvRef, Mode: RemoteSet}, true
	}
	return RemoteKey{}, false
}

// remoteURL checks a collector URL: http or https, a host, nothing else
// that could carry a credential (user info, query, fragment).
func remoteURL(raw string) bool {
	if len(raw) > 128 {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" &&
		u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == ""
}

// neverRemotePrefixes are refused whatever else is true: they route keys to
// another endpoint, widen what may run, or are only the host's to change.
var neverRemotePrefixes = []string{
	"providers", "mcp", "forges", "permissions", "classifier", "hooks",
	"update_check", "workspace_dirs", "allow_project_workspace_dirs", "bash_rewrite",
}

// rcGateKeys are the belai rc flags, which no setting holds and no console sets.
var rcGateKeys = []string{
	"web_controls", "web_shell", "web_project_settings", "web_allow_guardrails_off",
	"no_clone", "allow_private_cidr", "keleustes_manage", "keleustes_shell",
}

// NeverRemote reports whether key is one a console may never change, and
// why.
func NeverRemote(key string) (bool, string) {
	k := strings.ToLower(key)
	if strings.Contains(k, "dangerously") {
		return true, "a dangerously key is never changed remotely"
	}
	for _, g := range rcGateKeys {
		if k == g || strings.TrimPrefix(k, "rc.") == g {
			return true, "an rc gate is the host's final gate and is never changed remotely"
		}
	}
	for _, p := range neverRemotePrefixes {
		if k == p || strings.HasPrefix(k, p+".") {
			return true, p + " is never changed remotely"
		}
	}
	return false, ""
}

// ErrLoosen is the refusal of a change that moves a tighten key towards the
// looser end.
var ErrLoosen = errors.New("tighten only: this change loosens a safety setting")

// RemoteValue reads key's effective value from s, as the console sees it.
func RemoteValue(s Settings, key string) (string, bool) {
	b := strconv.FormatBool
	switch key {
	case "model":
		return s.Model, true
	case "effort":
		return s.Effort, true
	case "agents.enabled":
		return b(s.AgentsEnabled()), true
	case "agents.max_workers":
		return strconv.Itoa(s.MaxWorkers()), true
	case "agents.factory_reserved_workers":
		return strconv.Itoa(s.FactoryReservedWorkersSetting()), true
	case "agents.clone":
		return b(s.AgentsCloneEnabled()), true
	case "session_retention_days":
		return strconv.Itoa(s.SessionRetention()), true
	case "guardrails":
		return b(s.GuardrailsEnabled()), true
	case "ask_permission":
		return b(s.AskPermissionEnabled()), true
	case "read_only":
		return b(s.ReadOnlyEnabled()), true
	case "sandbox.mode":
		return s.Sandbox.ModeOr(), true
	case "sandbox.network":
		return s.Sandbox.NetworkOr(), true
	case "sync.remote_prompts":
		return b(s.SyncRemotePromptsEnabled()), true
	case "sync.remote_answers":
		return b(s.SyncRemoteAnswersEnabled()), true
	case "sync.hooks":
		return b(s.SyncItemEnabled("hook")), true
	case "a2a.enabled":
		return b(s.A2AEnabled()), true
	case "a2a.filter":
		return s.A2AFilter(), true
	}
	t := s.Telemetry
	if t == nil {
		t = &TelemetrySettings{}
	}
	switch key {
	case "telemetry.otlp_endpoint":
		return t.OTLPEndpoint, true
	case "telemetry.traces":
		return b(t.Traces == nil || *t.Traces), true
	case "telemetry.metrics":
		return b(t.Metrics == nil || *t.Metrics), true
	}
	if name, ok := strings.CutPrefix(key, TelemetryHeaderPrefix); ok {
		v := t.Headers[name]
		if v != "" && !envRef.MatchString(v) {
			// A literal the host's owner wrote stays on the host.
			v = "(set on host)"
		}
		return v, true
	}
	return "", false
}

// ParseRemote checks raw against k's type and range and returns it in
// canonical form.
func (k RemoteKey) ParseRemote(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	switch k.Type {
	case RemoteBool:
		v, err := strconv.ParseBool(raw)
		if err != nil || (raw != "true" && raw != "false") {
			return "", fmt.Errorf("%s takes true or false", k.Key)
		}
		return strconv.FormatBool(v), nil
	case RemoteInt:
		n, err := strconv.Atoi(raw)
		if err != nil || n < k.Min || n > k.Max {
			return "", fmt.Errorf("%s takes a whole number from %d to %d", k.Key, k.Min, k.Max)
		}
		return strconv.Itoa(n), nil
	case RemoteWord:
		if !slices.Contains(k.Words, raw) {
			return "", fmt.Errorf("%s takes one of %s", k.Key, strings.Join(k.Words, ", "))
		}
		return raw, nil
	case RemoteIdent:
		if !remoteIdent.MatchString(raw) {
			return "", fmt.Errorf("%s takes an identifier", k.Key)
		}
		return raw, nil
	case RemoteURL:
		raw = strings.TrimRight(raw, "/")
		if raw != "" && !remoteURL(raw) {
			return "", fmt.Errorf("%s takes an http:// or https:// collector URL without credentials, query or fragment", k.Key)
		}
		return raw, nil
	case RemoteEnvRef:
		if raw != "" && !envRef.MatchString(raw) {
			return "", fmt.Errorf("%s names a host environment variable (env:NAME); a secret value is never set remotely", sanitizeKey(k.Key))
		}
		return raw, nil
	}
	return "", fmt.Errorf("%s has no type", k.Key)
}

// Loosens reports whether moving from cur to next moves a tighten key towards
// its looser end. Both are canonical values.
func (k RemoteKey) Loosens(cur, next string) bool {
	if k.Mode != RemoteTighten || cur == next {
		return false
	}
	switch k.Type {
	case RemoteBool:
		return next != strconv.FormatBool(k.Tight)
	case RemoteWord:
		return slices.Index(k.Words, next) < slices.Index(k.Words, cur)
	}
	return true
}

// ApplyRemote sets key to raw on s, after the table, the never-remote list and
// the tighten rule. allowLoosen is the host's --web-allow-guardrails-off; it
// never lets an Always key loosen. It returns the old and new canonical
// values.
func ApplyRemote(s *Settings, key, raw string, allowLoosen bool) (string, string, error) {
	if never, why := NeverRemote(key); never {
		return "", "", errors.New(why)
	}
	k, ok := LookupRemoteKey(key)
	if !ok {
		return "", "", fmt.Errorf("%s is not a key Keleustes may change", sanitizeKey(key))
	}
	next, err := k.ParseRemote(raw)
	if err != nil {
		return "", "", err
	}
	cur, _ := RemoteValue(*s, key)
	if k.Loosens(cur, next) && (!allowLoosen || k.Always) {
		return cur, next, ErrLoosen
	}
	setRemote(s, key, next)
	return cur, next, nil
}

// sanitizeKey keeps a refused key printable in a reason.
func sanitizeKey(key string) string {
	if len(key) > 64 {
		key = key[:64]
	}
	var b strings.Builder
	for _, r := range key {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}

// setRemote writes a canonical value; the key is in the table.
func setRemote(s *Settings, key, v string) {
	bp := func() *bool { x := v == "true"; return &x }
	ip := func() *int { n, _ := strconv.Atoi(v); return &n }
	agents := func() *AgentsSettings {
		if s.Agents == nil {
			s.Agents = &AgentsSettings{}
		}
		return s.Agents
	}
	sync := func() *SyncSettings {
		if s.Sync == nil {
			s.Sync = &SyncSettings{}
		}
		return s.Sync
	}
	sandbox := func() *SandboxSettings {
		if s.Sandbox == nil {
			s.Sandbox = &SandboxSettings{}
		}
		return s.Sandbox
	}
	a2a := func() *A2ASettings {
		if s.A2A == nil {
			s.A2A = &A2ASettings{}
		}
		return s.A2A
	}
	switch key {
	case "model":
		s.Model = v
	case "effort":
		s.Effort = v
	case "agents.enabled":
		agents().Enabled = bp()
	case "agents.max_workers":
		agents().MaxWorkers = ip()
	case "agents.factory_reserved_workers":
		agents().FactoryReservedWorkers = ip()
	case "agents.clone":
		agents().Clone = bp()
	case "session_retention_days":
		s.SessionRetentionDays = ip()
	case "guardrails":
		s.Guardrails = bp()
	case "ask_permission":
		s.AskPermission = bp()
	case "read_only":
		s.ReadOnly = bp()
	case "sandbox.mode":
		sandbox().Mode = v
	case "sandbox.network":
		sandbox().Network = v
	case "sync.remote_prompts":
		sync().RemotePrompts = bp()
	case "sync.remote_answers":
		sync().RemoteAnswers = bp()
	case "sync.hooks":
		sync().Hooks = bp()
	case "a2a.enabled":
		a2a().Enabled = bp()
	case "a2a.filter":
		a2a().Filter = v
	}
	if s.Telemetry == nil && strings.HasPrefix(key, "telemetry.") {
		s.Telemetry = &TelemetrySettings{}
	}
	switch key {
	case "telemetry.otlp_endpoint":
		s.Telemetry.OTLPEndpoint = v
	case "telemetry.traces":
		s.Telemetry.Traces = bp()
	case "telemetry.metrics":
		s.Telemetry.Metrics = bp()
	}
	if name, ok := strings.CutPrefix(key, TelemetryHeaderPrefix); ok {
		if v == "" {
			delete(s.Telemetry.Headers, name)
			return
		}
		if s.Telemetry.Headers == nil {
			s.Telemetry.Headers = map[string]string{}
		}
		s.Telemetry.Headers[name] = v
	}
}
