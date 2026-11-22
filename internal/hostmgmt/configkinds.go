package hostmgmt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/products"
	"github.com/vulnetix/belai/internal/secretshape"
	"github.com/vulnetix/belai/internal/vaultenv"
)

// config_get, config_set, project_prefs_set and agents_set
// (docs/gaps/host-management.md §5.2, §5.7).

// settingsSHA256 is the sha256 of the global settings file as it is on disk
// (of nothing when there is none), the value config_set's if_match names.
func settingsSHA256() (string, []byte, error) {
	path, err := config.GlobalSettingsPath()
	if err != nil {
		return "", nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", nil, err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), data, nil
}

// secretKeyRE names a settings key whose value is a credential.
var secretKeyRE = regexp.MustCompile(`(?i)(^|_)(api_?key|token|secret|secrets|password|passwd|credentials?|private_key|bearer|cookie|authorization)$`)

// secretMaps are maps whose every value is withheld (an MCP server's env,
// headers and secrets, a provider's headers).
var secretMaps = map[string]bool{"env": true, "headers": true, "secrets": true}

var present = map[string]any{"present": true}

// redact walks a decoded settings document and replaces every credential with
// {"present":true}: a key that names one, every value of an env, headers or
// secrets map, and any string that has a secret's shape.
func redact(v any, all bool) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			switch {
			case all:
				out[k] = present
			case secretMaps[strings.ToLower(k)]:
				out[k] = redact(val, true)
			case secretKeyRE.MatchString(k) && !empty(val):
				out[k] = present
			default:
				out[k] = redact(val, false)
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = redact(e, all)
		}
		return out
	case string:
		if all || secretshape.Holds([]byte(x)) {
			return present
		}
		return vaultenv.Default.Scrub(x)
	}
	if all {
		return present
	}
	return v
}

func empty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case map[string]any:
		return len(x) == 0
	case []any:
		return len(x) == 0
	}
	return false
}

// redactedSettings is s as a redacted JSON document.
func redactedSettings(s config.Settings) any {
	b, err := json.Marshal(s)
	if err != nil {
		return map[string]any{}
	}
	var doc any
	if json.Unmarshal(b, &doc) != nil {
		return map[string]any{}
	}
	return redact(doc, false)
}

type remoteKeyView struct {
	Key   string   `json:"key"`
	Type  string   `json:"type"`
	Mode  string   `json:"mode"`
	Value string   `json:"value"`
	Min   *int     `json:"min,omitempty"`
	Max   *int     `json:"max,omitempty"`
	Words []string `json:"words,omitempty"`
}

func runConfigGet(_ context.Context, c *call, _ *Plan) result {
	if c.p["scope"] == "project" {
		dir := c.p["path"]
		if dir == "" {
			return failed("a project scope names its path")
		}
		proj, err := config.LoadProject(dir)
		if err != nil {
			return failed("the project's settings could not be read")
		}
		prefs, err := config.LoadProjectPrefs(dir)
		if err != nil {
			return failed("the project's preferences could not be read")
		}
		flat := map[string]string{}
		for k, v := range prefs.Flat() {
			flat[k] = prefString(v)
		}
		return done(resultJSON(map[string]any{"scope": "project", "path": products.HomeRel(c.m.o.UserHome, dir),
			"settings": redactedSettings(proj), "prefs": flat}))
	}
	s, err := config.LoadGlobal()
	if err != nil {
		return failed("the host's settings could not be read")
	}
	sha, _, err := settingsSHA256()
	if err != nil {
		return failed("the host's settings could not be read")
	}
	var keys []remoteKeyView
	for _, k := range config.RemoteKeys() {
		v, _ := config.RemoteValue(s, k.Key)
		kv := remoteKeyView{Key: k.Key, Type: string(k.Type), Mode: string(k.Mode), Value: v, Words: k.Words}
		if k.Type == config.RemoteInt {
			lo, hi := k.Min, k.Max
			kv.Min, kv.Max = &lo, &hi
		}
		keys = append(keys, kv)
	}
	return done(resultJSON(map[string]any{"scope": "global", "settings_sha256": sha, "settings": redactedSettings(s), "remote_keys": keys}))
}

func prefString(v any) string {
	switch x := v.(type) {
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case string:
		return x
	}
	return ""
}

func planConfigSet(_ context.Context, c *call) (*Plan, string) {
	key, raw := c.p["key"], c.p["value"]
	if never, why := config.NeverRemote(key); never {
		return nil, why
	}
	if c.a.GetIfMatch() == "" {
		return nil, "config_set names the settings_sha256 it was made against (if_match)"
	}
	sha, _, err := settingsSHA256()
	if err != nil {
		return nil, "the host's settings could not be read"
	}
	if sha != c.a.GetIfMatch() {
		return nil, "settings changed on host"
	}
	s, err := config.LoadGlobal()
	if err != nil {
		return nil, "the host's settings could not be read"
	}
	from, to, err := config.ApplyRemote(&s, key, raw, c.m.o.Gates.AllowGuardrailsOff)
	if err != nil {
		return nil, err.Error()
	}
	if err := config.ValidateSettings(s); err != nil {
		return nil, "the change would make the settings invalid"
	}
	path, _ := config.GlobalSettingsPath()
	return &Plan{Params: map[string]string{"key": key, "value": to}, Changes: []Change{{Key: key, From: from, To: to}},
		Files: []FileState{{Path: path, SHA256: sha}}}, ""
}

func runConfigSet(_ context.Context, c *call, pl *Plan) result {
	// The plan just checked if_match; read once more so a write that raced it
	// is caught rather than overwritten.
	sha, data, err := settingsSHA256()
	if err != nil || sha != c.a.GetIfMatch() {
		return failed("settings changed on host")
	}
	s, err := config.LoadGlobal()
	if err != nil {
		return failed("the host's settings could not be read")
	}
	ch := pl.Changes[0]
	if _, _, err := config.ApplyRemote(&s, ch.Key, ch.To, c.m.o.Gates.AllowGuardrailsOff); err != nil {
		return failed(err.Error())
	}
	path, err := config.GlobalSettingsPath()
	if err != nil {
		return failed("the host's settings path is unknown")
	}
	if len(data) > 0 {
		if err := os.WriteFile(path+".bak."+c.a.GetId(), data, 0o600); err != nil {
			return failed("the settings backup could not be written; nothing was changed")
		}
	}
	if err := config.SaveGlobal(s); err != nil {
		return failed("the settings could not be written")
	}
	next, _, _ := settingsSHA256()
	return done(resultJSON(map[string]any{"key": ch.Key, "from": ch.From, "to": ch.To, "settings_sha256": next}))
}

// prefValue decodes a preference value the way the website's JSON does: a
// boolean, a number or a word; "" clears the key.
func prefValue(raw string) any {
	switch raw {
	case "true":
		return true
	case "false":
		return false
	}
	if f, err := strconv.ParseFloat(raw, 64); err == nil {
		return f
	}
	return raw
}

func planProjectPrefs(_ context.Context, c *call) (*Plan, string) {
	if !c.m.o.Gates.WebProjectSettings {
		return nil, "this host does not let Keleustes change project settings; start belai rc with --web-project-settings"
	}
	key, raw := c.p["key"], c.p["value"]
	// The preference is checked against a copy now so a bad key or value is
	// refused before the ack; rc checks it again when it writes.
	cur, err := config.LoadProjectPrefs(c.p["path"])
	if err != nil {
		return nil, "the project's preferences could not be read"
	}
	from := prefString(cur.Flat()[key])
	next := cur
	if raw == "" {
		err = next.UnsetFlat(key)
	} else {
		err = next.SetFlat(key, prefValue(raw))
	}
	if err != nil {
		return nil, err.Error()
	}
	return &Plan{Params: map[string]string{"path": c.p["path"], "key": key, "value": raw},
		Changes: []Change{{Key: key, From: from, To: raw}}}, ""
}

func planAgentsSet(ctx context.Context, c *call) (*Plan, string) {
	if !has(builtinAgents(), c.p["profile"]) {
		return nil, "this host has no built-in agent profile by that name"
	}
	c.p["key"] = "agents.builtin." + c.p["profile"]
	switch c.p["state"] {
	case "on":
		c.p["value"] = "true"
	case "off":
		c.p["value"] = "false"
	default:
		c.p["value"] = ""
	}
	return planProjectPrefs(ctx, c)
}

// runProjectPrefs writes through rc's project_prefs path.
func runProjectPrefs(_ context.Context, c *call, pl *Plan) result {
	if c.m.o.Hooks.SetProjectPrefs == nil {
		return failed("this daemon cannot change project preferences")
	}
	key, raw := pl.Params["key"], pl.Params["value"]
	var set map[string]any
	var unset []string
	if raw == "" {
		unset = []string{key}
	} else {
		set = map[string]any{key: prefValue(raw)}
	}
	report, why := c.m.o.Hooks.SetProjectPrefs(pl.Params["path"], set, unset)
	if why != "" {
		return failed(why)
	}
	return done(resultJSON(map[string]string{"report": report}))
}
