package config

import (
	"regexp"
	"slices"
	"strings"
)

// Per-repository switches for the built-in agents and the Vulnetix
// detections (docs/gaps/host-management.md §5.7). They live in the
// host-private ProjectPrefs file like the other flat keys, so a repository
// cannot set them, and they are written through the same SetFlat path the
// website's and Keleustes's project_prefs requests use. The keys:
//
//   - agents.builtin.<profile>: true or false for one built-in profile
//     (belai:<name>); unset inherits the global agents.enabled;
//   - vulnetix.scans.<subcommand>: one scanner subcommand of
//     VulnetixSubcommandNames;
//   - vulnetix.dep_watch and vulnetix.sweep.
//
// rc refuses a worker start of a built-in profile that is off for the
// directory ("disabled for repo"), and the project sweep skips a directory
// whose vulnetix.sweep is false.

// PrefsRepo holds the per-repository switches.
type PrefsRepo struct {
	Builtin  map[string]bool `json:"builtin,omitempty"`
	Scans    map[string]bool `json:"scans,omitempty"`
	DepWatch *bool           `json:"dep_watch,omitempty"`
	Sweep    *bool           `json:"sweep,omitempty"`
}

// builtinProfileRE is a built-in agent profile name as a key may carry it.
var builtinProfileRE = regexp.MustCompile(`^belai:[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidBuiltinProfileName reports whether name has the shape of a built-in
// agent profile.
func ValidBuiltinProfileName(name string) bool { return builtinProfileRE.MatchString(name) }

// lookupRepoPrefKey returns the shape of a per-repository key.
func lookupRepoPrefKey(key string) (prefKey, bool) {
	switch {
	case key == "vulnetix.dep_watch", key == "vulnetix.sweep":
		return prefKey{kind: prefBool}, true
	case strings.HasPrefix(key, "agents.builtin."):
		if ValidBuiltinProfileName(strings.TrimPrefix(key, "agents.builtin.")) {
			return prefKey{kind: prefBool}, true
		}
	case strings.HasPrefix(key, "vulnetix.scans."):
		if slices.Contains(VulnetixSubcommandNames, strings.TrimPrefix(key, "vulnetix.scans.")) {
			return prefKey{kind: prefBool}, true
		}
	}
	return prefKey{}, false
}

// isRepoPrefKey reports whether key is a per-repository key.
func isRepoPrefKey(key string) bool {
	_, ok := lookupRepoPrefKey(key)
	return ok
}

// flatRepo adds the per-repository keys set in p to out.
func (p ProjectPrefs) flatRepo(out map[string]any) {
	r := p.Repo
	if r == nil {
		return
	}
	for name, on := range r.Builtin {
		out["agents.builtin."+name] = on
	}
	for sub, on := range r.Scans {
		out["vulnetix.scans."+sub] = on
	}
	if r.DepWatch != nil {
		out["vulnetix.dep_watch"] = *r.DepWatch
	}
	if r.Sweep != nil {
		out["vulnetix.sweep"] = *r.Sweep
	}
}

// setRepoFlat sets one per-repository key; key is known to be one.
func (p *ProjectPrefs) setRepoFlat(key string, b bool) {
	if p.Repo == nil {
		p.Repo = &PrefsRepo{}
	}
	r := p.Repo
	switch {
	case key == "vulnetix.dep_watch":
		r.DepWatch = &b
	case key == "vulnetix.sweep":
		r.Sweep = &b
	case strings.HasPrefix(key, "agents.builtin."):
		if r.Builtin == nil {
			r.Builtin = map[string]bool{}
		}
		r.Builtin[strings.TrimPrefix(key, "agents.builtin.")] = b
	case strings.HasPrefix(key, "vulnetix.scans."):
		if r.Scans == nil {
			r.Scans = map[string]bool{}
		}
		r.Scans[strings.TrimPrefix(key, "vulnetix.scans.")] = b
	}
}

// unsetRepoFlat clears one per-repository key.
func (p *ProjectPrefs) unsetRepoFlat(key string) {
	r := p.Repo
	if r == nil {
		return
	}
	switch {
	case key == "vulnetix.dep_watch":
		r.DepWatch = nil
	case key == "vulnetix.sweep":
		r.Sweep = nil
	case strings.HasPrefix(key, "agents.builtin."):
		delete(r.Builtin, strings.TrimPrefix(key, "agents.builtin."))
	case strings.HasPrefix(key, "vulnetix.scans."):
		delete(r.Scans, strings.TrimPrefix(key, "vulnetix.scans."))
	}
	if len(r.Builtin) == 0 && len(r.Scans) == 0 && r.DepWatch == nil && r.Sweep == nil {
		p.Repo = nil
	}
}

// BuiltinAgentState is a built-in profile's switch for a directory: "on",
// "off" or "inherit".
func (p ProjectPrefs) BuiltinAgentState(profile string) string {
	if p.Repo != nil {
		if on, ok := p.Repo.Builtin[profile]; ok {
			if on {
				return "on"
			}
			return "off"
		}
	}
	return "inherit"
}

// BuiltinAgentOff reports whether the host's preferences for workdir turn the
// built-in profile off. A preference file that cannot be read turns nothing
// off here; config.Resolve reports it where it is used.
func BuiltinAgentOff(workdir, profile string) bool {
	if !ValidBuiltinProfileName(profile) {
		return false
	}
	p, err := LoadProjectPrefs(workdir)
	return err == nil && p.BuiltinAgentState(profile) == "off"
}

// SweepOff reports whether the host's preferences for workdir keep it out of
// the project sweep.
func SweepOff(workdir string) bool {
	p, err := LoadProjectPrefs(workdir)
	return err == nil && p.Repo != nil && p.Repo.Sweep != nil && !*p.Repo.Sweep
}
