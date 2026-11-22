package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/vulnetix/belai/internal/harness"
)

// Env is what tools.json records about environment variables: each
// harness's own names (keyed by canonical id) and the provider keys of its
// service entries, which a multi-provider harness reads too. A name may end
// in "*" (a prefix).
type Env struct {
	Own      map[string][]string
	Services []string
}

// ToolEnv reads the env lists of tools.json.
func ToolEnv(cli string, ov Overlay) (Env, error) {
	tools, err := parseTools(filepath.Join(cli, "internal", "aibom", "catalog", "tools.json"))
	if err != nil {
		return Env{}, err
	}
	e := Env{Own: map[string][]string{}}
	for _, t := range tools {
		if t.Type == "service" {
			e.Services = append(e.Services, t.Env...)
			continue
		}
		id := t.ID
		if c, ok := ov.IDMap[id]; ok {
			id = c
		}
		e.Own[id] = append(e.Own[id], t.Env...)
	}
	return e, nil
}

// Names reports whether tools.json names name for harness id: in the
// harness's own list, or as a service's provider key.
func (e Env) Names(id, name string) bool {
	return envMatch(e.Own[id], name) || envMatch(e.Services, name)
}

func envMatch(list []string, name string) bool {
	for _, p := range list {
		if pre, ok := strings.CutSuffix(p, "*"); ok {
			if pre != "" && strings.HasPrefix(name, pre) {
				return true
			}
		} else if p == name {
			return true
		}
	}
	return false
}

// ApplyLaunch reads the hand-written launch profiles (launch.json, keyed by
// canonical id) and sets each harness's Launch. A profile for an id the
// registry does not hold, one that fails harness.Launch.Validate, a
// host-checked PTY profile without a min_version pin, or a grant_env name
// tools.json does not record for that harness stops the build: a launch
// profile decides what argv belai may run and where a vault key may go.
func ApplyLaunch(hs []harness.Harness, path string, env Env) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var profiles map[string]*harness.Launch
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&profiles); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	byID := map[string]int{}
	for i, h := range hs {
		byID[h.ID] = i
	}
	ids := make([]string, 0, len(profiles))
	for id := range profiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		i, ok := byID[id]
		if !ok {
			return fmt.Errorf("%s: %q is not a registry id", path, id)
		}
		l := profiles[id]
		if err := l.Validate(); err != nil {
			return fmt.Errorf("%s: %s: %w", path, id, err)
		}
		if err := checkProfile(id, l, env); err != nil {
			return fmt.Errorf("%s: %s: %w", path, id, err)
		}
		hs[i].Launch = l
	}
	return nil
}

// checkProfile holds the generator's rules beyond Validate.
func checkProfile(id string, l *harness.Launch, env Env) error {
	if l.Tier == harness.TierPTY && l.Conf == harness.ConfHost && l.MinVersion == "" {
		return fmt.Errorf("a host-checked profile pins min_version (the version it was checked on)")
	}
	var unknown []string
	for _, name := range l.GrantEnv {
		if !env.Names(id, name) {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		return fmt.Errorf("grant_env %s: tools.json records no such variable for this harness or a provider", strings.Join(unknown, ", "))
	}
	return nil
}

// launchCell is the Launch column of the docs table.
func launchCell(l *harness.Launch) string {
	switch {
	case l == nil:
		return ""
	case l.Tier == harness.TierGUI:
		return "open only"
	case l.MayLaunch():
		return "PTY (" + l.Conf + ")"
	}
	return "PTY, unverified"
}
