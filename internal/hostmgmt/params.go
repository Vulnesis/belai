package hostmgmt

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/products"
)

// Typed parameter validators. Each returns the canonical value or a reason
// that names no value. Nothing here is free text: a value is an enum, a
// number, an identifier or a path kept under an allowed root.

var (
	identRE   = regexp.MustCompile(`^[A-Za-z0-9._:/@-]{1,128}$`)
	versionRE = regexp.MustCompile(`^v?[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}([-+][0-9A-Za-z.]{1,40})?$`)
	hostRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(:[0-9]{1,5})?$`)
	ownerRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}(/[A-Za-z0-9][A-Za-z0-9._-]{0,99}){0,7}$`)
	keyRE     = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[A-Za-z0-9_:.-]+)*$`)
)

func pIdent(_ *call, v string) (string, error) {
	if !identRE.MatchString(v) || strings.HasPrefix(v, "-") {
		return "", errors.New("not an identifier")
	}
	return v, nil
}

func pEnum(words ...string) func(*call, string) (string, error) {
	return func(_ *call, v string) (string, error) {
		if !slices.Contains(words, v) {
			return "", fmt.Errorf("takes one of %s", strings.Join(words, ", "))
		}
		return v, nil
	}
}

func pInt(lo, hi int) func(*call, string) (string, error) {
	return func(_ *call, v string) (string, error) {
		n, err := strconv.Atoi(v)
		if err != nil || n < lo || n > hi {
			return "", fmt.Errorf("takes a whole number from %d to %d", lo, hi)
		}
		return strconv.Itoa(n), nil
	}
}

func pBool(_ *call, v string) (string, error) {
	if v != "true" && v != "false" {
		return "", errors.New("takes true or false")
	}
	return v, nil
}

func pProduct(_ *call, v string) (string, error) {
	if !products.Valid(v) {
		return "", errors.New("takes cli, package_firewall, ai_firewall or sensor")
	}
	return v, nil
}

func pVersion(_ *call, v string) (string, error) {
	if !versionRE.MatchString(v) {
		return "", errors.New("takes a release version such as v1.2.3")
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v, nil
}

func pHost(_ *call, v string) (string, error) {
	v = strings.ToLower(v)
	if !hostRE.MatchString(v) {
		return "", errors.New("not a host name")
	}
	return v, nil
}

func pOwner(_ *call, v string) (string, error) {
	if !ownerRE.MatchString(v) || strings.Contains(v, "..") {
		return "", errors.New("not an owner")
	}
	return v, nil
}

func pKey(_ *call, v string) (string, error) {
	if len(v) > 128 || !keyRE.MatchString(v) {
		return "", errors.New("not a settings key")
	}
	return v, nil
}

func pPrefKey(_ *call, v string) (string, error) {
	if len(v) > 128 || !keyRE.MatchString(v) {
		return "", errors.New("not a preference key")
	}
	return v, nil
}

// pValue is a settings or preference value: a short single token. Its type
// is checked against the key's table (config.RemoteKeys, config.ProjectPrefs).
func pValue(_ *call, v string) (string, error) {
	if len(v) > 128 || strings.ContainsAny(v, " \t\r\n\x00") {
		return "", errors.New("not a value")
	}
	return v, nil
}

func pBuiltinProfile(_ *call, v string) (string, error) {
	if !config.ValidBuiltinProfileName(v) {
		return "", errors.New("not a built-in agent profile")
	}
	return v, nil
}

// pIdentList is a comma-separated list of identifiers, at most 64, sorted and
// without duplicates.
func pIdentList(_ *call, v string) (string, error) {
	var out []string
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !identRE.MatchString(s) || strings.HasPrefix(s, "-") {
			return "", errors.New("takes a comma-separated list of identifiers")
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if len(out) > 64 {
		return "", errors.New("lists at most 64 identifiers")
	}
	slices.Sort(out)
	return strings.Join(out, ","), nil
}

// pArgvJSON is a JSON array of 1 to 64 strings, each at most 4096 bytes with
// no NUL.
func pArgvJSON(_ *call, v string) (string, error) {
	var argv []string
	if json.Unmarshal([]byte(v), &argv) != nil || len(argv) == 0 || len(argv) > 64 {
		return "", errors.New("takes a JSON array of 1 to 64 strings")
	}
	for _, a := range argv {
		if len(a) > 4096 || strings.ContainsRune(a, 0) {
			return "", errors.New("an argument is too long or holds a NUL")
		}
	}
	if argv[0] == "" || strings.HasPrefix(argv[0], "-") {
		return "", errors.New("the first word is not a program")
	}
	b, _ := json.Marshal(argv)
	return string(b), nil
}

// pOfferedDir is a directory the rc daemon offers.
func pOfferedDir(c *call, v string) (string, error) {
	return c.m.resolveUnder(v, c.m.offeredDirs(), "a directory this host offers")
}

// pAnyDir is a directory the daemon offers or the project registry trusts.
func pAnyDir(c *call, v string) (string, error) {
	return c.m.resolveUnder(v, append(c.m.offeredDirs(), c.m.workspaceRoots()...), "a directory this host offers or a workspace directory")
}

// pWorkspacePath is a directory under one of the user's workspace_dirs.
func pWorkspacePath(c *call, v string) (string, error) {
	return c.m.resolveUnder(v, c.m.workspaceRoots(), "a directory under workspace_dirs")
}

// pWorktreePath is a directory under the fleet worktrees directory.
func pWorktreePath(c *call, v string) (string, error) {
	root, err := config.WorktreesDir()
	if err != nil {
		return "", errors.New("this host has no worktrees directory")
	}
	return c.m.resolveUnder(v, []string{root}, "a directory under the worktrees directory")
}

func (m *Manager) offeredDirs() []string {
	if m.o.Hooks.Dirs == nil {
		return nil
	}
	return m.o.Hooks.Dirs()
}

// workspaceRoots are the user's global workspace_dirs, expanded.
func (m *Manager) workspaceRoots() []string {
	s, err := config.LoadGlobal()
	if err != nil {
		return nil
	}
	var out []string
	for _, d := range s.WorkspaceDirs {
		if strings.HasPrefix(d, "~/") {
			d = filepath.Join(m.o.UserHome, d[2:])
		}
		if filepath.IsAbs(d) {
			out = append(out, filepath.Clean(d))
		}
	}
	return out
}

// resolveUnder resolves raw (absolute, or ~/ under the user's home) and keeps
// it only when it, with every symlink resolved, is inside one of roots (also
// resolved). A ".." segment is refused before anything is resolved.
func (m *Manager) resolveUnder(raw string, roots []string, what string) (string, error) {
	if raw == "" || len(raw) > 4096 || strings.ContainsRune(raw, 0) {
		return "", errors.New("not a path")
	}
	if strings.HasPrefix(raw, "~/") || raw == "~" {
		raw = filepath.Join(m.o.UserHome, strings.TrimPrefix(strings.TrimPrefix(raw, "~"), "/"))
	}
	if !filepath.IsAbs(raw) {
		return "", errors.New("must be absolute or start with ~/")
	}
	for _, seg := range strings.Split(filepath.ToSlash(raw), "/") {
		if seg == ".." {
			return "", errors.New("a path may not hold ..")
		}
	}
	real, err := filepath.EvalSymlinks(filepath.Clean(raw))
	if err != nil {
		return "", errors.New("no such directory on this host")
	}
	if info, err := os.Stat(real); err != nil || !info.IsDir() {
		return "", errors.New("not a directory")
	}
	for _, r := range roots {
		rr, err := filepath.EvalSymlinks(r)
		if err != nil {
			continue
		}
		if within(rr, real) {
			return real, nil
		}
	}
	return "", fmt.Errorf("not %s (symlinks resolved)", what)
}

// within reports whether path is root or below it.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
