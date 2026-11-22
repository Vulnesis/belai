package hostmgmt

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vulnetix/belai/internal/agentprofile"
	"github.com/vulnetix/belai/internal/builddetect"
	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/gitinfo"
	"github.com/vulnetix/belai/internal/lintdetect"
	"github.com/vulnetix/belai/internal/proc"
	"github.com/vulnetix/belai/internal/projectregistry"
	"github.com/vulnetix/belai/internal/testdetect"
	"github.com/vulnetix/belai/internal/trustgate"
)

// repo_trust, repo_untrust, repo_clone and worktree_drop
// (docs/gaps/host-management.md §5.6), and the per-repository detections
// the inventory reports (§5.7).

// gitRoot is the repository root of dir, or "".
func gitRoot(dir string) string {
	info, ok := gitinfo.Detect(dir)
	if !ok {
		return ""
	}
	if r, err := filepath.EvalSymlinks(info.Root); err == nil {
		return r
	}
	return info.Root
}

func planRepoTrust(_ context.Context, c *call) (*Plan, string) {
	dir := c.p["path"]
	if gitRoot(dir) != dir {
		return nil, "only the root of an existing git repository can be trusted"
	}
	if trusted, _, _, err := projectregistry.TrustOf(dir); err == nil && trusted {
		return nil, "that repository is already trusted"
	}
	return &Plan{Params: map[string]string{"path": dir}, Notes: []string{"trust the directory only, never its proposed workspace_dirs"}}, ""
}

func runRepoTrust(_ context.Context, c *call, pl *Plan) result {
	if err := trustgate.Grant(pl.Params["path"], nil); err != nil {
		return failed("the trust could not be recorded")
	}
	return done(resultJSON(map[string]bool{"trusted": true}))
}

func planRepoUntrust(_ context.Context, c *call) (*Plan, string) {
	dir := c.p["path"]
	if trusted, _, _, err := projectregistry.TrustOf(dir); err != nil || !trusted {
		return nil, "that directory is not trusted on this host"
	}
	return &Plan{Params: map[string]string{"path": dir}}, ""
}

func runRepoUntrust(_ context.Context, _ *call, pl *Plan) result {
	n, err := projectregistry.Untrust(config.WorkdirKey(pl.Params["path"]))
	if err != nil {
		return failed("the trust could not be revoked")
	}
	return done(resultJSON(map[string]int{"untrusted": n}))
}

// cloneTarget is where repo_clone puts a repository (§5.6): <first
// workspace_dir>/<name>. A host with no workspace_dirs falls back to the
// worktrees directory's repos/<owner>/<name> (host/owner/name off
// github.com), where Software Factory clones live, and note says so.
func (m *Manager) cloneTarget(forgeHost, owner, name string) (parent, rel, note string, err error) {
	if roots := m.workspaceRoots(); len(roots) > 0 {
		return roots[0], name, "", nil
	}
	wt, err := config.WorktreesDir()
	if err != nil {
		return "", "", "", errors.New("this host has no workspace_dirs and no worktrees directory")
	}
	rel = filepath.Join(owner, name)
	if forgeHost != "github.com" {
		rel = filepath.Join(strings.ReplaceAll(forgeHost, ":", "_"), filepath.FromSlash(owner), name)
	}
	return filepath.Join(wt, "repos"), rel, "this host has no workspace_dirs, so the clone goes under the worktrees directory", nil
}

// cloneURLOf is the https URL repo_clone fetches, lower case like rc's.
func cloneURLOf(forgeHost, owner, name string) string {
	return "https://" + forgeHost + "/" + strings.ToLower(owner) + "/" + strings.ToLower(name) + ".git"
}

// targetIsOther says why an existing target cannot take the clone: it is not
// a directory, a non-empty directory that is not a checkout, or a checkout of
// another repository. "" means it is free or already this repository.
func targetIsOther(ctx context.Context, dir, url string) string {
	fi, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil || !fi.IsDir() {
		return "the target exists and is not a directory"
	}
	if _, err := os.Lstat(filepath.Join(dir, ".git")); err != nil {
		if des, _ := os.ReadDir(dir); len(des) > 0 {
			return "the target exists and is not a git checkout"
		}
		return ""
	}
	got, err := gitOut(ctx, dir, "config", "--get", "remote.origin.url")
	norm := func(s string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".git") }
	if err != nil || norm(got) != norm(url) {
		return "the target exists and is a checkout of another repository"
	}
	return ""
}

func planRepoClone(ctx context.Context, c *call) (*Plan, string) {
	if c.m.o.Gates.NoClone {
		return nil, "this host does not clone repositories (belai rc --no-clone)"
	}
	if c.m.o.Hooks.Clone == nil {
		return nil, "this daemon cannot clone repositories"
	}
	fh, owner, name := c.p["forge_host"], c.p["owner"], c.p["name"]
	if fh == "github.com" && strings.Contains(owner, "/") {
		return nil, "a github.com owner has no slash"
	}
	parent, rel, note, err := c.m.cloneTarget(fh, owner, name)
	if err != nil {
		return nil, err.Error()
	}
	target := filepath.Join(parent, rel)
	url := cloneURLOf(fh, owner, name)
	if why := targetIsOther(ctx, target, url); why != "" {
		return nil, why + ": " + homeRel(c.m.o.UserHome, target)
	}
	shown := homeRel(c.m.o.UserHome, target)
	pl := &Plan{Params: map[string]string{"forge_host": fh, "owner": owner, "name": name, "target": shown},
		Notes: []string{"cloned through belai's repository engine (git argv, hooks off, no prompts), then trusted for the directory only"}}
	argv := []string{"git", "clone"}
	if d := c.p["depth"]; d != "" {
		pl.Params["depth"] = d
		argv = append(argv, "--depth", d)
	}
	pl.Steps = []Step{{Argv: append(argv, url, shown)}}
	if note != "" {
		pl.Notes = append(pl.Notes, note)
	}
	return pl, ""
}

func runRepoClone(ctx context.Context, c *call, pl *Plan) result {
	fh, owner, name := pl.Params["forge_host"], pl.Params["owner"], pl.Params["name"]
	parent, rel, _, err := c.m.cloneTarget(fh, owner, name)
	if err != nil {
		return failed(err.Error())
	}
	if homeRel(c.m.o.UserHome, filepath.Join(parent, rel)) != pl.Params["target"] {
		return failed("the clone target changed since the preview")
	}
	depth, _ := strconv.Atoi(pl.Params["depth"])
	path, why := c.m.o.Hooks.Clone(ctx, CloneRequest{ForgeHost: fh, Owner: owner, Name: name, Parent: parent, Dir: rel, Depth: depth})
	if why != "" {
		return failed(why)
	}
	c.m.poke()
	return done(resultJSON(map[string]any{"path": homeRel(c.m.o.UserHome, path), "depth": depth}))
}

// worktreeOrphan reports whether a linked worktree's repository is gone.
func worktreeOrphan(dir string) (orphan, linked bool) {
	data, err := os.ReadFile(filepath.Join(dir, ".git"))
	if err != nil {
		return false, false
	}
	p, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir: ")
	if !ok {
		return false, false
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(dir, p)
	}
	_, err = os.Stat(p)
	return os.IsNotExist(err), true
}

// staleAfter is how long a worktree is left unchanged before it counts as
// stale.
const staleAfter = 14 * 24 * time.Hour

// worktreeStale reports whether a worktree may be dropped: its repository is
// gone, or nothing in it changed for staleAfter and git reports it clean.
func worktreeStale(ctx context.Context, dir string, now time.Time) (bool, string) {
	orphan, linked := worktreeOrphan(dir)
	if !linked {
		return false, "not a linked git worktree"
	}
	if orphan {
		return true, "its repository is gone"
	}
	if now.Sub(lastChange(dir)) < staleAfter {
		return false, "it changed in the last 14 days"
	}
	out, err := gitOut(ctx, dir, "status", "--porcelain")
	if err != nil {
		return false, "git could not read it"
	}
	if strings.TrimSpace(out) != "" {
		return false, "it has uncommitted changes"
	}
	return true, "unchanged for 14 days and clean"
}

// lastChange is the newest modification time in dir, looking at most at
// 20000 entries.
func lastChange(dir string) time.Time {
	var newest time.Time
	n := 0
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if n++; n > 20000 {
			return filepath.SkipAll
		}
		if info, err := d.Info(); err == nil && info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		return nil
	})
	return newest
}

// gitOut runs git with a fixed argv, hooks off and the scrubbed environment.
func gitOut(ctx context.Context, dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir, "-c", "core.hooksPath=/dev/null"}, args...)...)
	cmd.Env = append(proc.WithoutGitEnv(proc.ScrubbedEnv()), "GIT_TERMINAL_PROMPT=0")
	proc.SetProcessGroup(cmd)
	out, err := cmd.Output()
	return string(out), err
}

func planWorktreeDrop(ctx context.Context, c *call) (*Plan, string) {
	dir := c.p["path"]
	stale, why := worktreeStale(ctx, dir, c.m.o.Now())
	if !stale {
		return nil, "only a stale worktree is dropped: " + why
	}
	return &Plan{Params: map[string]string{"path": dir}, Steps: []Step{{Remove: dir}}, Notes: []string{why}}, ""
}

func runWorktreeDrop(ctx context.Context, c *call, pl *Plan) result {
	dir := pl.Params["path"]
	if orphan, _ := worktreeOrphan(dir); !orphan {
		if _, err := gitOut(ctx, dir, "worktree", "remove", dir); err != nil {
			return failed("git could not remove the worktree")
		}
		return done(resultJSON(map[string]bool{"dropped": true}))
	}
	if err := os.RemoveAll(dir); err != nil {
		return failed("the worktree could not be removed")
	}
	return done(resultJSON(map[string]bool{"dropped": true}))
}

// builtinAgents lists the built-in agent profiles this host carries.
func builtinAgents() []string {
	all, err := agentprofile.List()
	if err != nil {
		return nil
	}
	var out []string
	for _, p := range all {
		if agentprofile.IsBuiltin(p.Name) {
			out = append(out, p.Name)
		}
	}
	return out
}

// detCache is one repository's detections at one HEAD.
type detCache struct {
	head        string
	build, lint []string
	test, langs []string
}

// detections runs the build, lint and test detectors for root, once per
// HEAD.
func (m *Manager) detections(root, head string) detCache {
	m.mu.Lock()
	d, ok := m.det[root]
	m.mu.Unlock()
	if ok && d.head == head && head != "" {
		return d
	}
	d = detCache{head: head}
	langs := map[string]bool{}
	for _, b := range builddetect.Detect(root) {
		d.build = append(d.build, b.Name)
		langs[b.Ecosystem] = true
	}
	for _, l := range lintdetect.Detect(root) {
		d.lint = append(d.lint, l.Name)
		langs[l.Ecosystem] = true
	}
	for _, s := range testdetect.Detect(root, nil, nil) {
		d.test = append(d.test, s.Name)
		langs[s.Ecosystem] = true
	}
	for l := range langs {
		if l != "" && l != "just" && l != "make" {
			d.langs = append(d.langs, l)
		}
	}
	sortStrings(d.langs)
	m.mu.Lock()
	m.det[root] = d
	m.mu.Unlock()
	return d
}
