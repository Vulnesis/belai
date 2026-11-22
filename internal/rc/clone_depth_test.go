package rc

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnetix/belai/internal/repos"
)

// A host repo_clone (cloneAt) puts the checkout at dir under the parent it
// names and fetches only depth commits.
func TestCloneAtAppliesDepthAndDir(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	bare := filepath.Join(root, "origin.git")
	work := filepath.Join(root, "work")
	env := append(os.Environ(), "HOME="+home, "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test")
	git := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = dir, env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	for _, d := range []string{home, work} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	git(root, "init", "-q", "--bare", "-b", "main", bare)
	git(work, "init", "-q", "-b", "main")
	for _, s := range []string{"one", "two", "three"} {
		if err := os.WriteFile(filepath.Join(work, "a.txt"), []byte(s+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		git(work, "add", "a.txt")
		git(work, "commit", "--no-gpg-sign", "-q", "-m", s)
	}
	git(work, "remote", "add", "origin", bare)
	git(work, "push", "-q", "origin", "main")
	parent := filepath.Join(root, "code")
	opts := repos.Options{ReposDir: parent, GitHubCLI: true,
		LookPath: func(n string) (string, error) {
			if n == "git" {
				return exec.LookPath("git")
			}
			return "", errors.New("not found")
		},
		Env: []string{"HOME=" + home, "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_CONFIG_NOSYSTEM=1", "GIT_ALLOW_PROTOCOL=file:https:ssh",
			"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=url.file://" + bare + ".insteadOf", "GIT_CONFIG_VALUE_0=https://github.com/acme/web.git"}}
	var trusted []string
	path, err := cloneAt(context.Background(), CloneTarget{Owner: "acme", Name: "web"}, "", "web", 1, opts,
		func(dir string) error { trusted = append(trusted, dir); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(parent, "web") || len(trusted) != 1 || trusted[0] != path {
		t.Fatalf("path %q trusted %v", path, trusted)
	}
	if n := git(path, "rev-list", "--count", "HEAD"); n != "1" {
		t.Fatalf("depth 1 fetched %s commits", n)
	}
	if b, _ := os.ReadFile(filepath.Join(path, "a.txt")); string(b) != "three\n" {
		t.Fatalf("checkout %q", b)
	}
}
