package forgejob

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@x", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@x")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// remote makes a bare "remote" where main and feat conflict on app.txt.
func remote(t *testing.T) (bare, head, base string) {
	d := t.TempDir()
	w := filepath.Join(d, "w")
	os.MkdirAll(w, 0o755)
	run(t, w, "init", "-q", "-b", "main")
	os.WriteFile(filepath.Join(w, "app.txt"), []byte("a\n"), 0o644)
	run(t, w, "add", ".")
	run(t, w, "commit", "-q", "-m", "init")
	run(t, w, "checkout", "-q", "-b", "feat")
	os.WriteFile(filepath.Join(w, "app.txt"), []byte("feat\n"), 0o644)
	run(t, w, "commit", "-q", "-am", "feat")
	head = run(t, w, "rev-parse", "HEAD")
	run(t, w, "checkout", "-q", "main")
	os.WriteFile(filepath.Join(w, "app.txt"), []byte("main\n"), 0o644)
	os.WriteFile(filepath.Join(w, "base.txt"), []byte("new\n"), 0o644)
	run(t, w, "add", ".")
	run(t, w, "commit", "-q", "-m", "main")
	base = run(t, w, "rev-parse", "HEAD")
	bare = filepath.Join(d, "r.git")
	run(t, d, "clone", "-q", "--bare", w, bare)
	return bare, head, base
}

func payload(head, base string) string {
	both := "both\n"
	b, _ := json.Marshal(PushRequest{
		CLI: "glab", Host: "gitlab.example.com", Repo: "grp/app",
		HeadRef: "feat", HeadSHA: head, BaseRef: "main", BaseSHA: base,
		Files:    map[string]*string{"app.txt": &both},
		BaseOnly: []BaseTake{{Path: "base.txt"}},
		Message:  "Merge main into feat", AuthorName: "ana", AuthorEmail: "ana@example.com", AuthorForced: true,
	})
	return string(b)
}

func TestPushBuildsTwoParentMergeAndRefusesMovedBranch(t *testing.T) {
	bare, head, base := remote(t)
	remoteURL = func(host, repo string) string {
		if host != "gitlab.example.com" || repo != "grp/app" {
			t.Fatalf("url not forced from host and repo: %s %s", host, repo)
		}
		return "file://" + bare
	}
	fileAllow = func() string { return "always" }
	defer func() {
		remoteURL = func(host, repo string) string { return "https://" + host + "/" + repo + ".git" }
		fileAllow = func() string { return "never" }
	}()
	req, why := ParsePush(payload(head, base))
	if why != "" {
		t.Fatal(why)
	}
	out, why, err := Push(context.Background(), req)
	if err != nil || why != "" {
		t.Fatalf("push: %v %s", err, why)
	}
	var res PushResult
	json.Unmarshal(out, &res)
	if got := run(t, bare, "rev-parse", "refs/heads/feat"); got != res.Commit {
		t.Fatalf("feat is %s, pushed %s", got, res.Commit)
	}
	if n := len(strings.Fields(run(t, bare, "rev-list", "--parents", "-n", "1", res.Commit))); n != 3 {
		t.Fatalf("want two parents, got %d fields", n)
	}
	if got := run(t, bare, "show", res.Commit+":app.txt"); got != "both" {
		t.Fatalf("app.txt = %q", got)
	}
	if got := run(t, bare, "show", res.Commit+":base.txt"); got != "new" {
		t.Fatalf("base.txt = %q", got)
	}
	if got := run(t, bare, "log", "-1", "--format=%ae", res.Commit); got != "ana@example.com" {
		t.Fatalf("author %q", got)
	}
	// Same plan again: the head moved, nothing is pushed.
	_, why, err = Push(context.Background(), req)
	if err != nil || !strings.Contains(why, "moved") {
		t.Fatalf("want moved refusal, got %v %q", err, why)
	}
}

func TestParsePushRefusesWhatItMustNot(t *testing.T) {
	sha := strings.Repeat("a", 40)
	ok := payload(sha, sha)
	if _, why := ParsePush(ok); why != "" {
		t.Fatal(why)
	}
	for name, mutate := range map[string]func(*PushRequest){
		"cli":      func(r *PushRequest) { r.CLI = "sh" },
		"host":     func(r *PushRequest) { r.Host = "evil host" },
		"repo":     func(r *PushRequest) { r.Repo = "../x" },
		"ref":      func(r *PushRequest) { r.HeadRef = "feat/../main" },
		"ref dash": func(r *PushRequest) { r.BaseRef = "-upload-pack=x" },
		"sha":      func(r *PushRequest) { r.HeadSHA = "HEAD" },
		"path":     func(r *PushRequest) { s := "x"; r.Files = map[string]*string{"../etc/passwd": &s} },
		"dot git":  func(r *PushRequest) { s := "x"; r.Files = map[string]*string{".git/config": &s} },
		"author":   func(r *PushRequest) { r.AuthorEmail = "a>b" },
	} {
		var r PushRequest
		json.Unmarshal([]byte(ok), &r)
		mutate(&r)
		b, _ := json.Marshal(r)
		if _, why := ParsePush(string(b)); why == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, why := ParsePush(`{"cli":"gh","url":"https://x"}`); why == "" {
		t.Error("unknown field accepted")
	}
}
