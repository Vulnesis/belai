// Package forgejob runs Keleustes' forge jobs: the forge job (one checked
// gh, glab or tea call for a named host, forge.go) and the forge_push job:
// build a two-parent merge
// commit for a pull request's conflict resolution and push it, with the
// host's own forge CLI as git credential helper (keleustes
// docs/gaps/forges-proto-request.md, section 5).
//
// Keleustes sends file contents, shas and ref names only. The remote URL
// is forced from host + repo, the credential helper from the CLI, and the
// push is guarded by --force-with-lease on the head commit Keleustes read,
// so a branch that moved is refused, never overwritten. No token passes
// through Belai or Keleustes.
//
// Wiring (belai agent): in internal/rc/factoryjobs.go handleFactoryJob,
//
//	case forgejob.KindPush:
//		req, why := forgejob.ParsePush(j.GetPayloadJson())
//		if why == "" && !d.o.ForgeSignedIn(ctx, req.CLI, req.Host) {
//			why = "this host has no signed-in " + req.CLI + " login for " + req.Host
//		}
//		if why != "" { refuse(why); return }
//		run = func(ctx context.Context) (json.RawMessage, string, error) { return forgejob.Push(ctx, req) }
//
// and advertise "forge_push" in Capabilities.job_kinds.
package forgejob

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"
)

// KindPush is the job kind.
const KindPush = "forge_push"

// Limits on one job.
const (
	maxFiles = 2000
	maxBytes = 20 << 20
)

// BaseTake is a base-branch change the merge takes as is.
type BaseTake struct {
	Path     string  `json:"path"`
	Removed  bool    `json:"removed"`
	Previous *string `json:"previous"`
}

// PushRequest is the forge_push payload.
type PushRequest struct {
	CLI          string             `json:"cli"`
	Host         string             `json:"host"`
	Repo         string             `json:"repo"`
	HeadRef      string             `json:"head_ref"`
	HeadSHA      string             `json:"head_sha"`
	BaseRef      string             `json:"base_ref"`
	BaseSHA      string             `json:"base_sha"`
	Files        map[string]*string `json:"files"`
	RenamedFrom  []string           `json:"renamed_from"`
	BaseOnly     []BaseTake         `json:"base_only"`
	Message      string             `json:"message"`
	AuthorName   string             `json:"author_name"`
	AuthorEmail  string             `json:"author_email"`
	AuthorForced bool               `json:"author_forced"`
}

// PushResult is the job answer.
type PushResult struct {
	Commit string `json:"commit"`
	Pushed bool   `json:"pushed"`
	Error  string `json:"error,omitempty"`
}

var (
	hostRe    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?$`)
	segmentRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
	shaRe     = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	refRe     = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,250}$`)
)

// helpers is the credential helper per CLI; nothing else may run.
var helpers = map[string]string{
	"gh":   "!gh auth git-credential",
	"glab": "!glab auth git-credential",
	"tea":  "!tea login helper",
}

// remoteURL is the push URL (tests point it at a file:// remote).
var remoteURL = func(host, repo string) string { return "https://" + host + "/" + repo + ".git" }

func validRef(r string) bool {
	return refRe.MatchString(r) && !strings.Contains(r, "..") && !strings.HasPrefix(r, "/") &&
		!strings.HasSuffix(r, "/") && !strings.HasSuffix(r, ".lock") && !strings.HasPrefix(r, "-") &&
		!strings.Contains(r, "//") && !strings.Contains(r, "@{")
}

func validPath(p string) bool {
	if p == "" || len(p) > 4096 || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00\n\r") {
		return false
	}
	for _, s := range strings.Split(p, "/") {
		if s == "" || s == "." || s == ".." || s == ".git" {
			return false
		}
	}
	return path.Clean(p) == p
}

// ParsePush decodes and checks a payload. The second result is the refusal
// reason ("" when the job may run).
func ParsePush(payload string) (PushRequest, string) {
	var r PushRequest
	dec := json.NewDecoder(strings.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, "forge_push payload is not valid JSON"
	}
	if _, ok := helpers[r.CLI]; !ok {
		return r, "forge_push: cli must be gh, glab or tea"
	}
	r.Host = strings.ToLower(r.Host)
	if !hostRe.MatchString(r.Host) {
		return r, "forge_push: not a host"
	}
	segs := strings.Split(r.Repo, "/")
	if len(segs) < 2 || len(segs) > 20 {
		return r, "forge_push: repo must be owner/name"
	}
	for _, s := range segs {
		if !segmentRe.MatchString(s) || s == "." || s == ".." {
			return r, "forge_push: bad repo segment"
		}
	}
	if !validRef(r.HeadRef) || !validRef(r.BaseRef) {
		return r, "forge_push: bad branch name"
	}
	if !shaRe.MatchString(r.HeadSHA) || !shaRe.MatchString(r.BaseSHA) {
		return r, "forge_push: bad commit sha"
	}
	if len(r.Files) == 0 || len(r.Files)+len(r.BaseOnly)+len(r.RenamedFrom) > maxFiles {
		return r, "forge_push: no files, or too many"
	}
	total := 0
	for p, t := range r.Files {
		if !validPath(p) {
			return r, "forge_push: bad file path"
		}
		if t != nil {
			total += len(*t)
		}
	}
	if total > maxBytes {
		return r, "forge_push: files too large"
	}
	for _, p := range r.RenamedFrom {
		if !validPath(p) {
			return r, "forge_push: bad file path"
		}
	}
	for _, b := range r.BaseOnly {
		if !validPath(b.Path) || (b.Previous != nil && !validPath(*b.Previous)) {
			return r, "forge_push: bad file path"
		}
	}
	if len(r.Message) > 8000 || strings.ContainsRune(r.Message, 0) {
		return r, "forge_push: bad message"
	}
	if strings.ContainsAny(r.AuthorName+r.AuthorEmail, "<>\n\x00") || len(r.AuthorName) > 200 || len(r.AuthorEmail) > 200 {
		return r, "forge_push: bad author"
	}
	return r, ""
}

type repo struct {
	dir   string
	index string
	cred  []string
}

func (g *repo) git(ctx context.Context, env []string, stdin string, args ...string) (string, string, error) {
	full := append(append([]string{"-C", g.dir}, g.cred...), args...)
	cmd := exec.CommandContext(ctx, "git", full...)
	cmd.Env = append(append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=true", "GIT_INDEX_FILE="+g.index), env...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return strings.TrimSpace(out.String()), strings.TrimSpace(errb.String()), err
}

func (g *repo) must(ctx context.Context, env []string, stdin string, args ...string) (string, error) {
	out, errs, err := g.git(ctx, env, stdin, args...)
	if err != nil {
		lines := strings.Split(errs, "\n")
		return "", fmt.Errorf("git %s: %s", args[0], lines[len(lines)-1])
	}
	return out, nil
}

// entry is (mode, blob) of path in tree-ish, or ok=false.
func (g *repo) entry(ctx context.Context, treeish, p string) (string, string, bool) {
	out, _, err := g.git(ctx, nil, "", "ls-tree", treeish, "--", p)
	if err != nil || out == "" {
		return "", "", false
	}
	meta, _, _ := strings.Cut(strings.Split(out, "\n")[0], "\t")
	f := strings.Fields(meta)
	if len(f) < 3 {
		return "", "", false
	}
	return f[0], f[2], true
}

// Push builds the merge commit and pushes it. A refusal (moved branch) is
// the second result; err is a failure to run.
func Push(ctx context.Context, r PushRequest) (json.RawMessage, string, error) {
	dir, err := os.MkdirTemp("", "belai-forge-push-")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(dir)
	g := &repo{dir: dir, index: dir + "/kls-index", cred: []string{
		"-c", "credential.helper=",
		"-c", "credential.https://" + r.Host + ".helper=" + helpers[r.CLI],
		"-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "protocol.file.allow=" + fileAllow(),
	}}
	url := remoteURL(r.Host, r.Repo)
	if _, err := g.must(ctx, nil, "", "init", "--bare", "-q"); err != nil {
		return nil, "", err
	}
	if _, err := g.must(ctx, nil, "", "fetch", "--no-tags", "-q", url,
		"+refs/heads/"+r.HeadRef+":refs/kls/head", "+refs/heads/"+r.BaseRef+":refs/kls/base"); err != nil {
		return nil, "", err
	}
	head, err := g.must(ctx, nil, "", "rev-parse", "refs/kls/head")
	if err != nil {
		return nil, "", err
	}
	if head != r.HeadSHA {
		return nil, "the head branch moved since the conflicts were loaded; load them again", nil
	}
	if _, _, err := g.git(ctx, nil, "", "cat-file", "-e", r.BaseSHA+"^{commit}"); err != nil {
		return nil, "the base commit is gone from " + r.BaseRef + "; load the conflicts again", nil
	}
	if _, err := g.must(ctx, nil, "", "read-tree", r.HeadSHA); err != nil {
		return nil, "", err
	}
	rm := func(p string) error {
		_, err := g.must(ctx, nil, "", "update-index", "--force-remove", "--", p)
		return err
	}
	for _, p := range r.RenamedFrom {
		if err := rm(p); err != nil {
			return nil, "", err
		}
	}
	for _, b := range r.BaseOnly {
		if b.Previous != nil && *b.Previous != b.Path {
			if err := rm(*b.Previous); err != nil {
				return nil, "", err
			}
		}
		if b.Removed {
			if err := rm(b.Path); err != nil {
				return nil, "", err
			}
		} else if mode, blob, ok := g.entry(ctx, r.BaseSHA, b.Path); ok {
			if _, err := g.must(ctx, nil, "", "update-index", "--add", "--cacheinfo", mode+","+blob+","+b.Path); err != nil {
				return nil, "", err
			}
		}
	}
	for p, t := range r.Files {
		if t == nil {
			if err := rm(p); err != nil {
				return nil, "", err
			}
			continue
		}
		// An empty stdin is the null device: an empty blob.
		blob, err := g.must(ctx, nil, *t, "hash-object", "-w", "--stdin")
		if err != nil {
			return nil, "", err
		}
		mode := "100644"
		if m, _, ok := g.entry(ctx, r.HeadSHA, p); ok {
			mode = m
		} else if m, _, ok := g.entry(ctx, r.BaseSHA, p); ok {
			mode = m
		}
		if _, err := g.must(ctx, nil, "", "update-index", "--add", "--cacheinfo", mode+","+blob+","+p); err != nil {
			return nil, "", err
		}
	}
	tree, err := g.must(ctx, nil, "", "write-tree")
	if err != nil {
		return nil, "", err
	}
	var who []string
	if name, _, err := g.git(ctx, nil, "", "config", "user.name"); err != nil || name == "" {
		who = append(who, "GIT_AUTHOR_NAME="+nonEmpty(r.AuthorName, "Keleustes"), "GIT_COMMITTER_NAME="+nonEmpty(r.AuthorName, "Keleustes"))
	}
	if mail, _, err := g.git(ctx, nil, "", "config", "user.email"); r.AuthorForced || err != nil || mail == "" {
		who = append(who, "GIT_AUTHOR_EMAIL="+nonEmpty(r.AuthorEmail, "keleustes@localhost"), "GIT_COMMITTER_EMAIL="+nonEmpty(r.AuthorEmail, "keleustes@localhost"))
	}
	msg := nonEmpty(strings.TrimSpace(r.Message), "Merge "+r.BaseRef+" into "+r.HeadRef)
	commit, err := g.must(ctx, who, "", "commit-tree", tree, "-p", r.HeadSHA, "-p", r.BaseSHA, "-m", msg)
	if err != nil {
		return nil, "", err
	}
	_, errs, err := g.git(ctx, nil, "", "push", "-q", url, commit+":refs/heads/"+r.HeadRef,
		"--force-with-lease=refs/heads/"+r.HeadRef+":"+r.HeadSHA)
	if err != nil {
		if strings.Contains(errs, "stale info") || strings.Contains(errs, "rejected") || strings.Contains(errs, "non-fast-forward") {
			return nil, "the head branch moved since the conflicts were loaded; load them again", nil
		}
		lines := strings.Split(errs, "\n")
		return nil, "", fmt.Errorf("git push: %s", lines[len(lines)-1])
	}
	out, _ := json.Marshal(PushResult{Commit: commit, Pushed: true})
	return out, "", nil
}

func nonEmpty(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

// fileAllow is "never" except in tests.
var fileAllow = func() string { return "never" }
