package rc

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/gitinfo"
	"github.com/vulnetix/belai/internal/sanitize"
)

// The AGENTS.md draft job (Keleustes job kind "init_draft", belai-counterparts
// row 54): /init as a job. The host drafts an instruction file for a
// repository it offers with one call of its own model, given only the
// harness-computed repository map (paths, counts, detected commands), never
// repository prose. Nothing is written: the draft goes back to Keleustes,
// where a person reads it and, on accepting, a pull request is opened through
// the forge. The draft is a model's text, so Keleustes treats it as untrusted.

// jobKindInitDraft is the job kind of an AGENTS.md draft.
const jobKindInitDraft = "init_draft"

// MaxInitDraftBytes caps a draft.
const MaxInitDraftBytes = 64 << 10

// InitDraft is a drafted instruction file (the protocol's InitDraftResult).
type InitDraft struct {
	// Path is "AGENTS.md", or the instruction file the repository already has.
	Path     string
	Markdown string
	SHA256   string
	// BaseSHA256 is the existing file's hash when the draft replaces one.
	BaseSHA256 string
}

// initRepoName is the owner/name shape a request may name a repository by.
var initRepoName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// parseInitDraft reads an init_draft payload and resolves its directory: an
// offered directory named by cwd, or the one whose origin (or base name) is
// repo.
func (d *Daemon) parseInitDraft(payload string) (dir, provider, model, why string) {
	if len(payload) > 8<<10 {
		return "", "", "", "the draft request is too large"
	}
	var req nodev1.InitDraftRequest
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal([]byte(payload), &req); err != nil {
		return "", "", "", "the draft request is not an InitDraftRequest"
	}
	provider, model = req.GetProvider(), req.GetModel()
	for _, v := range []string{provider, model} {
		if v != "" && !factoryModelName.MatchString(v) {
			return "", "", "", "the draft request names a model in the wrong shape"
		}
	}
	cwd, repo := req.GetCwd(), req.GetRepo()
	if repo != "" && !initRepoName.MatchString(repo) {
		return "", "", "", "the repository is not owner/name"
	}
	for _, offered := range d.dirs() {
		switch {
		case cwd != "" && offered.Path == cwd:
			return offered.Path, provider, model, ""
		case cwd == "" && repo != "" && repoMatches(offered.Path, repo):
			return offered.Path, provider, model, ""
		}
	}
	if cwd == "" && repo == "" {
		return "", "", "", "the draft request names a directory or a repository"
	}
	return "", "", "", "this host offers no such repository"
}

// repoMatches reports whether dir is a checkout of owner/name: its origin
// says so, or, with no origin, its base name is name.
func repoMatches(dir, repo string) bool {
	want := strings.ToLower(repo)
	if origin := gitinfo.OriginURL(dir); origin != "" {
		r := strings.ToLower(strings.TrimSuffix(origin, ".git"))
		return strings.HasSuffix(r, "/"+want) || strings.HasSuffix(r, ":"+want)
	}
	return strings.EqualFold(filepath.Base(dir), want[strings.Index(want, "/")+1:])
}

// runInitDraftJob is the job's runner; parse errors are refusals.
func (d *Daemon) runInitDraftJob(payload string, grant *factorylink.Grant) (func(context.Context) (json.RawMessage, string, error), string) {
	if d.o.InitDraft == nil {
		return nil, "this host drafts no instruction files"
	}
	dir, provider, model, why := d.parseInitDraft(payload)
	if why != "" {
		return nil, why
	}
	return func(ctx context.Context) (json.RawMessage, string, error) {
		dr, why, err := d.o.InitDraft(ctx, dir, provider, model, grant)
		if err != nil || why != "" {
			return nil, why, err
		}
		return initDraftResult(dr)
	}, ""
}

// initDraftResult checks a draft and encodes it as an InitDraftResult.
func initDraftResult(dr InitDraft) (json.RawMessage, string, error) {
	if dr.Path != "AGENTS.md" && dr.Path != "CLAUDE.md" {
		return nil, "", errors.New("the draft names no instruction file")
	}
	if strings.TrimSpace(dr.Markdown) == "" || len(dr.Markdown) > MaxInitDraftBytes {
		return nil, "the model did not return a usable draft", nil
	}
	if !knowledgeSHARE.MatchString(dr.SHA256) || (dr.BaseSHA256 != "" && !knowledgeSHARE.MatchString(dr.BaseSHA256)) {
		return nil, "", errors.New("the draft's hashes are not SHA-256")
	}
	out, err := protojson.Marshal(&nodev1.InitDraftResult{Path: dr.Path, Markdown: sanitize.Text(dr.Markdown),
		Sha256: dr.SHA256, BaseSha256: dr.BaseSHA256})
	return out, "", err
}
