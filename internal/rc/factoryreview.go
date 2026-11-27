package rc

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sanitize"
)

// The code review job (Keleustes job kind "review", belai-counterparts row
// 47): `belai review` (docs/review.md) as a job. The host reviews a working
// tree, a branch or a pull request in a directory it offers, with the same
// read-only review turn, caps and validation as the command line, and answers
// the validated findings. Nothing is posted from the host: a job review never
// comments on a pull request, whatever review.post says. Keleustes posts the
// findings with its own pr_review output, as data.
//
// The request is Keleustes's and untrusted: the directory must be one this
// daemon offers, the target is a closed word, and refs pass review.ValidRef's
// shape (checked again by the runner). The result is checked once more here
// before it leaves, field by field, so a runner bug cannot send free text.

// jobKindReview is the job kind of a code review.
const jobKindReview = "review"

// Review targets a job may name (review.Kind values).
var reviewTargets = []string{"workdir", "branch", "pr"}

// ReviewSeverities and ReviewCriteria are the closed lists a finding's
// severity and criterion come from (review.Severities, review.RubricIDs; a
// test in cmd/belai keeps them equal).
var (
	ReviewSeverities = []string{"blocker", "major", "minor", "nit"}
	ReviewCriteria   = []string{"correctness", "security", "tests", "errors", "concurrency", "performance",
		"compatibility", "maintainability", "docs"}
	reviewVerdicts = []string{"approve", "comment", "request_changes"}
)

// Caps on a review job's answer (review.MaxFindings, MaxBodyBytes, MaxFixBytes).
const (
	maxReviewFindings = 20
	maxReviewBody     = 2048
	maxReviewFix      = 1024
	maxReviewPath     = 512
)

// reviewRefRE is the shape of a branch or base ref (review.ValidRef's).
var reviewRefRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/@+-]{0,199}$`)

// reviewPathRE is the shape of a reviewable file's path (review.PlainPath's
// alphabet).
var reviewPathRE = regexp.MustCompile(`^[A-Za-z0-9._@+-][A-Za-z0-9._/@+-]*$`)

// ReviewJob is one checked review request: Dir is a directory this daemon
// offers, Target "workdir", "branch" or "pr", Ref a branch or a pull request
// number, Base what a branch is compared with.
type ReviewJob struct {
	Dir, Target, Ref, Base string
	Provider, Model        string
	Force                  bool
}

// parseReviewJob reads a review payload (a ReviewJobRequest, proto3 JSON) and
// resolves its directory.
func (d *Daemon) parseReviewJob(payload string) (ReviewJob, string) {
	if len(payload) > 8<<10 {
		return ReviewJob{}, "the review request is too large"
	}
	var req nodev1.ReviewJobRequest
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal([]byte(payload), &req); err != nil {
		return ReviewJob{}, "the review request is not a ReviewJobRequest"
	}
	j := ReviewJob{Target: req.GetTarget(), Ref: req.GetRef(), Base: req.GetBase(),
		Provider: req.GetProvider(), Model: req.GetModel(), Force: req.GetForce()}
	if j.Target == "" {
		j.Target = "workdir"
	}
	if !slices.Contains(reviewTargets, j.Target) {
		return ReviewJob{}, "the review request names no target this Belai reviews (workdir, branch or pr)"
	}
	for _, v := range []string{j.Provider, j.Model} {
		if v != "" && !factoryModelName.MatchString(v) {
			return ReviewJob{}, "the review request names a model in the wrong shape"
		}
	}
	switch j.Target {
	case "workdir":
		if j.Ref != "" || j.Base != "" {
			return ReviewJob{}, "a working tree review takes no ref or base"
		}
	case "branch":
		for _, r := range []string{j.Ref, j.Base} {
			if r != "" && (!reviewRefRE.MatchString(r) || strings.Contains(r, "..") || strings.Contains(r, "@{") ||
				strings.HasSuffix(r, "/") || strings.HasSuffix(r, ".lock")) {
				return ReviewJob{}, "the review request names a ref in the wrong shape"
			}
		}
	case "pr":
		if j.Base != "" {
			return ReviewJob{}, "a pull request review takes no base"
		}
		if n, err := strconv.Atoi(j.Ref); err != nil || n <= 0 || n > 1e7 || strconv.Itoa(n) != j.Ref {
			return ReviewJob{}, "the review request names no pull request number"
		}
	}
	dir, why := d.offeredRepoDir(req.GetCwd(), req.GetRepo())
	if why != "" {
		return ReviewJob{}, why
	}
	j.Dir = dir
	return j, ""
}

// runReviewJob is the job's runner; parse errors are refusals. facts gains the
// target, and after the run the pull request and the files reviewed.
func (d *Daemon) runReviewJob(payload string, grant *factorylink.Grant, facts map[string]string) (func(context.Context) (json.RawMessage, string, error), string) {
	if d.o.ReviewJob == nil {
		return nil, "this host runs no code reviews"
	}
	j, why := d.parseReviewJob(payload)
	if why != "" {
		return nil, why
	}
	facts["target"] = j.Target
	return func(ctx context.Context) (json.RawMessage, string, error) {
		res, why, err := d.o.ReviewJob(ctx, j, grant)
		if err != nil || why != "" {
			return nil, why, err
		}
		out, err := reviewJobResult(res)
		if err == nil && res != nil {
			facts["files"] = strconv.Itoa(int(res.GetFiles()))
			if res.GetPr() > 0 {
				facts["pr"] = strconv.Itoa(int(res.GetPr()))
			}
		}
		return out, "", err
	}, ""
}

// reviewJobResult checks a review's result field by field and encodes it as
// a ReviewResult. A finding outside the closed lists, off the path alphabet
// or over a cap is dropped and counted; free text is cleaned again.
func reviewJobResult(r *nodev1.ReviewResult) (json.RawMessage, error) {
	if r == nil {
		r = &nodev1.ReviewResult{}
	}
	out := &nodev1.ReviewResult{
		Verdict: r.GetVerdict(), Target: r.GetTarget(), Pr: r.GetPr(), Files: r.GetFiles(),
		Skipped: r.GetSkipped(), Dropped: r.GetDropped(), Truncated: r.GetTruncated(),
		Incomplete: r.GetIncomplete(), Cached: r.GetCached(),
	}
	if !slices.Contains(reviewVerdicts, out.Verdict) {
		out.Verdict, out.Incomplete = "comment", true
	}
	if !slices.Contains(reviewTargets, out.Target) {
		out.Target = ""
	}
	if h := strings.ToLower(r.GetHeadSha()); len(h) == 40 || len(h) == 64 {
		if strings.Trim(h, "0123456789abcdef") == "" {
			out.HeadSha = h
		}
	}
	for _, f := range r.GetFindings() {
		if len(out.Findings) >= maxReviewFindings || !reviewFindingOK(f) {
			out.Dropped++
			continue
		}
		out.Findings = append(out.Findings, &nodev1.ReviewFinding{
			Path: f.GetPath(), Line: f.GetLine(), Severity: f.GetSeverity(), Criterion: f.GetCriterion(),
			Body: sanitize.Line(f.GetBody(), 0), Fix: sanitize.Line(f.GetFix(), 0),
		})
	}
	// A verdict the findings no longer back is narrowed, as the review does.
	if out.Verdict == "request_changes" && !slices.ContainsFunc(out.Findings, func(f *nodev1.ReviewFinding) bool {
		return f.GetSeverity() == "blocker" || f.GetSeverity() == "major"
	}) {
		out.Verdict = "comment"
	}
	return protojson.Marshal(out)
}

func reviewFindingOK(f *nodev1.ReviewFinding) bool {
	p := f.GetPath()
	if p == "" || len(p) > maxReviewPath || !reviewPathRE.MatchString(p) || strings.HasPrefix(p, ".git/") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	body, fix := f.GetBody(), f.GetFix()
	return f.GetLine() > 0 && slices.Contains(ReviewSeverities, f.GetSeverity()) &&
		slices.Contains(ReviewCriteria, f.GetCriterion()) &&
		strings.TrimSpace(body) != "" && len(body) <= maxReviewBody && utf8.ValidString(body) &&
		len(fix) <= maxReviewFix && utf8.ValidString(fix)
}
