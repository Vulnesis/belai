package main

import (
	"context"
	"encoding/json"
	"errors"
	"math"

	"github.com/vulnetix/belai/internal/bgagent"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/httpclient"
	"github.com/vulnetix/belai/internal/permissions"
	"github.com/vulnetix/belai/internal/rc"
	"github.com/vulnetix/belai/internal/review"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/session"
	"github.com/vulnetix/belai/internal/workdiff"
)

// The Keleustes review job (keleustes belai-counterparts row 47): `belai
// review` as a job. The daemon has checked the request and resolved its
// directory; this runs the same review the command line does (the read-only
// review turn, the caps, the validation against the diff, the store) in that
// directory, with the model resolved as a model job's is (resolveModelJob,
// the job's vault grant first). It never posts: posting is the command line's
// -comment and the TUI's /review post, and Keleustes posts with its own
// pr_review output. The answer is the validated findings only, never the
// model's reply or any diff text.

// rcReviewJob is the daemon's runner for review jobs.
func rcReviewJob(ctx context.Context, j rc.ReviewJob, grant *factorylink.Grant) (*nodev1.ReviewResult, string, error) {
	if err := trustRepo(j.Dir, false); err != nil {
		return nil, "that directory is not a trusted workspace on this host", nil
	}
	payload, _ := json.Marshal(map[string]string{"provider": j.Provider, "model": j.Model})
	env, why := resolveModelJob(j.Dir, payload, grant)
	if why != "" {
		return nil, why, nil
	}
	if !env.settings.ReviewEnabled() {
		return nil, review.ErrDisabled.Error(), nil
	}
	mgr := bgagent.NewManager(j.Dir, env.cfg, httpclient.Default(), env.settings, env.pol)
	mgr.SetCredentialSource(env.resolver)
	mgr.SetSessionID(session.MustID())
	perms := permissions.From(env.settings.Permissions.Allow, env.settings.Permissions.Ask, env.settings.Permissions.Deny)
	store, _ := review.OpenStore()
	opts := review.Options{
		Settings: env.settings,
		Collector: review.Collector{
			Dir:  j.Dir,
			Hide: func(rel string) bool { return workdiff.ReadDenied(perms, j.Dir, rel) },
		},
		Reviewer: review.Agent{Manager: mgr, Workdir: j.Dir},
		Store:    store,
		Rubric:   review.LoadRubric(env.settings, j.Dir),
		Force:    j.Force,
	}
	return runReviewJob(ctx, opts, reviewJobTarget(j))
}

// reviewJobTarget is the review.Target of a checked job.
func reviewJobTarget(j rc.ReviewJob) review.Target {
	switch j.Target {
	case "branch":
		return review.Target{Kind: review.KindBranch, Ref: j.Ref, Base: j.Base}
	case "pr":
		return review.Target{Kind: review.KindPR, Ref: j.Ref}
	}
	return review.Target{Kind: review.KindWorkdir}
}

// runReviewJob runs one review and shapes its result for Keleustes. A review
// that is switched off is a refusal; any other error fails the job with the
// harness's own message.
func runReviewJob(ctx context.Context, opts review.Options, t review.Target) (*nodev1.ReviewResult, string, error) {
	res, _, err := review.Run(ctx, opts, t)
	switch {
	case errors.Is(err, review.ErrDisabled):
		return nil, err.Error(), nil
	case err != nil:
		return nil, "", errors.New(sanitize.Line(err.Error(), 400))
	}
	return reviewResultPB(res), "", nil
}

// reviewResultPB is a review's result as the protocol's ReviewResult.
func reviewResultPB(r review.Result) *nodev1.ReviewResult {
	out := &nodev1.ReviewResult{
		Verdict: string(r.Verdict), Target: string(r.Target.Kind), HeadSha: r.HeadSHA,
		Pr: nonNeg(r.PR), Files: nonNeg(r.Files), Skipped: nonNeg(r.Skipped), Dropped: nonNeg(r.Dropped),
		Truncated: r.Truncated, Incomplete: r.Incomplete, Cached: r.Cached,
	}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, &nodev1.ReviewFinding{
			Path: f.File, Line: nonNeg(f.Line), Severity: string(f.Severity), Criterion: f.Rubric,
			Body: f.Body, Fix: f.Fix,
		})
	}
	return out
}

// nonNeg clamps a count or line number into the proto's uint32.
func nonNeg(n int) uint32 {
	if n < 0 {
		return 0
	}
	if uint64(n) > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(n)
}
