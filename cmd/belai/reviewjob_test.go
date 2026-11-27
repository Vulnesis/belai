package main

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/rc"
	"github.com/vulnetix/belai/internal/review"
)

// The daemon's closed lists are the review's.
func TestReviewJobListsMatchTheReview(t *testing.T) {
	var sev []string
	for _, s := range review.Severities {
		sev = append(sev, string(s))
	}
	if !slices.Equal(sev, rc.ReviewSeverities) {
		t.Errorf("severities %v, review has %v", rc.ReviewSeverities, sev)
	}
	if !slices.Equal(review.RubricIDs(), rc.ReviewCriteria) {
		t.Errorf("criteria %v, review has %v", rc.ReviewCriteria, review.RubricIDs())
	}
}

func TestReviewJobTarget(t *testing.T) {
	cases := map[rc.ReviewJob]review.Target{
		{Target: "workdir"}: {Kind: review.KindWorkdir},
		{}:                  {Kind: review.KindWorkdir},
		{Target: "branch", Ref: "f", Base: "main"}:     {Kind: review.KindBranch, Ref: "f", Base: "main"},
		{Target: "pr", Ref: "7", Base: "ignored-here"}: {Kind: review.KindPR, Ref: "7"},
	}
	for j, want := range cases {
		if got := reviewJobTarget(j); got != want {
			t.Errorf("%+v -> %+v, want %+v", j, got, want)
		}
	}
}

// A job review runs the command line's review and never posts it, even where
// review.post allows the command line to.
func TestRunReviewJobAnswersFindingsAndNeverPosts(t *testing.T) {
	allow := "allow"
	rv := &scriptedReviewer{reply: "verdict: request_changes\nfinding: a.go:2: major correctness: x is never read\nfix: drop it\nfinding: nope.go:1: major docs: off the diff\n"}
	r, f := newReviewRun(t, rv, reviewArgs{}, review.Target{Kind: review.KindPR, Ref: "7"}, config.Settings{Review: &config.ReviewSettings{Post: &allow}})
	res, why, err := runReviewJob(context.Background(), r.opts, r.target)
	if err != nil || why != "" {
		t.Fatal(why, err)
	}
	if res.GetVerdict() != "request_changes" || res.GetTarget() != "pr" || res.GetPr() != 7 || res.GetDropped() != 1 {
		t.Fatalf("result = %v", res)
	}
	if len(res.GetFindings()) != 1 {
		t.Fatalf("findings = %v", res.GetFindings())
	}
	if g := res.GetFindings()[0]; g.GetPath() != "a.go" || g.GetLine() != 2 || g.GetSeverity() != "major" ||
		g.GetCriterion() != "correctness" || g.GetFix() != "drop it" {
		t.Errorf("finding = %v", g)
	}
	if len(f.comments) != 0 {
		t.Fatalf("a job review posted %d comment(s)", len(f.comments))
	}
	// The same head again comes from the host's store, with no model turn.
	again, _, _ := runReviewJob(context.Background(), r.opts, r.target)
	if !again.GetCached() || rv.calls != 1 {
		t.Errorf("cached %v after %d model turns", again.GetCached(), rv.calls)
	}

	off := false
	r, _ = newReviewRun(t, rv, reviewArgs{}, review.Target{Kind: review.KindWorkdir}, config.Settings{Review: &config.ReviewSettings{Enabled: &off}})
	if _, why, err := runReviewJob(context.Background(), r.opts, r.target); err != nil || why == "" {
		t.Errorf("a disabled review: why %q, err %v", why, err)
	}
	r, _ = newReviewRun(t, &scriptedReviewer{err: errors.New("provider down")}, reviewArgs{}, review.Target{Kind: review.KindWorkdir}, config.Settings{})
	if _, _, err := runReviewJob(context.Background(), r.opts, r.target); err == nil {
		t.Error("a failed review turn did not fail the job")
	}
}
