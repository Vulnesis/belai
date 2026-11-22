package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnetix/belai/internal/session"
	"github.com/vulnetix/belai/internal/turnlog"
)

func TestRCResumeAndFork(t *testing.T) {
	store := session.NewStoreAt(t.TempDir())
	cwd := t.TempDir()
	key, err := session.KeyFor(cwd)
	if err != nil {
		t.Fatal(err)
	}
	old := session.MustID()
	w, err := session.NewWriter(store, key, old, session.Meta{Cwd: cwd})
	if err != nil {
		t.Fatal(err)
	}
	w.User("first question")
	w.Assistant("first answer", nil, nil)
	w.User("second question")
	w.Assistant("second answer", nil, nil)
	es, _ := w.Entries()
	var second string
	for _, e := range es {
		if e.Type == "user" && e.Content == "second question" {
			second = e.ID
		}
	}

	// Resume: the whole conversation, in a new session that records where it
	// came from; the old file is untouched.
	nw, history, err := rcResume(store, key, session.MustID(), old, "", session.Meta{Cwd: cwd, Mode: "agent"})
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 4 || history[3].Content != "second answer" {
		t.Fatalf("resumed history = %+v", history)
	}
	ne, _ := nw.Entries()
	if m, _ := session.LatestMeta(ne); m.ResumedFrom != old || m.Cwd != cwd {
		t.Fatalf("meta = %+v", m)
	}
	if after, _ := store.ReadFrom(key, old); len(after) != len(es) {
		t.Fatal("the resumed session's file changed")
	}

	// Fork at the second user message: it continues from the answer before it.
	_, history, err = rcResume(store, key, session.MustID(), old, second, session.Meta{Cwd: cwd})
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 || history[1].Content != "first answer" {
		t.Fatalf("forked history = %+v", history)
	}

	for _, c := range [][2]string{{session.MustID(), ""}, {"../x", ""}, {old, "nope"}} {
		if _, _, err := rcResume(store, key, session.MustID(), c[0], c[1], session.Meta{}); err == nil {
			t.Errorf("rcResume(%q, %q) took it", c[0], c[1])
		}
	}
}

func TestRCPlanFileAndAnswers(t *testing.T) {
	store := session.NewStoreAt(t.TempDir())
	key, _ := session.KeyFor(t.TempDir())
	w, err := session.NewWriter(store, key, session.MustID(), session.Meta{})
	if err != nil {
		t.Fatal(err)
	}
	tlog := turnlog.New(w)
	plan := filepath.Join(t.TempDir(), "plan.md")
	if err := os.WriteFile(plan, []byte("# Plan\n1. do it\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rcPlanFile(tlog, "plan-demo", plan)
	es, _ := w.Entries()
	last := es[len(es)-1]
	if last.Type != "plan_file" || !strings.Contains(last.Content, "do it") || len(last.Meta["sha256"].(string)) != 64 {
		t.Fatalf("plan entry = %+v", last)
	}

	path := filepath.Join(t.TempDir(), "a.answers.json")
	if err := os.WriteFile(path, []byte(`[{"choose":1,"note":"staging"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := rcAnswers(path, os.Stderr)
	if err != nil || s == nil || len(s.answers) != 1 {
		t.Fatalf("answers = %+v, %v", s, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("the answers file was left behind")
	}
}
