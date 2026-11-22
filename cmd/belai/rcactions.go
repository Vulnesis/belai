package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/vulnetix/belai/internal/agent"
	"github.com/vulnetix/belai/internal/attribution"
	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/checkpoint"
	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/forge"
	"github.com/vulnetix/belai/internal/headless"
	"github.com/vulnetix/belai/internal/httpclient"
	"github.com/vulnetix/belai/internal/kanban"
	"github.com/vulnetix/belai/internal/permissions"
	"github.com/vulnetix/belai/internal/posture"
	"github.com/vulnetix/belai/internal/rc"
	"github.com/vulnetix/belai/internal/rolemanager"
	"github.com/vulnetix/belai/internal/run"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/session"
	"github.com/vulnetix/belai/internal/tools"
	"github.com/vulnetix/belai/internal/transcript"
	"github.com/vulnetix/belai/internal/turnlog"
)

// The rc-session halves of the Keleustes start fields and console actions
// (belai-counterparts #45, #46, #52): resuming or forking a stored session,
// the scripted answers, the plan file a plan session returns, and the host's
// implementation of each console action.

// rcResume copies the session a Keleustes dispatch resumes (or the chain up to
// the entry it forks at) into the new session id and returns the writer that
// continues it and the conversation to replay. The daemon checked both ids;
// they are checked again here, against this project's store only.
func rcResume(store *session.Store, key session.Key, newID, from, fork string, meta session.Meta) (*session.Writer, []run.Turn, error) {
	if !session.ValidID(from) {
		return nil, nil, errors.New("-resume is not a session id")
	}
	src, err := store.ReadFrom(key, from)
	if err != nil || len(src) == 0 {
		return nil, nil, errors.New("this host has no such session")
	}
	leaf := session.ActiveLeaf(src)
	if fork != "" {
		e, err := session.FindEntry(src, fork)
		if err != nil || e.ID != fork {
			return nil, nil, errors.New("that session has no such entry")
		}
		if leaf, _, err = session.Target(e); err != nil {
			return nil, nil, err
		}
		if leaf == "" {
			return nil, nil, errors.New("a fork at the first message starts a new session; dispatch one instead")
		}
	}
	if err := store.ForkPath(key, from, key, newID, leaf); err != nil {
		return nil, nil, err
	}
	entries, err := store.ReadFrom(key, newID)
	if err != nil || len(entries) == 0 {
		return nil, nil, errors.New("the resumed session could not be read")
	}
	history := headless.TurnsFromEntries(session.ActivePath(entries))
	last := entries[len(entries)-1].ID
	w := session.ResumeWriter(store, key, newID, last)
	meta.ResumedFrom = from
	w.Entry(meta.ToEntry(last))
	return w, history, w.Err()
}

// rcCheckpoints opens the session's file checkpoint store when checkpoints
// are on, or returns nil. A store that cannot be opened refuses saves, so an
// edit is withheld rather than run unprotected (as in the TUI).
func rcCheckpoints(s config.Settings, cwd, sessionID string, roots []string, tlog *turnlog.Log) *checkpoint.Tracker {
	if !s.CheckpointsEnabled() {
		return nil
	}
	contains := func(abs string) bool {
		c := tools.NewCwd(cwd)
		for _, d := range roots[1:] {
			_ = c.AddRoot(d)
		}
		return c.Contains(abs)
	}
	p := s.Permissions
	pol := checkpoint.PolicyFor(cwd, contains, permissions.From(p.Allow, p.Ask, p.Deny))
	lim := checkpoint.Limits{MaxPerSession: s.CheckpointsMaxPerSession(), MaxBytes: s.CheckpointsMaxBytes()}
	dir, err := config.CheckpointsDir(cwd, sessionID)
	var t *checkpoint.Tracker
	if err == nil {
		t, err = checkpoint.Open(dir, lim, pol)
	}
	if err != nil {
		tlog.System("checkpoints: " + sanitize.Line(err.Error(), 160) + "; edits are withheld until this is fixed")
		return checkpoint.Unavailable(err)
	}
	return t
}

// rcAnswers loads the answers the daemon admitted and left for this session,
// and removes the file: the session holds them in memory from here on.
func rcAnswers(path string, log io.Writer) (*answerScript, error) {
	if path == "" {
		return nil, nil
	}
	s, err := loadAnswerScript(path, log)
	_ = os.Remove(path)
	return s, err
}

// rcPlanFile is the transcript entry a plan session returns its plan in (row
// 52): the file's text (model-written, untrusted wherever it is read) with
// its name, size and SHA-256. Keleustes takes the hash into SessionEnd.
func rcPlanFile(tlog *turnlog.Log, name, path string) {
	w := tlog.Writer()
	if w == nil {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return
	}
	const maxPlan = 256 << 10
	if len(data) > maxPlan {
		data = data[:maxPlan]
	}
	sum := sha256.Sum256(data)
	text := string(data)
	if !utf8.ValidString(text) {
		text = strings.ToValidUTF8(text, "?")
	}
	w.Entry(session.Entry{Type: "plan_file", Role: "system", Content: text,
		Meta: map[string]any{"kind": "plan_file", "name": sanitize.Line(name, 120), "sha256": hex.EncodeToString(sum[:]), "bytes": len(data)}})
}

// rcActionEnv is what the console actions of one session need.
type rcActionEnv struct {
	cfg       run.Config
	settings  config.Settings
	pol       posture.Policy
	cwd       string
	sessionID string
	writer    *session.Writer
	tlog      *turnlog.Log
	ckpt      *checkpoint.Tracker
	runner    func() rc.Runner
	branch    func() string
}

func actionNonce() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b[:])
}

// turnsDoc serialises a conversation for a summary model: a document to read,
// never a dialogue to continue (transcript.Serialize).
func turnsDoc(history []run.Turn, nonce string) string {
	msgs := make([]transcript.Message, 0, len(history))
	for _, t := range history {
		msgs = append(msgs, transcript.Message{Role: t.Role, Content: t.Content, ToolName: t.ToolName})
	}
	return transcript.Serialize(msgs, transcript.SerializeOptions{Nonce: nonce})
}

// admitText runs text a model will read through the session's classifier and
// posture, with the wording a /compact refusal uses.
func (e rcActionEnv) admitText(ctx context.Context, subject, text string) (string, error) {
	pipe := run.NewPipeline(e.cfg, httpclient.Default(), nil)
	dec, err := pipe.Admit(ctx, text, subject, e.pol)
	var refusal *rolemanager.RefusalError
	switch {
	case errors.As(err, &refusal):
		return "", fmt.Errorf("the %s was refused by the security classifier (%s)", subject, refusal.Sentinel.Label())
	case err != nil:
		return "", fmt.Errorf("the %s could not be checked: %w", subject, err)
	case dec.Action != rolemanager.ActionProceed:
		return "", fmt.Errorf("the %s was not admitted (%s)", subject, dec.Sentinel.Label())
	}
	return dec.Content, nil
}

// actions builds the session's console actions.
func (e rcActionEnv) actions() *rc.Actions {
	classifier := run.NewClassifier(e.cfg, httpclient.Default())
	caveman := e.settings.ClassifierCavemanEnabled()
	return &rc.Actions{
		SessionID:   e.sessionID,
		Checkpoints: e.ckpt,
		Rename:      func(title string) { e.writer.Name(title) },
		Compact: func(ctx context.Context, history []run.Turn, focus string) (string, error) {
			ctx, served := rolemanager.TrackServedModel(ctx)
			raw, err := classifier.Classify(ctx, rolemanager.BuildCompactionPayload(turnsDoc(history, actionNonce()), caveman, focus))
			if err != nil {
				return "", fmt.Errorf("compact: the summary could not be written: %w", err)
			}
			s, err := rolemanager.ValidateServedSummary(raw, served())
			if err != nil {
				return "", fmt.Errorf("compact: %w", err)
			}
			return e.admitText(ctx, "summary", s)
		},
		Relay: func(ctx context.Context, history []run.Turn, direction string) (string, error) {
			nonce := actionNonce()
			max := e.settings.HandoffMaxBytes()
			facts := rolemanager.RelayFacts{Nonce: nonce, MaxBytes: max}
			if e.branch != nil {
				facts.Branch = e.branch()
			}
			ctx, served := rolemanager.TrackServedModel(ctx)
			raw, err := classifier.Classify(ctx, rolemanager.BuildHandoffDraftPayload(turnsDoc(history, nonce), facts, direction, caveman))
			if err != nil {
				return "", fmt.Errorf("relay: the handoff could not be drafted: %w", err)
			}
			text, err := rolemanager.ValidateHandoff(raw, served(), max)
			if err != nil {
				return "", fmt.Errorf("relay: %w", err)
			}
			return e.admitText(ctx, "handoff", text)
		},
		Admit: func(ctx context.Context, text string) (string, error) {
			return e.admitText(ctx, "handoff", sanitize.Text(text))
		},
		Side: func(ctx context.Context, question string, history []run.Turn) (string, error) {
			if !e.settings.SideEnabled() {
				return "", errors.New("side questions are off (side.enabled is false)")
			}
			sess, ok := e.runner().(*agent.Session)
			if !ok {
				return "", errors.New("this session cannot take a side question")
			}
			res, err := sess.AskSide(ctx, agent.SideAskInput{Question: question,
				Context: sideContext(history, e.settings.SideHistoryTurns()), MaxReplyBytes: e.settings.SideMaxReplyBytes()})
			return res.Reply, err
		},
		Commit: func(ctx context.Context, paths []string, message string) (string, error) {
			if message == "" {
				message = forge.TaskCommitMessage("changes from the console", paths)
			}
			msg := attribution.Message(message, e.sessionID)
			sha, err := forge.CommitPaths(ctx, forge.NonInteractiveRunner, e.cwd, paths, msg)
			if err != nil {
				return "", errors.New(forge.CleanErr(err))
			}
			if sha == "" {
				return "", nil
			}
			project, _ := kanban.ProjectFor(e.cwd)
			audit.Emit(audit.Fact{Kind: audit.RepoCommit, ActorKind: audit.ActorWeb, Actor: "belai",
				SessionID: e.sessionID, Repo: project, Commit: forge.HeadCommit(ctx, forge.NonInteractiveRunner, e.cwd), Outcome: "console_commit"})
			return fmt.Sprintf("commit %s %s", sha, firstLine(msg, 120)), nil
		},
	}
}

// sideContext is the recent conversation a side question reads: the last
// turns, each capped, at most 8 KiB. History was admitted when it ran.
func sideContext(history []run.Turn, turns int) string {
	if turns <= 0 {
		turns = 6
	}
	start := max(len(history)-turns, 0)
	var b strings.Builder
	for _, t := range history[start:] {
		if t.Role != "user" && t.Role != "assistant" {
			continue
		}
		c := []rune(t.Content)
		if len(c) > 1500 {
			c = c[:1500]
		}
		line := t.Role + ": " + string(c) + "\n"
		if b.Len()+len(line) > 8<<10 {
			break
		}
		b.WriteString(line)
	}
	return b.String()
}

// rcAdmitText is the daemon's admission of remote text a model will read (a
// Keleustes dispatch's answer notes, a one-off worker's prompt): the host's
// classifier and posture for cwd, exactly as a prompt into a harness session
// is admitted (rcHarnessAdmit). A refusal, or no classifier, is an error.
func rcAdmitText(ctx context.Context, cwd, subject, text string) (string, error) {
	eff, err := config.Resolve(cwd, os.Getenv, config.Settings{})
	if err != nil {
		return "", err
	}
	c, err := rcHarnessClassifier(cwd, eff.Settings)
	if err != nil {
		return "", err
	}
	dec, err := run.NewPipeline(c, httpclient.Default(), nil).Admit(ctx, sanitize.Text(text), subject, rcHarnessPolicy(cwd))
	if err != nil {
		return "", err
	}
	return dec.Content, nil
}
