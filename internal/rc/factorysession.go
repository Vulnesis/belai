package rc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/session"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// Keleustes start fields beyond the website's (belai-counterparts #46, #51,
// #52, #55): resume and fork a session of this host, answer its questions up
// front, its harness gates, and a worker with no stored profile. Every value
// is untrusted and checked here or by the child before it is used; text a
// model will read (an answer's note, a worker's prompt) is admitted by the
// host's classifier first (Options.AdmitText).

// factoryDispatchFeatures are the optional Dispatch fields this daemon applies,
// advertised in Capabilities.dispatch_features so Keleustes sends no other.
var factoryDispatchFeatures = []string{"resume", "fork", "answers", "gates", "adhoc", "plan_upload", "session_actions", "attachments"}

// Bounds on the Keleustes-only fields.
const (
	maxAnswersBytes  = 64 << 10
	maxAnswerEntries = 64
	maxAnswerNote    = 4000
	maxAnswerMatch   = 200
	maxAdhocPrompt   = 16 << 10
	maxAdhocTools    = 64
)

// factorySessionExtras copies the Keleustes-only fields onto the request.
func factorySessionExtras(fd *nodev1.Dispatch, r *sessionsync.Dispatch) {
	r.Resume, r.Fork, r.Answers = fd.GetResumeSession(), fd.GetForkEntry(), fd.GetAnswersJson()
	if a := fd.GetAdhoc(); a != nil {
		claim := ""
		if l := a.GetClaimLists(); len(l) > 0 {
			claim = l[0]
			if len(l) > 1 {
				// More than one list is refused by checkFactoryExtras; keep the
				// shape so it fails there, not here.
				claim = strings.Join(l, ",")
			}
			if lb := a.GetClaimLabels(); len(lb) > 0 {
				claim += ":" + strings.Join(lb, ",")
			}
		}
		r.Adhoc = &sessionsync.AdhocSpec{Prompt: a.GetPrompt(), Tools: a.GetTools(), Claim: claim, To: a.GetTo(),
			Publish: a.GetPublish(), ReadOnly: a.GetReadOnly()}
	}
}

// checkFactoryExtras refuses the Keleustes-only fields on a kind they do not
// apply to, so nothing is silently ignored.
func checkFactoryExtras(fd *nodev1.Dispatch, kind string) string {
	session := kind == "session"
	switch {
	case (fd.GetResumeSession() != "" || fd.GetForkEntry() != "" || fd.GetAnswersJson() != "") && !session:
		return "resume, fork and answers apply to a session dispatch"
	case fd.GetForkEntry() != "" && fd.GetResumeSession() == "":
		return "a fork names the session it forks"
	case fd.GetResumeSession() != "" && fd.GetHarness() != "":
		return "a harness session resumes with harness_resume"
	case fd.GetAdhoc() != nil && kind != "worker":
		return "a one-off worker is a worker dispatch"
	case fd.GetAdhoc() != nil && fd.GetAgent() != "":
		return "a one-off worker names no profile"
	case fd.GetAdhoc() != nil && len(fd.GetAdhoc().GetClaimLists()) > 1:
		return "a one-off worker claims from one list"
	case len(fd.GetAttachments()) > 0 && !session:
		return "attachments apply to a session dispatch"
	case len(fd.GetAttachments()) > 0 && fd.GetHarness() != "":
		return "a harness session takes no attachments"
	case len(fd.GetAttachments()) > 0:
		if why := factorylink.CheckAttachments(fd.GetAttachments()); why != "" {
			return why
		}
	}
	return ""
}

// validEntryID accepts the shape of a session entry id (session.Writer).
func validEntryID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// sessionStore is the store resumes read from.
func (d *Daemon) sessionStore() (*session.Store, error) {
	if d.o.Sessions != nil {
		return d.o.Sessions, nil
	}
	return session.NewStore()
}

// checkResume says why the session a start resumes cannot be resumed in cwd
// (an offered directory, resolved), or "". Only a session stored for cwd's
// project on this host qualifies, so a resume never reaches another project's
// files or a session this host does not hold.
func (d *Daemon) checkResume(r sessionsync.Dispatch, cwd string) string {
	if r.Resume == "" {
		return ""
	}
	switch {
	case !session.ValidID(r.Resume):
		return "that is not a session id"
	case r.Fork != "" && !validEntryID(r.Fork):
		return "that is not an entry id"
	case r.Branch != "" || r.Workspace != "":
		return "a resumed session runs where it ran; it takes no branch or workspace"
	case IsPixMode(r.Mode):
		return "a pix-assistant session cannot be resumed"
	}
	store, err := d.sessionStore()
	if err != nil {
		return "this host has no session store"
	}
	key, err := session.KeyFor(cwd)
	if err != nil {
		return "this host has no such session"
	}
	entries, err := store.ReadFrom(key, r.Resume)
	if err != nil || len(entries) == 0 {
		return "this host has no such session"
	}
	if r.Fork != "" {
		e, err := session.FindEntry(entries, r.Fork)
		if err != nil || e.ID != r.Fork {
			return "that session has no such entry"
		}
		if _, _, err := session.Target(e); err != nil {
			return "fork at a user message or a final assistant reply"
		}
	}
	return ""
}

// scriptedAnswer is one entry of an -answers file (cmd/belai/answers.go).
type scriptedAnswer struct {
	Choose *int   `json:"choose,omitempty"`
	Note   string `json:"note,omitempty"`
	Skip   bool   `json:"skip,omitempty"`
	Match  string `json:"match,omitempty"`
}

// errAnswersRefused is the refusal for answers the classifier did not admit.
var errAnswersRefused = errors.New("the answers were refused")

// checkAnswers parses and bounds a dispatch's answers, admits every note
// through the host's classifier, and returns the file to hand the session
// (the admitted notes, re-encoded) or the reason it refused.
func (d *Daemon) checkAnswers(ctx context.Context, cwd, raw string) ([]byte, string) {
	if raw == "" {
		return nil, ""
	}
	if len(raw) > maxAnswersBytes {
		return nil, fmt.Sprintf("the answers are larger than %d bytes", maxAnswersBytes)
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var list []scriptedAnswer
	if err := dec.Decode(&list); err != nil || dec.More() {
		return nil, `the answers are a JSON array of {"choose", "note", "skip", "match"}`
	}
	if len(list) > maxAnswerEntries {
		return nil, fmt.Sprintf("at most %d answers", maxAnswerEntries)
	}
	for i := range list {
		a := &list[i]
		if a.Choose != nil && *a.Choose < 0 {
			return nil, fmt.Sprintf("answer %d: choose must not be negative", i)
		}
		if a.Match != "" {
			if utf8.RuneCountInString(a.Match) > maxAnswerMatch {
				return nil, fmt.Sprintf("answer %d: match is longer than %d characters", i, maxAnswerMatch)
			}
			if _, err := regexp.Compile("(?i)" + a.Match); err != nil {
				return nil, fmt.Sprintf("answer %d: match is not a pattern", i)
			}
		}
		if a.Note == "" {
			continue
		}
		if utf8.RuneCountInString(a.Note) > maxAnswerNote {
			return nil, fmt.Sprintf("answer %d: the note is longer than %d characters", i, maxAnswerNote)
		}
		if d.o.AdmitText == nil {
			return nil, "this host cannot check answers"
		}
		clean, err := d.o.AdmitText(ctx, cwd, "dispatch answers", a.Note)
		if err != nil {
			return nil, errAnswersRefused.Error()
		}
		a.Note = clean
	}
	b, err := json.Marshal(list)
	if err != nil {
		return nil, "the answers could not be encoded"
	}
	return b, ""
}

// answersPath is where the daemon leaves a session's answers for it: beside
// the session's log, mode 0600, removed when the session ends.
func (d *Daemon) answersPath(sid string) string {
	p := d.sessionLog(sid)
	if p == "" {
		return ""
	}
	return strings.TrimSuffix(p, ".log") + ".answers.json"
}

// writeAnswers writes b to path for the child to read.
func writeAnswers(path string, b []byte) error {
	if path == "" {
		return errors.New("no state directory")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// gateIgnored drops the gate options that would loosen what the host's
// settings for cwd say, auditing each dispatch that had any, and returns the
// options to pass on.
func gateIgnored(opts map[string]string, cwd, dispatchID string) map[string]string {
	has := false
	for k := range opts {
		if slices.Contains(GateOptionKeys, k) {
			has = true
		}
	}
	if !has {
		return opts
	}
	eff, err := config.Resolve(cwd, os.Getenv, config.Settings{})
	if err != nil {
		return opts
	}
	s := eff.Settings
	ignored := ApplyGateOptions(&s, opts)
	if len(ignored) == 0 {
		return opts
	}
	out := make(map[string]string, len(opts))
	for k, v := range opts {
		if !slices.Contains(ignored, k) {
			out[k] = v
		}
	}
	audit.Emit(audit.Fact{Kind: audit.HostDispatch, ActorKind: audit.ActorWeb, Outcome: "option_ignored",
		Data: map[string]string{"dispatch": "session", "status": "option_ignored", "gate": strings.Join(ignored, "+"),
			"id": sanitize.Ident(dispatchID, 64)}})
	return out
}

// toolName is the shape of a tool name a one-off worker may list.
var toolName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

// listName is the shape of a board list or label a one-off worker names.
var listName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// checkAdhoc checks a one-off worker's spec and admits its prompt through the
// host's classifier, returning the spec to start (the admitted prompt) or the
// reason it refused. The worker validates the profile it builds again.
func (d *Daemon) checkAdhoc(ctx context.Context, cwd string, a *sessionsync.AdhocSpec) (*sessionsync.AdhocSpec, string) {
	out := *a
	out.Prompt = strings.TrimSpace(a.Prompt)
	switch {
	case out.Prompt == "":
		return nil, "a one-off worker needs a prompt"
	case len(out.Prompt) > maxAdhocPrompt:
		return nil, fmt.Sprintf("a one-off worker's prompt is at most %d bytes", maxAdhocPrompt)
	case len(a.Tools) > maxAdhocTools:
		return nil, fmt.Sprintf("a one-off worker lists at most %d tools", maxAdhocTools)
	}
	for _, t := range a.Tools {
		if !toolName.MatchString(t) {
			return nil, "that is not a tool name"
		}
	}
	if a.Claim != "" {
		list, labels, _ := strings.Cut(a.Claim, ":")
		if !listName.MatchString(list) {
			return nil, "a one-off worker claims from one list"
		}
		if labels != "" {
			for _, l := range strings.Split(labels, ",") {
				if !listName.MatchString(l) {
					return nil, "that is not a label"
				}
			}
		}
	}
	if a.To != "" && !listName.MatchString(a.To) {
		return nil, "that is not a list name"
	}
	switch a.Publish {
	case "", "none", "draft_pr", "agent":
	default:
		return nil, "publish is none, draft_pr or agent"
	}
	if d.o.AdmitText == nil {
		return nil, "this host cannot check a one-off worker's prompt"
	}
	clean, err := d.o.AdmitText(ctx, cwd, "one-off worker prompt", out.Prompt)
	if err != nil {
		return nil, "the worker's prompt was refused"
	}
	out.Prompt = strings.TrimSpace(clean)
	if out.Prompt == "" {
		return nil, "the worker's prompt was empty after cleaning"
	}
	return &out, ""
}

// adhocArgs is the argv tail of `belai agent start` for a one-off worker. The
// prompt never goes on argv, which every user on the host can read: it goes in
// sessionsync.AdhocPromptEnv (see runAgentStart) and the child reads it there.
func adhocArgs(a *sessionsync.AdhocSpec) []string {
	args := []string{"-prompt-from-env"}
	if len(a.Tools) > 0 {
		args = append(args, "-tools="+strings.Join(a.Tools, ","))
	}
	if a.Claim != "" {
		args = append(args, "-claim="+a.Claim)
	}
	if a.To != "" {
		args = append(args, "-to="+a.To)
	}
	if a.Publish != "" {
		args = append(args, "-publish="+a.Publish)
	}
	if a.ReadOnly {
		args = append(args, "-read-only")
	}
	return args
}

// adhocDigest is the audit's view of a one-off worker: the prompt's hash, never
// its text.
func adhocDigest(a *sessionsync.AdhocSpec) string {
	sum := sha256.Sum256([]byte(a.Prompt))
	return hex.EncodeToString(sum[:8])
}

// auditResume records a resume or fork start with the session it continues.
func auditResume(r sessionsync.Dispatch, sid string) {
	status := "resume"
	if r.Fork != "" {
		status = "fork"
	}
	audit.Emit(audit.Fact{Kind: audit.HostDispatch, ActorKind: audit.ActorWeb, SessionID: sid, Outcome: status,
		Data: map[string]string{"dispatch": "session", "status": status, "target": r.Resume}})
}

// answersDigest is the audit's view of a dispatch's answers.
func answersDigest(b []byte) string {
	sum := sha256.Sum256(bytes.TrimSpace(b))
	return hex.EncodeToString(sum[:8])
}
