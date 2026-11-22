package harnessrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/vulnetix/belai/internal/harness"
	"github.com/vulnetix/belai/internal/harnesstail"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// openDialog is a first-run screen shown to the owner as an ask.
type openDialog struct {
	askID string
	d     harness.Dialog
}

// dialogWatch tracks the profile's first-run screens. A screen is matched
// only in output after the last answered one, so an answered dialog still in
// the replay is not asked again.
type dialogWatch struct {
	mu   sync.Mutex
	cur  *openDialog
	from int64 // ring offset after the last answer
	// held is the dialog answered last, until the screen stops showing it.
	held string
	seen int64 // ring offset at the last scan
	// answered is when the last dialog was answered: the harness redraws after
	// it, and a prompt typed meanwhile is lost.
	answered time.Time
	n        int
}

func (w *dialogWatch) open() *openDialog {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cur
}

func squash(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToLower(r)
	}, s)
}

// scanDialogs looks for a profile dialog on the screen and, when one is up,
// asks the owner (an "ask" entry: Keleustes shows it with its options). The
// harness's screen text is only matched, never sent.
func (s *Session) scanDialogs() {
	if len(s.l.Dialogs) == 0 || s.r == nil {
		return
	}
	w := &s.dialogs
	buf, off := s.r.raw.Snapshot()
	w.mu.Lock()
	if w.cur != nil || off == w.seen {
		w.mu.Unlock()
		return
	}
	w.seen = off
	start := int64(len(buf)) - (off - w.from)
	if start < 0 {
		start = 0
	}
	held := w.held
	w.mu.Unlock()
	// The emulated screen first (a full-screen TUI redraws in place), then the
	// raw output since the last answer (a TUI the emulator draws wrongly).
	gridText := s.r.screen.text()
	rawText := screenText(buf[start:], 400)
	matches := dialogOn
	if held != "" {
		still := false
		for _, d := range s.l.Dialogs {
			still = still || (d.ID == held && matches(d, gridText))
		}
		if still {
			return // the answered dialog is still drawn; wait for it to go
		}
		w.mu.Lock()
		w.held = ""
		w.mu.Unlock()
	}
	for _, d := range s.l.Dialogs {
		plain := gridText
		if !matches(d, plain) {
			if plain = rawText; !matches(d, plain) {
				continue
			}
		}
		w.mu.Lock()
		w.n++
		od := &openDialog{askID: "dlg-" + strconv.Itoa(w.n) + "-" + d.ID, d: d}
		w.cur = od
		w.mu.Unlock()
		opts := make([]string, 0, len(d.Options))
		for _, o := range d.Options {
			opts = append(opts, o.ID)
		}
		title := d.Title
		if q := questionLine(plain, d.Match[0]); q != "" {
			title += ": " + q
		}
		s.own("ask", "harness_dialog", title, map[string]any{"ask_id": od.askID, "kind": "permission",
			"tool": s.c.Harness.ID, "options": opts, "dialog": d.ID, "live": true})
		s.audit("dialog", d.ID, map[string]string{"id": od.askID})
		return
	}
}

func (s *Session) watchDialogs(ctx context.Context) {
	if len(s.l.Dialogs) == 0 {
		return
	}
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.scanDialogs()
		}
	}
}

// answer takes the owner's answer to an open dialog and sends that option's
// fixed keys from the profile. Anything else is refused.
func (s *Session) answer(ctx context.Context, a sessionsync.RemoteAnswer) {
	if s.answerQuestion(ctx, a) {
		return
	}
	refuse := func(why string) {
		_ = s.c.Mirror.AckAnswer(ctx, a.ID, sessionsync.AckRefused, why, "")
		s.audit("answer_refused", why, map[string]string{"id": a.AskID})
	}
	od := s.dialogs.open()
	if od == nil || a.AskID != od.askID {
		refuse("this harness asks in its own screen; use keys")
		return
	}
	if !s.c.Controls {
		refuse("this host runs without --web-controls")
		return
	}
	if stopped, _ := s.c.Stopped(); stopped {
		refuse("factory stopped")
		return
	}
	decision, err := dialogDecision(a.Payload, od.askID)
	if err != nil {
		refuse(err.Error())
		return
	}
	var opt *harness.DialogOption
	var ids []string
	for i := range od.d.Options {
		ids = append(ids, od.d.Options[i].ID)
		if od.d.Options[i].ID == decision || strings.EqualFold(od.d.Options[i].Label, decision) {
			opt = &od.d.Options[i]
		}
	}
	if opt == nil {
		refuse(fmt.Sprintf("%q is not one of this question's answers (%s)", sanitize.Line(decision, 40), strings.Join(ids, ", ")))
		return
	}
	for _, k := range opt.Keys {
		_ = s.r.write([]byte(harness.KeyBytes[k]))
		time.Sleep(150 * time.Millisecond)
	}
	_, off := s.r.raw.Snapshot()
	s.dialogs.mu.Lock()
	s.dialogs.cur, s.dialogs.from, s.dialogs.answered, s.dialogs.held = nil, off, time.Now(), od.d.ID
	s.dialogs.mu.Unlock()
	i := s.own("ask_answer", "harness_dialog", opt.Label, map[string]any{"ask_id": od.askID, "decision": opt.ID, "dialog": od.d.ID})
	_ = s.c.Mirror.AckAnswer(ctx, a.ID, sessionsync.AckAccepted, "", strconv.FormatInt(i, 10))
	s.audit("dialog_answered", opt.ID, map[string]string{"id": od.askID, "decision": opt.ID})
}

// usageProvider is the provider a dialect's tokens are billed by when the
// line does not say.
var usageProvider = map[string]string{"jsonl-claude": "anthropic", "jsonl-codex": "openai"}

// usage records the tokens a native record reports as a usage line (an
// "assistant" entry whose meta the mirror adds up per model), once per model
// message.
func (s *Session) usage(e harnesstail.Event) {
	s.usageMu.Lock()
	if e.Model != "" {
		s.model = e.Model
	}
	// A resumed session's file starts with the earlier session's lines: their
	// usage was counted then.
	if !e.At.IsZero() && e.At.Before(s.started.Add(-2*time.Second)) {
		s.usageMu.Unlock()
		return
	}
	if e.InputTokens+e.OutputTokens+e.CacheRead+e.CacheWrite == 0 {
		s.usageMu.Unlock()
		return
	}
	if e.MessageID != "" {
		if s.seenMsg == nil {
			s.seenMsg = map[string]bool{}
		}
		if s.seenMsg[e.MessageID] {
			s.usageMu.Unlock()
			return
		}
		s.seenMsg[e.MessageID] = true
	}
	model := s.model
	s.usageMu.Unlock()
	provider := e.Provider
	if provider == "" && s.l.Transcript != nil {
		provider = usageProvider[s.l.Transcript.Dialect]
	}
	if provider == "" {
		provider = s.c.Harness.ID
	}
	if model == "" {
		model = s.c.Model
	}
	s.inTok.Add(e.InputTokens)
	s.outTok.Add(e.OutputTokens)
	s.own("assistant", "harness_usage", fmt.Sprintf("%d in · %d out · %s", e.InputTokens, e.OutputTokens, model), map[string]any{"provider": provider, "model": model,
		"prompt_tokens": e.InputTokens, "completion_tokens": e.OutputTokens,
		"cache_read_tokens": e.CacheRead, "cache_write_tokens": e.CacheWrite})
}

// settling reports whether a dialog was answered moments ago and the screen
// is still moving.
func (s *Session) settling() bool {
	s.dialogs.mu.Lock()
	at := s.dialogs.answered
	s.dialogs.mu.Unlock()
	return !at.IsZero() && (time.Since(at) < 2*time.Second || s.r.Quiet() < s.c.Timings.ReadyQuiet)
}

// dialogDecision reads an answer for askID in any of the shapes Keleustes
// sends: {"decision": "..."}, a plain JSON string (one question), or
// {"answers": {"<ask id>": "..."}} (several questions in one go; only the
// open one is taken, and an unknown id is refused by name).
func dialogDecision(payload json.RawMessage, askID string) (string, error) {
	var one struct {
		Decision string            `json:"decision"`
		Answers  map[string]string `json:"answers"`
	}
	var s string
	switch {
	case json.Unmarshal(payload, &s) == nil:
		return strings.TrimSpace(s), nil
	case json.Unmarshal(payload, &one) == nil && one.Decision != "":
		return one.Decision, nil
	case len(one.Answers) > 0:
		var unknown []string
		for id := range one.Answers {
			if id != askID {
				unknown = append(unknown, sanitize.Ident(id, 64))
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			return "", fmt.Errorf("no open question %s; the open one is %s", strings.Join(unknown, ", "), askID)
		}
		return one.Answers[askID], nil
	}
	return "", errors.New(`the answer is not {"decision": "<option>"}, a plain option, or {"answers": {"<question id>": "<option>"}}`)
}

// questionLine is the last screen line holding the dialog's first match (the
// harness's own question, such as "Do you want to create hello.txt?"),
// cleaned to one short line. It is harness text, shown as data.
func questionLine(screen, match string) string {
	want := squash(match)
	lines := strings.Split(screen, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(squash(lines[i]), want) {
			return sanitize.Line(lines[i], 200)
		}
	}
	return ""
}

// dialogOn reports whether every text of d's match list is on the screen
// (compared without whitespace and case).
func dialogOn(d harness.Dialog, screen string) bool {
	t := squash(screen)
	for _, m := range d.Match {
		if !strings.Contains(t, squash(m)) {
			return false
		}
	}
	return true
}
