package harnessrun

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// OriginAnswer is the origin of a prompt typed as the owner's answer to a
// question the harness's last reply asked.
const OriginAnswer = "owner-answer"

// MaxQuestion caps the question text an ask shows.
const MaxQuestion = 300

var questionLead = regexp.MustCompile(`(?i)^(would you like|do you want|should i|shall i|which|what|how would you like|could you|can you|please confirm|let me know)\b`)

// replyQuestion returns the question the final reply of a turn asks the
// owner, or "". It is conservative: only the reply's last paragraph counts,
// and it must end with a question mark, or open like a question ("Would you
// like", "Should I", ...) and hold one. A question earlier in the reply,
// followed by more text, is not one.
func replyQuestion(reply string) string {
	text := strings.TrimSpace(strings.ReplaceAll(reply, "\r\n", "\n"))
	if text == "" {
		return ""
	}
	paras := regexp.MustCompile(`\n\s*\n`).Split(text, -1)
	last := strings.TrimSpace(paras[len(paras)-1])
	// Markdown dressing does not change the question.
	plain := strings.TrimSpace(strings.Trim(last, "*_`> "))
	if plain == "" || strings.Contains(last, "```") {
		return ""
	}
	lines := strings.Split(plain, "\n")
	end := strings.TrimSpace(strings.TrimRight(lines[len(lines)-1], "*_` "))
	switch {
	case strings.HasSuffix(end, "?"):
	case questionLead.MatchString(strings.TrimLeft(plain, "-*• ")) && strings.Contains(plain, "?"):
	default:
		return ""
	}
	return sanitize.Line(plain, MaxQuestion)
}

// maybeQuestion raises a free-text ask when the turn just ended on a reply
// that asks the owner something. The native transcript is the source: the
// reply text, not the screen.
func (s *Session) maybeQuestion() {
	h := &s.hard
	h.mu.Lock()
	reply, at, typed, open := h.lastReply, h.lastReplyAt, h.lastTyped, h.question
	h.mu.Unlock()
	if open != "" || typed.IsZero() || at.Before(typed) || s.dialogs.open() != nil {
		return
	}
	q := replyQuestion(reply)
	if q == "" {
		return
	}
	h.mu.Lock()
	h.questions++
	id := "q-" + strconv.Itoa(h.questions)
	h.question = id
	h.mu.Unlock()
	// Parked, not live: the harness is idle at its prompt; the answer is the
	// next prompt.
	s.own("ask", "harness_question", q, map[string]any{"ask_id": id, "kind": "question", "tool": s.c.Harness.ID,
		"options": []string{"answer", "dismiss"}, "live": false})
	s.audit("question", "", map[string]string{"id": id})
}

// closeQuestion clears an open question (answered, dismissed or superseded
// by a prompt).
func (s *Session) closeQuestion(decision string) string {
	h := &s.hard
	h.mu.Lock()
	id := h.question
	h.question = ""
	h.mu.Unlock()
	if id != "" {
		s.own("ask_answer", "harness_question", decision, map[string]any{"ask_id": id, "decision": decision})
	}
	return id
}

// answerQuestion takes the owner's answer to the open question: "dismiss"
// closes it, "answer" with text types that text as the next prompt through
// the same admitted, neutralised, audited path as any remote prompt.
func (s *Session) answerQuestion(ctx context.Context, a sessionsync.RemoteAnswer) bool {
	s.hard.mu.Lock()
	open := s.hard.question
	s.hard.mu.Unlock()
	if open == "" || a.AskID != open {
		return false
	}
	refuse := func(why string) {
		_ = s.c.Mirror.AckAnswer(ctx, a.ID, sessionsync.AckRefused, why, "")
		s.audit("answer_refused", why, map[string]string{"id": a.AskID})
	}
	var p struct {
		Decision string `json:"decision"`
		Text     string `json:"text"`
	}
	if json.Unmarshal(a.Payload, &p) != nil {
		var plain string
		if json.Unmarshal(a.Payload, &plain) == nil {
			p.Decision, p.Text = "answer", plain
		}
	}
	if stopped, why := s.c.Stopped(); stopped {
		refuse("factory stopped: " + why)
		return true
	}
	switch p.Decision {
	case "dismiss":
		s.closeQuestion("dismissed")
		_ = s.c.Mirror.AckAnswer(ctx, a.ID, sessionsync.AckAccepted, "", "")
		s.audit("question_dismissed", "", map[string]string{"id": open})
		return true
	case "answer":
	default:
		refuse(`a question takes {"decision": "answer", "text": "..."} or {"decision": "dismiss"}`)
		return true
	}
	if !s.c.RemotePrompts {
		refuse("this host takes no remote prompts (sync.remote_prompts)")
		return true
	}
	text := sessionsync.CleanPrompt(p.Text)
	if _, err := PromptBytes(text, true, s.l.Input); err != nil {
		refuse(err.Error())
		return true
	}
	select {
	case s.prompts <- queued{text: text, origin: OriginAnswer}:
	default:
		refuse("too many prompts are waiting")
		return true
	}
	s.closeQuestion("answered")
	_ = s.c.Mirror.AckAnswer(ctx, a.ID, sessionsync.AckAccepted, "", "")
	s.audit("question_answered", "", map[string]string{"id": open, "from": OriginAnswer})
	return true
}
