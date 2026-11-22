package factorylink

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/sessionctl"
	"github.com/vulnetix/belai/internal/sessionmeasure"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// tracked is what a session's uploaded lines say beyond its registration:
// whether a turn runs, the ask it waits on, and usage per model. It is read
// only from lines the harness already wrote (turn_state, ask, ask_answer,
// assistant usage meta), so it adds nothing a transcript does not hold.
type tracked struct {
	turn bool
	// seen: a turn_state line arrived; until then the session reads live.
	seen  bool
	ask   *nodev1.PendingAsk
	kinds map[string]string // ask id -> kind, for structured answers
	usage map[[2]string]*nodev1.ModelUsage
	turns uint32
	// checkpoints is the last checkpoint list the session wrote (rc
	// actions.go), and planSHA the hash of the last plan file it returned.
	checkpoints []*nodev1.Checkpoint
	planSHA     string
}

func newTracked() *tracked {
	return &tracked{kinds: map[string]string{}, usage: map[[2]string]*nodev1.ModelUsage{}}
}

// maxAskTitle caps the ask title a session publishes.
const maxAskTitle = 300

// maxCheckpoints caps the checkpoint list a session publishes.
const maxCheckpoints = 50

// askOptionLabels are the labels of the decisions webask knows. An id the
// table lacks is shown as itself.
var askOptionLabels = map[string]string{
	"allow_once":   "Allow once",
	"allow_always": "Allow always",
	"deny":         "Deny",
	"approve_here": "Approve",
	"approve_new":  "Approve in a new session",
	"refine":       "Refine",
	"stay":         "Stay in plan",
	"trust":        "Trust",
	"dont_trust":   "Don't trust",
	"answer":       "Answer",
	"dismiss":      "Dismiss",
	"approve":      "Approve",
	"edit":         "Edit",
	"drop":         "Drop",
}

// observe reads one uploaded line and reports whether the session's
// published state changed.
func (t *tracked) observe(e sessionsync.Entry) bool {
	switch e.Type {
	case "turn_state":
		var m struct {
			State string `json:"state"`
		}
		if json.Unmarshal(e.Meta, &m) != nil {
			return false
		}
		running := m.State == "started"
		t.seen = true
		if running && !t.turn {
			t.turns++
		}
		changed := running != t.turn
		t.turn = running
		return changed
	case "ask":
		var m struct {
			AskID         string          `json:"ask_id"`
			Kind          string          `json:"kind"`
			Tool          string          `json:"tool"`
			Options       []string        `json:"options"`
			Questionnaire json.RawMessage `json:"questionnaire"`
			Relay         *struct {
				Text      string `json:"text"`
				Direction string `json:"direction"`
			} `json:"relay"`
		}
		if json.Unmarshal(e.Meta, &m) != nil || m.AskID == "" {
			return false
		}
		t.kinds[m.AskID] = m.Kind
		a := &nodev1.PendingAsk{
			Id: sanitize.Ident(m.AskID, 64), Kind: sanitize.Ident(m.Kind, 32),
			Title: capLine(e.Content, maxAskTitle), Tool: sanitize.Line(m.Tool, 120),
			AskedAtMs: e.Timestamp,
		}
		for _, o := range m.Options {
			id := sanitize.Ident(o, 64)
			if id == "" {
				continue
			}
			label := askOptionLabels[id]
			if label == "" {
				label = id
			}
			a.Options = append(a.Options, &nodev1.AskOption{Id: id, Label: label})
		}
		if len(m.Questionnaire) > 0 && json.Valid(m.Questionnaire) && len(m.Questionnaire) <= 64<<10 {
			a.QuestionsJson = string(m.Questionnaire)
		}
		if m.Relay != nil && len(m.Relay.Text) <= 64<<10 {
			// The handoff draft (model text, admitted by the host): data for
			// the reviewer, never instructions.
			rj, _ := json.Marshal(map[string]string{"text": sanitize.Text(m.Relay.Text), "direction": sanitize.Line(m.Relay.Direction, 500)})
			a.RelayJson = string(rj)
		}
		t.ask = a
		return true
	case "checkpoints":
		var m struct {
			Checkpoints []struct {
				ID      string `json:"id"`
				AtMS    int64  `json:"at_ms"`
				Label   string `json:"label"`
				EntryID string `json:"entry_id"`
				Files   uint32 `json:"files"`
			} `json:"checkpoints"`
		}
		if json.Unmarshal(e.Meta, &m) != nil {
			return false
		}
		t.checkpoints = t.checkpoints[:0]
		for _, c := range m.Checkpoints {
			if len(t.checkpoints) == maxCheckpoints {
				break
			}
			id := sanitize.Ident(c.ID, 16)
			if id == "" {
				continue
			}
			t.checkpoints = append(t.checkpoints, &nodev1.Checkpoint{Id: id, AtMs: c.AtMS, Label: capLine(c.Label, 120),
				EntryId: sanitize.Ident(c.EntryID, 64), Files: c.Files})
		}
		return true
	case "plan_file":
		var m struct {
			SHA256 string `json:"sha256"`
		}
		if json.Unmarshal(e.Meta, &m) != nil || len(m.SHA256) != 64 || sanitize.Ident(m.SHA256, 64) != m.SHA256 {
			return false
		}
		t.planSHA = m.SHA256
		return false
	case "ask_answer":
		var m struct {
			AskID string `json:"ask_id"`
		}
		if json.Unmarshal(e.Meta, &m) != nil || t.ask == nil || t.ask.GetId() != m.AskID {
			return false
		}
		t.ask = nil
		return true
	case "assistant":
		var m struct {
			Provider         string `json:"provider"`
			Model            string `json:"model"`
			PromptTokens     int64  `json:"prompt_tokens"`
			CompletionTokens int64  `json:"completion_tokens"`
			CacheRead        int64  `json:"cache_read_tokens"`
			CacheWrite       int64  `json:"cache_write_tokens"`
			Cost             *int64 `json:"cost_micro_usd"`
		}
		if json.Unmarshal(e.Meta, &m) != nil || (m.PromptTokens == 0 && m.CompletionTokens == 0 && m.Cost == nil) {
			return false
		}
		k := [2]string{m.Provider, m.Model}
		u := t.usage[k]
		if u == nil {
			u = &nodev1.ModelUsage{Provider: m.Provider, Model: m.Model}
			t.usage[k] = u
		}
		u.InputTokens += m.PromptTokens
		u.OutputTokens += m.CompletionTokens
		u.CacheReadTokens += m.CacheRead
		u.CacheWriteTokens += m.CacheWrite
		if m.Cost != nil {
			u.CostUsd += float64(*m.Cost) / 1e6
		}
		return true
	}
	return false
}

// apply writes the tracked state onto an upsert.
func (t *tracked) apply(up *nodev1.SessionUpsert) {
	switch {
	case t.ask != nil:
		up.State = "waiting"
	case t.turn || !t.seen:
		up.State = "live"
	default:
		up.State = "idle"
	}
	up.PendingAsk = t.ask
	up.PendingQuestionId, up.PendingQuestion = "", ""
	if t.ask != nil {
		up.PendingQuestionId, up.PendingQuestion = t.ask.GetId(), t.ask.GetTitle()
	}
	up.Usage = up.Usage[:0]
	var in, out int64
	var cost float64
	for _, u := range t.usage {
		up.Usage = append(up.Usage, &nodev1.ModelUsage{Provider: u.Provider, Model: u.Model,
			InputTokens: u.InputTokens, OutputTokens: u.OutputTokens, CacheReadTokens: u.CacheReadTokens,
			CacheWriteTokens: u.CacheWriteTokens, CostUsd: u.CostUsd})
		in += u.InputTokens
		out += u.OutputTokens
		cost += u.CostUsd
	}
	up.InputTokens, up.OutputTokens, up.CostUsd = in, out, cost
	up.Checkpoints = t.checkpoints
}

func capLine(s string, n int) string {
	s = sanitize.Line(s, n)
	for len(s) > n {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

// acceptsFor says what remote input the session admits, from the syncer's
// options: the console offers only these.
func acceptsFor(m sessionsync.SessionMeta) *nodev1.SessionAccepts {
	a := &nodev1.SessionAccepts{Prompts: m.RemotePrompts, Answers: m.RemoteAnswers, Controls: m.Controls, Shell: m.Shell}
	if m.Harness != "" {
		// A third-party harness takes stop, interrupt and its own allowlisted
		// keys (named in the node's advert), never belai's session controls.
		if m.Controls {
			a.ControlsAllowed = []string{sessionsync.SignalStop, sessionsync.SignalInterrupt, "key"}
		}
		a.Shell = false
		return a
	}
	if m.Controls {
		a.ControlsAllowed = append(a.ControlsAllowed, sessionsync.SignalStop, sessionsync.SignalInterrupt, "checkout", "key")
		for _, c := range sessionctl.Controls {
			a.ControlsAllowed = append(a.ControlsAllowed, strings.TrimPrefix(c.Command, "/"))
		}
		a.ControlsAllowed = append(a.ControlsAllowed, "command")
		// The console session actions (rc/actions.go).
		a.ControlsAllowed = append(a.ControlsAllowed, "compact", "relay", "undo", "rewind", "commit", "btw", "rename")
	}
	return a
}

// gitFacts maps internal/gitsync.Info's identifier fields.
func gitFacts(raw json.RawMessage) *nodev1.GitFacts {
	var g struct {
		Head     string `json:"head"`
		Dirty    bool   `json:"dirty"`
		Ahead    int32  `json:"ahead"`
		Behind   int32  `json:"behind"`
		Detached bool   `json:"detached"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &g) != nil {
		return nil
	}
	return &nodev1.GitFacts{Commit: sanitize.Ident(g.Head, 64), Dirty: g.Dirty, Ahead: g.Ahead, Behind: g.Behind, Detached: g.Detached}
}

// rollupUsage maps the end-of-session rollup.
func rollupUsage(r *sessionmeasure.Rollup) []*nodev1.ModelUsage {
	if r == nil {
		return nil
	}
	out := make([]*nodev1.ModelUsage, 0, len(r.Models))
	for _, m := range r.Models {
		u := &nodev1.ModelUsage{Provider: m.Provider, Model: m.Model, InputTokens: m.PromptTokens,
			OutputTokens: m.CompletionTokens, CacheReadTokens: m.CacheReadTokens, CacheWriteTokens: m.CacheWriteTokens}
		if m.CostMicroUSD != nil {
			u.CostUsd = float64(*m.CostMicroUSD) / 1e6
		}
		out = append(out, u)
	}
	return out
}

// structuredAnswer maps a Keleustes Answer onto webask's answer shape for
// the ask kind open on the host. The host's validator (webask) still checks
// it against the open ask, exactly as a website answer.
func structuredAnswer(kind string, a *nodev1.Answer) (string, json.RawMessage) {
	if a.GetDecision() == "" && a.GetPayloadJson() == "" {
		return answerPayload(a.GetText())
	}
	switch kind {
	case "permission":
		b, _ := json.Marshal(map[string]string{"decision": a.GetDecision()})
		return kind, b
	case "plan_review":
		b, _ := json.Marshal(map[string]string{"choice": a.GetDecision(), "notes": a.GetText()})
		return kind, b
	case "relay_review":
		// A console relay review (rc/actions.go): approve, drop, or edit with
		// the edited note as text, which the host admits again.
		b, _ := json.Marshal(map[string]string{"decision": a.GetDecision(), "text": a.GetText()})
		return kind, b
	case "question":
		// A harness question: the owner's free text, typed as the next prompt.
		b, _ := json.Marshal(map[string]string{"decision": a.GetDecision(), "text": a.GetText()})
		return kind, b
	case "clarify", "mode_choice":
		raw := json.RawMessage(a.GetPayloadJson())
		if !json.Valid(raw) {
			b, _ := json.Marshal(a.GetPayloadJson())
			return kind, b
		}
		return kind, raw
	}
	// Unknown kind (an ask this process did not see): no kind, which every
	// ask refuses as not fitting.
	b, _ := json.Marshal(a.GetDecision())
	return "", b
}
