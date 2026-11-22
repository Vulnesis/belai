package rc

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/checkpoint"
	"github.com/vulnetix/belai/internal/rolemanager"
	"github.com/vulnetix/belai/internal/run"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/session"
	"github.com/vulnetix/belai/internal/sessionsync"
	"github.com/vulnetix/belai/internal/webask"
)

// Console session actions (belai-counterparts #45): the TUI's /compact,
// /relay, /undo, /rewind, /commit, /btw and /rename, run on a remote session
// from Keleustes. Each arrives as a RemoteCommand.Action on the controls
// channel, so it takes the --web-controls gate like any control, and each runs
// the host's own code: nothing the console sends is a command line. Text that
// a model reads (a compaction focus, a relay direction, an edited handoff, a
// side question) is admitted like a prompt; the relay replaces the
// conversation only after a person approves its relay_review ask.

// ActionNames are the console session actions, in the order the console shows
// them.
var ActionNames = []string{"compact", "relay", "undo", "rewind", "commit", "btw", "rename"}

// windDownActions only put back what the session did; they run while the
// factory is stopped (Keleustes sessions::WIND_DOWN).
var windDownActions = []string{"undo", "rewind"}

// IsWindDownAction reports whether the action only winds work down.
func IsWindDownAction(name string) bool { return slices.Contains(windDownActions, name) }

// KindRelayReview is the ask a relay raises: the handoff draft, for a person
// to approve, edit or drop.
const KindRelayReview = "relay_review"

// Relay review decisions.
const (
	RelayApprove = "approve"
	RelayEdit    = "edit"
	RelayDrop    = "drop"
)

// maxRenameRunes caps a session title from the console.
const maxRenameRunes = 120

// maxRelayEdit caps an edited handoff.
const maxRelayEdit = 64 << 10

// Actions are the host's implementations of the console session actions. A
// nil func refuses its action.
type Actions struct {
	// Rename names the session (a session_name entry).
	Rename func(title string)
	// Compact summarises history, steered by focus, and returns the admitted
	// summary.
	Compact func(ctx context.Context, history []run.Turn, focus string) (string, error)
	// Relay drafts a handoff note from history, steered by direction, and
	// returns it admitted.
	Relay func(ctx context.Context, history []run.Turn, direction string) (string, error)
	// Admit admits text a person edited (an edited handoff).
	Admit func(ctx context.Context, text string) (string, error)
	// Side answers a side question that stays out of the conversation.
	Side func(ctx context.Context, question string, history []run.Turn) (string, error)
	// Commit commits paths with message ("" for the harness's own message)
	// and returns the summary line.
	Commit func(ctx context.Context, paths []string, message string) (string, error)
	// Checkpoints is the session's file checkpoint store, or nil when
	// checkpoints are off.
	Checkpoints *checkpoint.Tracker
	// SessionID names the session in audit facts.
	SessionID string

	published string
}

// relayReview is the relay_review ask open now. Like a plan review it
// outlives the command that raised it and is answered while the session is
// idle.
type relayReview struct {
	askID     string
	text      string
	direction string
	turns     int
}

// auditAction records one console action and its outcome. Ids and words only.
func auditAction(a *Actions, name, status string) {
	sid := ""
	if a != nil {
		sid = a.SessionID
	}
	audit.Emit(audit.Fact{Kind: audit.HostDispatch, ActorKind: audit.ActorWeb, SessionID: sid, Outcome: status,
		Data: map[string]string{"dispatch": "session_action", "action": name, "status": status}})
}

// actionState is what an action may change in the session loop.
type actionState struct {
	history []run.Turn
	relay   *relayReview
	changed []string
}

// ackAction acknowledges an action with the controls' state.
func ackAction(o SessionOptions, c sessionsync.RemoteCommand, status, reason string) {
	auditAction(o.Actions, c.Action, status)
	ackCheckout(o, c.ID, status, reason)
}

// actionWhileRunning handles an action that arrives while a turn runs: a
// rename applies at once, the rest wait for the person to stop the turn.
func actionWhileRunning(o SessionOptions, c sessionsync.RemoteCommand) {
	if c.Action == "rename" {
		runRename(o, c)
		return
	}
	ackAction(o, c, sessionsync.AckRefused, "stop the running turn first")
}

func runRename(o SessionOptions, c sessionsync.RemoteCommand) {
	if o.Actions == nil || o.Actions.Rename == nil {
		ackAction(o, c, sessionsync.AckRefused, "this session cannot be renamed from the console")
		return
	}
	title := sanitize.Line(c.ActionArg, maxRenameRunes)
	if title == "" {
		ackAction(o, c, sessionsync.AckRefused, "rename takes a title")
		return
	}
	o.Actions.Rename(title)
	o.Log.System("console: session renamed")
	o.Mirror.Nudge()
	ackAction(o, c, sessionsync.AckAccepted, "")
}

// actionRefusal is why the action c cannot run in this session, or "".
func actionRefusal(o SessionOptions, c sessionsync.RemoteCommand) string {
	switch {
	case c.Line != "" || c.Key != "" || c.Command != "" || c.Shell != "" || c.Checkout != "" || c.Signal != "":
		return "an action carries nothing else"
	case o.Controls == nil:
		return "this session takes no controls from the web"
	case o.Actions == nil:
		return "this session takes no console actions"
	case !slices.Contains(ActionNames, c.Action):
		return "this session does not take that action"
	}
	return ""
}

// runAction runs one console action while the session is idle and returns the
// session loop's new state.
func runAction(ctx context.Context, o SessionOptions, c sessionsync.RemoteCommand, st actionState, bridge *askBridge) actionState {
	if why := actionRefusal(o, c); why != "" {
		ackAction(o, c, sessionsync.AckRefused, why)
		return st
	}
	a := o.Actions
	refuse := func(why string) actionState {
		ackAction(o, c, sessionsync.AckRefused, why)
		return st
	}
	text := strings.TrimSpace(c.ActionArg)
	switch c.Action {
	case "rename":
		runRename(o, c)
	case "compact":
		if a.Compact == nil {
			return refuse("this session cannot compact")
		}
		if len(st.history) == 0 {
			return refuse("compact: nothing to summarise yet")
		}
		summary, err := a.Compact(ctx, st.history, text)
		if err != nil {
			o.Log.System("console: compact: " + sanitize.Line(err.Error(), 200))
			o.Mirror.Nudge()
			return refuse(sanitize.Line(err.Error(), 200))
		}
		n := len(st.history)
		st.history = continueFrom(o, summary, "compaction", n)
		o.Log.System(fmt.Sprintf("console: compacted %d turns into a summary", n))
		o.Mirror.Nudge()
		ackAction(o, c, sessionsync.AckAccepted, "")
	case "relay":
		switch {
		case a.Relay == nil:
			return refuse("this session cannot relay")
		case bridge == nil || !o.Controls.Asks():
			return refuse("relay: turn ask on, so a person can review the handoff")
		case len(st.history) == 0:
			return refuse("relay: nothing to hand off yet")
		}
		note, err := a.Relay(ctx, st.history, text)
		if err != nil {
			return refuse(sanitize.Line(err.Error(), 200))
		}
		if st.relay != nil {
			closeRelay(bridge, st.relay, "a newer handoff replaced it")
		}
		st.relay = recordRelay(bridge, note, sanitize.Line(text, rolemanager.MaxRelayDirectionRunes), len(st.history))
		if st.relay == nil {
			return refuse("relay: the review could not be recorded")
		}
		ackAction(o, c, sessionsync.AckAccepted, "")
	case "undo", "rewind":
		t := a.Checkpoints
		if t == nil {
			return refuse(c.Action + ": file checkpoints are off in this session")
		}
		var id string
		if c.Action == "undo" {
			if text != "" {
				return refuse("undo takes no argument")
			}
			info, ok := t.Latest()
			if !ok {
				return refuse("undo: nothing to undo")
			}
			id = info.ID
		} else {
			if text == "" || strings.ContainsAny(text, " \t") {
				return refuse("rewind names one checkpoint")
			}
			id = text
			if !slices.ContainsFunc(t.List(), func(i checkpoint.Info) bool { return i.ID == id }) {
				return refuse("this session has no such checkpoint")
			}
		}
		plan, err := t.Plan(id)
		if err != nil {
			return refuse(sanitize.Line(err.Error(), 200))
		}
		if len(plan.Changes) == 0 {
			return refuse(c.Action + ": the files already match that checkpoint")
		}
		res, err := t.Apply(plan)
		if err != nil {
			return refuse(sanitize.Line(err.Error(), 200))
		}
		msg := fmt.Sprintf("console: %s %s: restored %d, removed %d", c.Action, id, res.Restored, res.Deleted)
		if res.Skipped > 0 {
			msg += fmt.Sprintf(", left %d", res.Skipped)
		}
		o.Log.System(msg)
		publishCheckpoints(o)
		o.Mirror.Nudge()
		ackAction(o, c, sessionsync.AckAccepted, "")
	case "commit":
		if a.Commit == nil {
			return refuse("this session cannot commit")
		}
		if len(st.changed) == 0 {
			return refuse("commit: this session changed no files")
		}
		line, err := a.Commit(ctx, st.changed, sanitize.Line(text, 200))
		if err != nil {
			return refuse(sanitize.Line(err.Error(), 200))
		}
		if line == "" {
			return refuse("commit: nothing to commit")
		}
		st.changed = nil
		o.Log.System("console: " + line)
		o.Mirror.Nudge()
		ackAction(o, c, sessionsync.AckAccepted, "")
	case "btw":
		if a.Side == nil {
			return refuse("this session cannot take a side question")
		}
		if text == "" {
			return refuse("btw takes a question")
		}
		reply, err := a.Side(ctx, text, st.history)
		if err != nil || strings.TrimSpace(reply) == "" {
			return refuse("btw: the side question could not be answered, nothing was added to the conversation")
		}
		if w := o.Log.Writer(); w != nil {
			w.Entry(session.Entry{Type: "system", Role: "system",
				Content: "side answer, not in history\nQ: " + sanitize.Line(text, 200) + "\n" + reply,
				Meta:    map[string]any{"kind": "btw"}})
		}
		o.Mirror.Nudge()
		ackAction(o, c, sessionsync.AckAccepted, "")
	}
	return st
}

// continueFrom writes text as the summary the conversation continues from (a
// "summary" entry, so a resume of this session continues from it too) and
// returns the history that replaces the old one.
func continueFrom(o SessionOptions, text, kind string, turns int) []run.Turn {
	if w := o.Log.Writer(); w != nil {
		w.Entry(session.Entry{Type: "summary", Content: text,
			Meta: map[string]any{"kind": kind, "source_messages": turns, "source": "console"}})
	}
	return []run.Turn{
		{Role: "user", Content: rolemanager.SummaryPrefix + text + rolemanager.SummarySuffix},
		{Role: "assistant", Content: rolemanager.SummaryAck},
	}
}

// relayOptions are the decisions a relay review takes.
var relayOptions = []string{RelayApprove, RelayEdit, RelayDrop}

// recordRelay writes the relay_review ask for an admitted handoff note.
func recordRelay(b *askBridge, note, direction string, turns int) *relayReview {
	meta := map[string]any{"options": relayOptions, "relay": map[string]string{"text": note, "direction": direction}}
	id := b.record(KindRelayReview, "handoff note ready for review", meta)
	if id == "" {
		return nil
	}
	return &relayReview{askID: id, text: note, direction: direction, turns: turns}
}

// closeRelay records the open relay review as closed because the host moved on.
func closeRelay(b *askBridge, r *relayReview, reason string) {
	if b == nil || r == nil {
		return
	}
	b.settle(r.askID, KindRelayReview, webask.FromHost, "", "", map[string]any{"closed": true, "reason": reason})
}

// relayAnswer is a relay review answer's payload.
type relayAnswer struct {
	Decision string `json:"decision"`
	Text     string `json:"text"`
}

// answerRelay applies one answer to the open relay review. It returns the new
// history and whether the review is settled.
func answerRelay(ctx context.Context, o SessionOptions, b *askBridge, r *relayReview, ans sessionsync.RemoteAnswer, history []run.Turn) ([]run.Turn, bool) {
	refuse := func(why string) ([]run.Turn, bool) {
		b.mirror.AckAnswer(ans.ID, sessionsync.AckRefused, why, "")
		return history, false
	}
	if ans.Kind != KindRelayReview {
		return refuse("the answer does not fit a relay review")
	}
	var pa relayAnswer
	if err := json.Unmarshal(ans.Payload, &pa); err != nil {
		return refuse("the answer does not fit a relay review")
	}
	text := r.text
	switch pa.Decision {
	case RelayDrop:
		id := b.settle(r.askID, KindRelayReview, webask.FromWeb, ans.ID, "relay review: dropped (answered on the web)", map[string]any{"decision": RelayDrop})
		b.mirror.AckAnswer(ans.ID, sessionsync.AckAccepted, "", id)
		auditAction(o.Actions, "relay", "dropped")
		return history, true
	case RelayApprove:
	case RelayEdit:
		edited := strings.TrimSpace(pa.Text)
		switch {
		case edited == "":
			return refuse("an edited handoff has text")
		case len(edited) > maxRelayEdit:
			return refuse("the edited handoff is too long")
		case o.Actions == nil || o.Actions.Admit == nil:
			return refuse("this session cannot check an edited handoff")
		}
		clean, err := o.Actions.Admit(ctx, edited)
		if err != nil {
			return refuse(sanitize.Line(err.Error(), 200))
		}
		text = clean
	default:
		return refuse("a relay review is approve, edit or drop")
	}
	id := b.settle(r.askID, KindRelayReview, webask.FromWeb, ans.ID, "relay review: "+pa.Decision+" (answered on the web)", map[string]any{"decision": pa.Decision})
	b.mirror.AckAnswer(ans.ID, sessionsync.AckAccepted, "", id)
	history = continueFrom(o, text, "handoff", len(history))
	o.Log.System("console: the conversation continues from the reviewed handoff note")
	o.Mirror.Nudge()
	auditAction(o.Actions, "relay", pa.Decision)
	return history, true
}

// maxPublishedCheckpoints caps the checkpoint list a session publishes.
const maxPublishedCheckpoints = 50

// publishCheckpoints writes the checkpoint list to the transcript when it
// changed (a "checkpoints" entry), so the console can offer rewind points.
// Ids, times, counts and the prompt's cleaned first line only.
func publishCheckpoints(o SessionOptions) {
	if o.Actions == nil || o.Actions.Checkpoints == nil {
		return
	}
	list := o.Actions.Checkpoints.List()
	var rows []map[string]any
	sig := ""
	for i := len(list) - 1; i >= 0 && len(rows) < maxPublishedCheckpoints; i-- {
		c := list[i]
		if c.Undone {
			continue
		}
		rows = append(rows, map[string]any{"id": c.ID, "at_ms": c.At.UnixMilli(), "label": sanitize.Line(c.Label, 120),
			"entry_id": c.Entry, "files": c.Files})
		sig += c.ID + ","
	}
	if sig == o.Actions.published {
		return
	}
	o.Actions.published = sig
	if w := o.Log.Writer(); w != nil {
		if rows == nil {
			rows = []map[string]any{}
		}
		w.Entry(session.Entry{Type: "checkpoints", Role: "system", Meta: map[string]any{"checkpoints": rows}})
	}
	o.Mirror.Nudge()
}
