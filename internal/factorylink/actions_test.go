package factorylink

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// The console session actions map onto RemoteCommand.Action, each with the
// argument shape it takes; anything else is refused.
func TestToCommandActions(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want sessionsync.RemoteCommand
		ok   bool
	}{
		{"compact", nil, sessionsync.RemoteCommand{Action: "compact"}, true},
		{"compact", []string{"keep", "tests"}, sessionsync.RemoteCommand{Action: "compact", ActionArg: "keep tests"}, true},
		{"relay", []string{"next"}, sessionsync.RemoteCommand{Action: "relay", ActionArg: "next"}, true},
		{"undo", nil, sessionsync.RemoteCommand{Action: "undo"}, true},
		{"undo", []string{"x"}, sessionsync.RemoteCommand{}, false},
		{"rewind", []string{"c3"}, sessionsync.RemoteCommand{Action: "rewind", ActionArg: "c3"}, true},
		{"rewind", nil, sessionsync.RemoteCommand{}, false},
		{"rewind", []string{"c1", "c2"}, sessionsync.RemoteCommand{}, false},
		{"commit", nil, sessionsync.RemoteCommand{Action: "commit"}, true},
		{"btw", []string{"why?"}, sessionsync.RemoteCommand{Action: "btw", ActionArg: "why?"}, true},
		{"btw", nil, sessionsync.RemoteCommand{}, false},
		{"rename", []string{"New", "name"}, sessionsync.RemoteCommand{Action: "rename", ActionArg: "New name"}, true},
		{"rename", nil, sessionsync.RemoteCommand{}, false},
	}
	for _, c := range cases {
		got, ok := ToCommand(&nodev1.Command{Name: c.name, Args: c.args})
		if ok != c.ok || got != c.want {
			t.Errorf("ToCommand(%s %v) = %+v, %v; want %+v, %v", c.name, c.args, got, ok, c.want, c.ok)
		}
	}
	a := acceptsFor(sessionsync.SessionMeta{Controls: true})
	for _, n := range []string{"compact", "relay", "undo", "rewind", "commit", "btw", "rename"} {
		if !slices.Contains(a.GetControlsAllowed(), n) {
			t.Errorf("controls_allowed lacks %s: %v", n, a.GetControlsAllowed())
		}
	}
	if a := acceptsFor(sessionsync.SessionMeta{}); len(a.GetControlsAllowed()) != 0 {
		t.Errorf("a session without controls lists %v", a.GetControlsAllowed())
	}
}

// A relay review ask carries its draft; a checkpoints line becomes the
// upsert's list; a plan_file line's hash rides to the session's end; a
// relay_review answer maps to its decision and the edited text.
func TestTrackedActions(t *testing.T) {
	tr := newTracked()
	meta, _ := json.Marshal(map[string]any{"ask_id": "a1", "kind": "relay_review", "options": []string{"approve", "edit", "drop"},
		"relay": map[string]string{"text": "note\x1b[31m", "direction": "next"}})
	if !tr.observe(sessionsync.Entry{Type: "ask", Content: "handoff note ready for review", Meta: meta}) {
		t.Fatal("ask not observed")
	}
	if tr.ask.GetKind() != "relay_review" || len(tr.ask.GetOptions()) != 3 || tr.ask.GetOptions()[0].GetLabel() != "Approve" {
		t.Fatalf("ask = %+v", tr.ask)
	}
	var rj map[string]string
	if err := json.Unmarshal([]byte(tr.ask.GetRelayJson()), &rj); err != nil || rj["direction"] != "next" || strings.Contains(rj["text"], "\x1b") {
		t.Fatalf("relay_json = %q", tr.ask.GetRelayJson())
	}
	cm, _ := json.Marshal(map[string]any{"checkpoints": []map[string]any{{"id": "c2", "at_ms": 5, "label": "fix it", "entry_id": "e-1", "files": 3},
		{"id": "../bad", "files": 1}}})
	if !tr.observe(sessionsync.Entry{Type: "checkpoints", Meta: cm}) {
		t.Fatal("checkpoints not observed")
	}
	up := &nodev1.SessionUpsert{}
	tr.apply(up)
	if len(up.GetCheckpoints()) != 2 || up.GetCheckpoints()[0].GetId() != "c2" || up.GetCheckpoints()[0].GetFiles() != 3 ||
		up.GetCheckpoints()[1].GetId() == "../bad" {
		t.Fatalf("checkpoints = %+v", up.GetCheckpoints())
	}
	sha := strings.Repeat("ab", 32)
	pm, _ := json.Marshal(map[string]any{"kind": "plan_file", "sha256": sha})
	tr.observe(sessionsync.Entry{Type: "plan_file", Meta: pm})
	if tr.planSHA != sha {
		t.Fatalf("plan sha = %q", tr.planSHA)
	}
	kind, payload := structuredAnswer("relay_review", &nodev1.Answer{QuestionId: "a1", Decision: "edit", Text: "better note"})
	if kind != "relay_review" || !strings.Contains(string(payload), `"text":"better note"`) || !strings.Contains(string(payload), `"decision":"edit"`) {
		t.Fatalf("answer = %s %s", kind, payload)
	}
}
