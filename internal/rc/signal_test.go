package rc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vulnetix/belai/internal/sessionctl"
	"github.com/vulnetix/belai/internal/sessionsync"
	"github.com/vulnetix/belai/internal/turnlog"
)

// signalSession runs a session with controls whose turns run until their
// context ends, and returns its pieces and the channel RunSession's result
// arrives on.
func signalSession(t *testing.T, controls bool) (*ctxRunner, *fakeMirror, chan sessionsync.RemoteCommand, *cmdAcks, chan error) {
	t.Helper()
	r := &ctxRunner{s: &steps{}, gate: make(chan struct{}), started: make(chan string, 8)}
	m := &fakeMirror{prompts: make(chan sessionsync.RemotePrompt, 4)}
	cmds := make(chan sessionsync.RemoteCommand, 4)
	acks := &cmdAcks{}
	o := SessionOptions{Log: turnlog.New(nil), Mirror: m, Prompt: "first", Idle: time.Hour,
		Commands: cmds, AckCommand: acks.ack}
	if controls {
		ctl, err := NewController(testState(), sessionctl.Env{}, func(sessionctl.State) (Runner, error) { return r, nil })
		if err != nil {
			t.Fatal(err)
		}
		o.Controls = ctl
	} else {
		// No controls, but branch switches: the session reads commands.
		o.Agent, o.Checkout = r, fakeCheckout(r.s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunSession(ctx, o) }()
	t.Cleanup(cancel)
	return r, m, cmds, acks, done
}

// "interrupt" stops the running turn and the session waits for the next
// prompt; "stop" ends the session.
func TestSignalsInterruptAndStop(t *testing.T) {
	r, m, cmds, acks, done := signalSession(t, true)
	<-r.started
	cmds <- sessionsync.RemoteCommand{ID: "i1", Signal: sessionsync.SignalInterrupt}
	eventuallyRC(t, "the interrupt ack", func() bool { return strings.Contains(acks.list(), "i1:accepted") })
	m.prompts <- sessionsync.RemotePrompt{ID: "p1", Content: "second"}
	if got := <-r.started; got != "second" {
		t.Fatalf("after the interrupt the session ran %q", got)
	}
	cmds <- sessionsync.RemoteCommand{ID: "s1", Signal: sessionsync.SignalStop}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("session ended with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stop did not end the session")
	}
	if !strings.Contains(acks.list(), "s1:accepted") {
		t.Errorf("acks = %s", acks.list())
	}
}

// Between turns a stop ends the session at once.
func TestSignalStopWhileIdle(t *testing.T) {
	r, _, cmds, acks, done := signalSession(t, true)
	<-r.started
	close(r.gate) // the first turn finishes
	time.Sleep(50 * time.Millisecond)
	cmds <- sessionsync.RemoteCommand{ID: "s1", Signal: sessionsync.SignalStop}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("stop did not end the idle session")
	}
	if !strings.Contains(acks.list(), "s1:accepted") {
		t.Errorf("acks = %s", acks.list())
	}
}

// A session without web controls (one that takes only branch switches)
// refuses signals and keeps its turn.
func TestSignalsNeedControls(t *testing.T) {
	r, _, cmds, acks, done := signalSession(t, false)
	<-r.started
	cmds <- sessionsync.RemoteCommand{ID: "s1", Signal: sessionsync.SignalStop}
	eventuallyRC(t, "the refusal", func() bool { return strings.Contains(acks.list(), "s1:refused") })
	select {
	case <-done:
		t.Fatal("a session without controls was stopped")
	case <-time.After(100 * time.Millisecond):
	}
}
