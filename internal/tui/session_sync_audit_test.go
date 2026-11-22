package tui

import (
	"context"
	"sync"
	"testing"

	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// fakeAuditServer is a Keleustes server's audit side: it keeps what it is sent.
type fakeAuditServer struct {
	mu     sync.Mutex
	events []audit.Event
	closed bool
}

func (f *fakeAuditServer) PutHost(context.Context, string, sessionsync.Host) error { return nil }

func (f *fakeAuditServer) PutAuditStream(context.Context, string, string) (sessionsync.AuditCursor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	last := int64(-1)
	if n := len(f.events); n > 0 {
		last = f.events[n-1].Seq
	}
	return sessionsync.AuditCursor{LastSeq: last, ChainOK: true}, nil
}

func (f *fakeAuditServer) PostAudit(_ context.Context, _, _ string, evs []audit.Event) (sessionsync.AuditCursor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	last := int64(-1)
	for _, e := range evs {
		if n := len(f.events); n == 0 || e.Seq > f.events[n-1].Seq {
			f.events = append(f.events, e)
		}
		if e.Seq > last {
			last = e.Seq
		}
	}
	return sessionsync.AuditCursor{LastSeq: last, ChainOK: true}, nil
}

func (f *fakeAuditServer) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

// #13: a TUI joined to Keleustes uploads its audit stream there, and what
// arrives verifies as one hash chain.
func TestKeleustesTUIUploadsAudit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("BELAI_HOME", home)
	srv := &fakeAuditServer{}
	prev := keleustesAudit
	keleustesAudit = func(string) (keleustesAuditSink, error) { return srv, nil }
	t.Cleanup(func() { keleustesAudit = prev; audit.SetDefault(nil) })

	a := New(Options{Workdir: t.TempDir()})
	a.startKeleustesStreams(home, "host-1")
	if a.audit == nil || !audit.Enabled() {
		t.Fatal("no audit stream started for the Keleustes session")
	}
	audit.Emit(audit.Fact{Kind: audit.HostDispatch, ActorKind: audit.ActorHuman, SessionID: "s-1",
		Data: map[string]string{"dispatch": "session", "status": "ok"}})
	audit.Emit(audit.Fact{Kind: audit.HostDispatch, ActorKind: audit.ActorHuman, SessionID: "s-1",
		Data: map[string]string{"dispatch": "stop", "status": "ok"}})
	a.factoryStop()

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if !srv.closed {
		t.Error("the audit connection was not closed with the session")
	}
	if a.audit != nil || audit.Enabled() {
		t.Error("the audit stream outlived the session")
	}
	if len(srv.events) < 2 {
		t.Fatalf("server got %d events", len(srv.events))
	}
	if bad := audit.Verify(srv.events); bad != -1 {
		t.Fatalf("uploaded chain breaks at seq %d", bad)
	}
	n := 0
	for _, e := range srv.events {
		if e.Kind == string(audit.HostDispatch) && e.SessionID == "s-1" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("uploaded %d session facts, want 2: %+v", n, srv.events)
	}
}
