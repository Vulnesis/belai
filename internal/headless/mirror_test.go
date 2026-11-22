package headless

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/session"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// fakeKeleustesSessions is the Sessions side of a Keleustes server: it keeps
// the lines it is sent and counts inbox polls.
type fakeKeleustesSessions struct {
	mu      sync.Mutex
	meta    []sessionsync.SessionMeta
	entries []sessionsync.Entry
	ended   bool
	polls   int
	closed  bool
}

func (f *fakeKeleustesSessions) PutHost(context.Context, string, sessionsync.Host) error { return nil }
func (f *fakeKeleustesSessions) PutSessionControls(_ context.Context, _ string, m sessionsync.SessionMeta) (int64, sessionsync.Controls, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.meta = append(f.meta, m)
	return int64(len(f.entries)) - 1, sessionsync.Controls{}, nil
}
func (f *fakeKeleustesSessions) HeartbeatControls(context.Context, string) (sessionsync.Controls, error) {
	return sessionsync.Controls{}, nil
}
func (f *fakeKeleustesSessions) PostEntries(_ context.Context, _ string, es []sessionsync.Entry) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range es {
		if e.Seq == int64(len(f.entries)) {
			f.entries = append(f.entries, e)
		}
	}
	return int64(len(f.entries)) - 1, nil
}
func (f *fakeKeleustesSessions) EndWith(context.Context, string, sessionsync.EndInfo) error {
	f.mu.Lock()
	f.ended = true
	f.mu.Unlock()
	return nil
}
func (f *fakeKeleustesSessions) InboxBatchA2A(ctx context.Context, _, _ string, wait time.Duration, _ int64) (sessionsync.Inbox, error) {
	f.mu.Lock()
	f.polls++
	f.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-time.After(wait):
	}
	return sessionsync.Inbox{}, nil
}
func (f *fakeKeleustesSessions) Ack(context.Context, string, string, string, string) error {
	return nil
}
func (f *fakeKeleustesSessions) AckAnswer(context.Context, string, string, string, string) error {
	return nil
}
func (f *fakeKeleustesSessions) AckCommand(context.Context, string, string, string, json.RawMessage) error {
	return nil
}
func (f *fakeKeleustesSessions) DraftResult(context.Context, string, string, string, any) error {
	return nil
}

func useFakeKeleustes(t *testing.T) *fakeKeleustesSessions {
	t.Helper()
	srv := &fakeKeleustesSessions{}
	prev := mirrorBackend
	mirrorBackend = func(string) (sessionsync.Backend, func() error, error) {
		return srv, func() error { srv.mu.Lock(); srv.closed = true; srv.mu.Unlock(); return nil }, nil
	}
	t.Cleanup(func() { mirrorBackend = prev })
	return srv
}

// #37: a headless run's transcript reaches the joined Keleustes server, line
// for line, and the session ends there with the run.
func TestHeadlessMirrorUploadsTranscript(t *testing.T) {
	t.Setenv("BELAI_HOME", t.TempDir())
	srv := useFakeKeleustes(t)
	workdir := t.TempDir()
	id := session.MustID()
	store, err := session.NewStore()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := session.KeyFor(workdir)
	w, err := session.NewWriter(store, key, id, session.Meta{Cwd: workdir})
	if err != nil {
		t.Fatal(err)
	}
	m := StartMirror(config.Settings{}, workdir, id, "openai", "gpt-x", "")
	if m == nil {
		t.Fatal("no mirror with sync on and a Keleustes profile")
	}
	w.User("hello")
	m.Touch()
	w.Assistant("hi there", nil, nil)
	m.Close()

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if !srv.ended || !srv.closed {
		t.Errorf("ended %v closed %v", srv.ended, srv.closed)
	}
	if len(srv.meta) == 0 || srv.meta[0].Model != "gpt-x" {
		t.Errorf("meta = %+v", srv.meta)
	}
	var user, assistant bool
	for _, e := range srv.entries {
		user = user || (e.Role == "user" && e.Content == "hello")
		assistant = assistant || (e.Role == "assistant" && e.Content == "hi there")
	}
	if !user || !assistant {
		t.Errorf("entries = %+v", srv.entries)
	}
	if srv.polls != 0 {
		t.Errorf("the upload-only mirror polled the inbox %d times", srv.polls)
	}
}

func TestHeadlessMirrorOffWithSyncOff(t *testing.T) {
	t.Setenv("BELAI_HOME", t.TempDir())
	useFakeKeleustes(t)
	off := false
	if m := StartMirror(config.Settings{Sync: &config.SyncSettings{Enabled: &off}}, t.TempDir(), session.MustID(), "p", "m", ""); m != nil {
		t.Error("a mirror started with sync.enabled false")
	}
	var m *Mirror
	m.Touch()
	m.Close()
}
