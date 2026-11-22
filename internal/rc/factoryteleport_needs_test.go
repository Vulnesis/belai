package rc

import (
	"reflect"
	"strings"
	"testing"

	"github.com/vulnetix/belai/internal/agentprofile"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/session"
	"github.com/vulnetix/belai/internal/sessionsync"
	"github.com/vulnetix/belai/internal/teleport"
)

// A teleport names the session's own profile and the crews that list it;
// a built-in profile needs nothing.
func TestTeleportNeedsNameTheProfileAndItsCrews(t *testing.T) {
	crews := []agentprofile.Crew{
		{Name: "ops", Members: []agentprofile.Member{{Profile: "log"}}},
		{Name: "other", Members: []agentprofile.Member{{Profile: "x"}}},
		{Name: "ops", Members: []agentprofile.Member{{Profile: "log"}}},
	}
	got := needsFor("log", crews)
	want := []factorylink.TeleportNeed{{Kind: "profile", Name: "log"}, {Kind: "crew", Name: "ops"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("needs = %+v", got)
	}
	if n := needsFor("belai:triage-vulns", crews); n != nil {
		t.Errorf("a built-in needs %+v", n)
	}
	if n := needsFor("", crews); n != nil {
		t.Errorf("no profile needs %+v", n)
	}
	b := teleport.Bundle{Entries: []sessionsync.Entry{
		{Type: session.EntryTypeSessionMeta, Content: `{"schema":2,"activeProfile":"old"}`},
		{Type: "user", Content: "hi"},
		{Type: session.EntryTypeSessionMeta, Content: `{"schema":2,"activeProfile":"log"}`},
	}}
	if n := TeleportNeeds(b); len(n) == 0 || n[0] != (factorylink.TeleportNeed{Kind: "profile", Name: "log"}) {
		t.Errorf("bundle needs = %+v", n)
	}
}

// A session a third-party harness ran never teleports: the job is refused
// with the reason, nothing is uploaded.
func TestKeleustesTeleportJobRefusesAHarnessSession(t *testing.T) {
	dir, store := tpOrigin(t)
	const hs = "77777777-2222-4333-8444-555555555555"
	key, err := session.KeyFor(dir)
	if err != nil {
		t.Fatal(err)
	}
	meta := session.Meta{Schema: session.SchemaVersion, Cwd: dir}.ToEntry("")
	line := session.Entry{ID: "h-1", ParentID: meta.ID, Type: "assistant", Role: "assistant", Content: "ok", Timestamp: 2,
		Meta: map[string]any{"harness": "claude-code"}}
	if err := store.Import(key, hs, []session.Entry{meta, line}); err != nil {
		t.Fatal(err)
	}
	ff := newFake()
	ff.jobs = []*nodev1.Job{teleportJobFrame("t1",
		`{"task":"teleport_upload","teleportId":"`+tpID+`","sessionId":"`+hs+`","toNode":"node-2"}`)}
	got, _ := runFactoryDaemon(t, ff, Options{
		Dirs: []Dir{{Path: dir, Name: "app", Source: SourceArg}}, Sessions: store, TeleportGit: tcAllowFile,
	})
	if r := got["t1"]; r.GetStatus() != jobRefused || !strings.Contains(r.GetError(), "harness session cannot be teleported") {
		t.Fatalf("t1 = %+v", r)
	}
	ff.mu.Lock()
	defer ff.mu.Unlock()
	if len(ff.uploads) != 0 {
		t.Errorf("a harness session was uploaded")
	}
}
