package harnesstail

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/vulnetix/belai/internal/harness"
)

type sink struct {
	mu sync.Mutex
	ev []Event
}

func (s *sink) emit(e Event) { s.mu.Lock(); s.ev = append(s.ev, e); s.mu.Unlock() }
func (s *sink) all() []Event { s.mu.Lock(); defer s.mu.Unlock(); return append([]Event(nil), s.ev...) }

func (s *sink) wait(t *testing.T, n int) []Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ev := s.all(); len(ev) >= n {
			return ev
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("want %d events, got %+v", n, s.all())
	return nil
}

func appendTo(t *testing.T, p, s string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

const (
	u1 = `{"type":"user","uuid":"a","message":{"role":"user","content":"hi"}}` + "\n"
	a1 = `{"type":"assistant","uuid":"b","message":{"role":"assistant","content":[{"type":"text","text":"yo"}],"stop_reason":"end_turn"}}` + "\n"
)

func follow(t *testing.T, src Source, off int64) (*sink, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s := &sink{}
	go func() { _ = Follow(ctx, src, off, "", 20*time.Millisecond, s.emit) }()
	return s, cancel
}

func TestFollowJSONLAppendTornAndRestart(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.jsonl")
	appendTo(t, p, u1)
	src := Source{Dialect: "jsonl-claude", Path: p, Root: dir}
	s, cancel := follow(t, src, 0)
	s.wait(t, 1)
	appendTo(t, p, a1[:30])
	time.Sleep(100 * time.Millisecond)
	if len(s.all()) != 1 {
		t.Fatal("a torn line was emitted")
	}
	appendTo(t, p, a1[30:])
	ev := s.wait(t, 2)
	cancel()
	if ev[1].Role != "assistant" || !ev[1].TurnEnd || ev[1].Off != int64(len(u1)) {
		t.Fatalf("%+v", ev[1])
	}
	// A restart from the first event's Next yields the same second event.
	s2, cancel2 := follow(t, src, ev[0].Next())
	defer cancel2()
	ev2 := s2.wait(t, 1)
	if ev2[0].Off != ev[1].Off || ev2[0].NativeID != "b" {
		t.Fatalf("restart: %+v", ev2[0])
	}
}

func TestFollowJSONLTruncation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "s.jsonl")
	appendTo(t, p, u1+a1)
	s, cancel := follow(t, Source{Dialect: "jsonl-claude", Path: p, Root: dir}, 0)
	defer cancel()
	s.wait(t, 2)
	if err := os.WriteFile(p, []byte(u1), 0o600); err != nil {
		t.Fatal(err)
	}
	ev := s.wait(t, 3)
	if ev[2].Off != 0 {
		t.Fatalf("after truncation: %+v", ev[2])
	}
}

func TestFollowGeminiRewrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "session-1.json")
	write := func(s string) {
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"messages":[{"id":"1","type":"user","content":"hi"}]}`)
	s, cancel := follow(t, Source{Dialect: DialectGemini, Path: p, Root: dir}, 0)
	defer cancel()
	s.wait(t, 1)
	time.Sleep(30 * time.Millisecond)
	write(`{"messages":[{"id":"1","type":"user","content":"hi"},{"id":"2","type":"gemini","content":"yo"}]}`)
	ev := s.wait(t, 2)
	if len(ev) != 2 || ev[1].Off != 1 || ev[1].Role != "assistant" {
		t.Fatalf("%+v", ev)
	}
}

func TestSymlinkOutOfRootRefused(t *testing.T) {
	dir, other := t.TempDir(), t.TempDir()
	target := filepath.Join(other, "secret.jsonl")
	appendTo(t, target, u1)
	link := filepath.Join(dir, "s.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	err := Follow(context.Background(), Source{Dialect: "jsonl-claude", Path: link, Root: dir}, 0, "", time.Millisecond, func(Event) {})
	if err == nil {
		t.Fatal("followed a symlink out of the root")
	}
}

func TestLocatePresetAndCodexNewFile(t *testing.T) {
	home := t.TempDir()
	cwd := "/work/x"
	slugDir := filepath.Join(home, ".claude", "projects", harness.CwdSlug(cwd))
	if err := os.MkdirAll(slugDir, 0o700); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		appendTo(t, filepath.Join(slugDir, "id-1.jsonl"), u1)
	}()
	src, err := Locate(context.Background(), Spec{Transcript: harness.Transcript{Dialect: "jsonl-claude", Path: "~/.claude/projects/{cwd_slug}/{native_id}.jsonl"},
		Home: home, Cwd: cwd, NativeID: "id-1", Poll: 20 * time.Millisecond})
	if err != nil || filepath.Base(src.Path) != "id-1.jsonl" {
		t.Fatalf("%+v %v", src, err)
	}

	day := filepath.Join(home, ".codex", "sessions", "2026", "11", "21")
	if err := os.MkdirAll(day, 0o700); err != nil {
		t.Fatal(err)
	}
	since := time.Now()
	appendTo(t, filepath.Join(day, "rollout-a.jsonl"), `{"type":"session_meta","payload":{"id":"other","cwd":"/elsewhere"}}`+"\n")
	appendTo(t, filepath.Join(day, "rollout-b.jsonl"), `{"type":"session_meta","payload":{"id":"mine","cwd":"/work/x"}}`+"\n")
	src, err = Locate(context.Background(), Spec{Transcript: harness.Transcript{Dialect: "jsonl-codex", Path: "~/.codex/sessions/*/*/*/rollout-*.jsonl", Locate: "new-file"},
		Home: home, Cwd: cwd, Since: since, Poll: 20 * time.Millisecond})
	if err != nil || src.SessionID != "mine" {
		t.Fatalf("%+v %v", src, err)
	}
}

func TestLocateGeminiHashDir(t *testing.T) {
	sum := sha256.Sum256([]byte("/w"))
	if _, ok := matchesCwd(DialectGemini, filepath.Join("/h/.gemini/tmp", hex.EncodeToString(sum[:]), "chats", "session-1.json"), "/w"); !ok {
		t.Fatal("hash dir did not match")
	}
	if _, ok := matchesCwd(DialectGemini, "/h/.gemini/tmp/abc/chats/session-1.json", "/w"); ok {
		t.Fatal("wrong dir matched")
	}
}

func TestFollowSQLiteOpenCode(t *testing.T) {
	sqlite, err := exec.LookPath("sqlite3")
	if err != nil {
		t.Skip("sqlite3 not on PATH")
	}
	db := filepath.Join(t.TempDir(), "opencode.db")
	run := func(q string) {
		t.Helper()
		if out, err := exec.Command(sqlite, db, q).CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
	}
	run(`CREATE TABLE session(id TEXT, directory TEXT, time_created INTEGER);
	CREATE TABLE message(id TEXT, session_id TEXT, time_created INTEGER, data TEXT);
	CREATE TABLE part(id TEXT, message_id TEXT, session_id TEXT, time_created INTEGER, data TEXT);
	INSERT INTO session VALUES('ses1','/w',` + strconv.FormatInt(time.Now().UnixMilli(), 10) + `);
	INSERT INTO message VALUES('m1','ses1',1,'{"id":"m1","role":"user"}');
	INSERT INTO part VALUES('p1','m1','ses1',1,'{"type":"text","text":"hi"}');`)
	src, err := Locate(context.Background(), Spec{Transcript: harness.Transcript{Dialect: "sqlite-opencode", Path: db, Locate: "sqlite-row"},
		Cwd: "/w", Since: time.Now().Add(-time.Minute), SQLite: sqlite, Poll: 20 * time.Millisecond})
	if err != nil || src.SessionID != "ses1" {
		t.Fatalf("%+v %v", src, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &sink{}
	go func() { _ = Follow(ctx, src, 0, sqlite, time.Millisecond, s.emit) }()
	s.wait(t, 1)
	time.Sleep(1100 * time.Millisecond)
	run(`INSERT INTO message VALUES('m2','ses1',2,'{"id":"m2","role":"assistant"}');
	INSERT INTO part VALUES('p2','m2','ses1',2,'{"type":"text","text":"yo"}');`)
	ev := s.wait(t, 2)
	if ev[1].Role != "assistant" || ev[1].Text != "yo" {
		t.Fatalf("%+v", ev)
	}
}

func TestExpandFollowsConfigDirsAndRealPath(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skip(err)
	}
	t.Setenv("CLAUDE_CONFIG_DIR", "/cfg/claude")
	t.Setenv("CODEX_HOME", "/cfg/codex")
	got := Expand("~/.claude/projects/{cwd_slug}/x.jsonl", "/home/u", link, "x")
	if want := filepath.Join("/cfg/claude/projects", harness.CwdSlug(real), "x.jsonl"); got != want {
		t.Fatalf("%s != %s", got, want)
	}
	if got := Expand("~/.codex/sessions/*.jsonl", "/home/u", "/w", ""); got != "/cfg/codex/sessions/*.jsonl" {
		t.Fatal(got)
	}
	if !sameDir(link, real) {
		t.Fatal("symlinked cwd not the same dir")
	}
}
