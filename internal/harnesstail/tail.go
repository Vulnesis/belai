// Package harnesstail follows a third-party harness's own transcript (its
// native JSONL, JSON document, SQLite database or Markdown history) while
// the harness runs, and turns each new native record into an event for the
// session mirror (docs/harness-sessions.md). Parsing is agentstore's: the
// same pick functions serve SearchSessions and this tail, so a format fix
// covers both.
//
// Files are opened read-only, never written, and a path whose real location
// leaves the store's root (a symlink out) is refused. Record text is the
// harness's model output: untrusted, passed on as data only.
package harnesstail

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vulnetix/belai/internal/agentstore"
	"github.com/vulnetix/belai/internal/harness"
)

// Dialects this package follows beyond agentstore's JSONL ones.
const (
	DialectGemini = "json-gemini"
	DialectAider  = "md-aider"
)

// Limits.
const (
	MaxLine     = 16 << 20
	MaxDocument = 32 << 20
	MaxText     = 64 << 10
	// LocateWait bounds the search for a session started without a preset id.
	LocateWait = 60 * time.Second
)

// Event is one native record and where it sits in the native store: a byte
// span for JSONL, a record index (Len 0) for the others.
type Event struct {
	agentstore.Record
	Off, Len int64
}

// Next is the offset to resume from after e.
func (e Event) Next() int64 {
	if e.Len > 0 {
		return e.Off + e.Len
	}
	return e.Off + 1
}

// Source is a located native session.
type Source struct {
	Dialect   string
	Path      string
	SessionID string
	// Root is the directory the path must stay under.
	Root string
}

// Spec says where to look for one session.
type Spec struct {
	Transcript harness.Transcript
	Home, Cwd  string
	NativeID   string
	// Since is the spawn time: a located file or row must be newer.
	Since time.Time
	// SQLite is the sqlite3 binary for the SQLite dialects.
	SQLite string
	// Poll overrides the 250 ms locate and follow poll (tests).
	Poll time.Duration
}

func (s Spec) poll() time.Duration {
	if s.Poll > 0 {
		return s.Poll
	}
	return 250 * time.Millisecond
}

// Expand fills a transcript path's placeholders and resolves "~/" and
// "{cwd}/" against home and cwd.
func Expand(pattern, home, cwd, nativeID string) string {
	// Harnesses name their project stores after the real path of the cwd.
	real := cwd
	if r, err := filepath.EvalSymlinks(cwd); err == nil {
		real = r
	}
	p := strings.NewReplacer("{native_id}", nativeID, "{cwd_slug}", harness.CwdSlug(real)).Replace(pattern)
	if rest, ok := strings.CutPrefix(p, "{cwd}/"); ok {
		return filepath.Join(cwd, rest)
	}
	return harness.ExpandHarness(home, p, os.Getenv)
}

// root is the static directory prefix of an expanded pattern.
func root(p string) string {
	i := strings.IndexAny(p, "*?[")
	if i < 0 {
		return filepath.Dir(p)
	}
	return filepath.Dir(p[:i])
}

// ErrNotFound means no native session matched within LocateWait.
var ErrNotFound = errors.New("harnesstail: native session not found")

// Locate finds the session's native store. With a preset native id the path
// is known and Locate waits for it to appear; otherwise it applies the
// profile's locate rule. ctx bounds the wait (LocateWait at most).
func Locate(ctx context.Context, s Spec) (Source, error) {
	ctx, cancel := context.WithTimeout(ctx, LocateWait)
	defer cancel()
	pat := Expand(s.Transcript.Path, s.Home, s.Cwd, s.NativeID)
	src := Source{Dialect: s.Transcript.Dialect, Root: root(pat), SessionID: s.NativeID}
	for {
		if found, ok := locateOnce(s, pat, src); ok {
			if err := checkRoot(found.Path, found.Root); err != nil {
				return Source{}, err
			}
			return found, nil
		}
		select {
		case <-ctx.Done():
			return Source{}, ErrNotFound
		case <-time.After(s.poll()):
		}
	}
}

func locateOnce(s Spec, pat string, src Source) (Source, bool) {
	switch s.Transcript.Locate {
	case "sqlite-row":
		if _, err := os.Stat(pat); err != nil || s.SQLite == "" {
			return src, false
		}
		srcs, err := agentstore.SQLiteSessions(s.SQLite, agentstore.Format(src.Dialect), pat)
		if err != nil {
			return src, false
		}
		sort.SliceStable(srcs, func(i, j int) bool { return srcs[i].ModTime.After(srcs[j].ModTime) })
		for _, c := range srcs {
			if sameDir(c.Project, s.Cwd) && !c.ModTime.Before(s.Since.Add(-2*time.Second)) {
				src.Path, src.SessionID = pat, c.SessionID
				return src, true
			}
		}
		return src, false
	case "new-file":
		matches, _ := filepath.Glob(pat)
		sort.Slice(matches, func(i, j int) bool { return mtime(matches[i]).After(mtime(matches[j])) })
		for _, m := range matches {
			if mtime(m).Before(s.Since.Add(-time.Second)) {
				break
			}
			if id, ok := matchesCwd(src.Dialect, m, s.Cwd); ok {
				src.Path, src.SessionID = m, id
				return src, true
			}
		}
		return src, false
	}
	matches, _ := filepath.Glob(pat)
	if len(matches) == 0 {
		return src, false
	}
	src.Path = matches[0]
	return src, true
}

func mtime(p string) time.Time {
	fi, err := os.Stat(p)
	if err != nil {
		return time.Time{}
	}
	return fi.ModTime()
}

// matchesCwd reads a candidate's recorded directory: Codex's session_meta
// line, or Gemini's project hash directory (sha256 of the cwd).
func matchesCwd(dialect, path, cwd string) (string, bool) {
	switch dialect {
	case string(agentstore.FormatJSONLCodex):
		f, err := os.Open(path)
		if err != nil {
			return "", false
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), MaxLine)
		if !sc.Scan() {
			return "", false
		}
		r, ok := agentstore.PickCodex(sc.Bytes())
		return r.SessionID, ok && r.NativeType == "session_meta" && sameDir(r.Cwd, cwd) && r.SessionID != ""
	case DialectGemini:
		base := filepath.Base(filepath.Dir(filepath.Dir(path)))
		for _, c := range []string{cwd, realDir(cwd)} {
			if sum := sha256.Sum256([]byte(c)); base == hex.EncodeToString(sum[:]) {
				return "", true
			}
		}
		return "", false
	}
	return "", true
}

// checkRoot refuses a store whose real path is outside its root.
func checkRoot(path, rootDir string) error {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	realRoot, err := filepath.EvalSymlinks(rootDir)
	if err != nil {
		return err
	}
	if rel, err := filepath.Rel(realRoot, real); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("harnesstail: %s leaves %s", path, rootDir)
	}
	return nil
}

// Follow emits the records of src from off onward and keeps following until
// ctx ends. off is a byte offset for JSONL and a record count otherwise; an
// Event's Next is the value to pass after a restart.
func Follow(ctx context.Context, src Source, off int64, sqlite string, poll time.Duration, emit func(Event)) error {
	if poll <= 0 {
		poll = 300 * time.Millisecond
	}
	if err := checkRoot(src.Path, src.Root); err != nil {
		return err
	}
	switch src.Dialect {
	case string(agentstore.FormatJSONLClaude), string(agentstore.FormatJSONLCodex), string(agentstore.FormatJSONLPi):
		return followJSONL(ctx, src, off, poll, emit)
	case DialectGemini:
		return followDoc(ctx, src, off, poll, emit, func(b []byte) ([]agentstore.Record, error) { return agentstore.GeminiRecords(b) }, false)
	case DialectAider:
		return followDoc(ctx, src, off, poll, emit, func(b []byte) ([]agentstore.Record, error) { return agentstore.AiderRecords(string(b)), nil }, true)
	case string(agentstore.FormatSQLiteGoose), string(agentstore.FormatSQLiteOpenCode):
		return followSQLite(ctx, src, off, sqlite, max(poll, time.Second), emit)
	}
	return fmt.Errorf("harnesstail: no tailer for %q", src.Dialect)
}

func capText(r *agentstore.Record) {
	if len(r.Text) > MaxText {
		cut := MaxText
		for cut > 0 && (r.Text[cut]&0xC0) == 0x80 {
			cut--
		}
		r.Text = r.Text[:cut] + "…"
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// followJSONL tails an append-only file by byte offset. A torn last line is
// held until its newline; a file that shrinks below off (truncated or
// replaced) is read again from the start.
func followJSONL(ctx context.Context, src Source, off int64, poll time.Duration, emit func(Event)) error {
	format := agentstore.Format(src.Dialect)
	var pending []byte
	for {
		fi, err := os.Stat(src.Path)
		if err == nil && fi.Size() < off+int64(len(pending)) {
			off, pending = 0, nil
		}
		if err == nil && fi.Size() > off+int64(len(pending)) {
			f, err := os.OpenFile(src.Path, os.O_RDONLY, 0)
			if err == nil {
				_, err = f.Seek(off+int64(len(pending)), io.SeekStart)
				if err == nil {
					chunk, _ := io.ReadAll(io.LimitReader(f, MaxLine))
					pending = append(pending, chunk...)
				}
				f.Close()
			}
			for {
				nl := bytes.IndexByte(pending, '\n')
				if nl < 0 {
					if len(pending) >= MaxLine {
						off, pending = off+int64(len(pending)), nil
					}
					break
				}
				line := pending[:nl]
				n := int64(nl + 1)
				if t := bytes.TrimSpace(line); len(t) > 0 {
					if r, ok := agentstore.PickLine(format, t); ok {
						capText(&r)
						emit(Event{Record: r, Off: off, Len: n})
					}
				}
				off += n
				pending = pending[nl+1:]
			}
		}
		if !sleep(ctx, poll) {
			return nil
		}
	}
}

// followDoc re-reads a whole document when it changes and emits records past
// the count already emitted. With holdLast, the last record is emitted only
// once the file has been still for two polls (aider's answer grows in place).
func followDoc(ctx context.Context, src Source, off int64, poll time.Duration, emit func(Event), parse func([]byte) ([]agentstore.Record, error), holdLast bool) error {
	var lastMod time.Time
	var lastSize int64 = -1
	still := 0
	for {
		fi, err := os.Stat(src.Path)
		if err == nil {
			changed := !fi.ModTime().Equal(lastMod) || fi.Size() != lastSize
			if changed {
				still = 0
			} else {
				still++
			}
			if (changed || (holdLast && still == 2)) && fi.Size() <= MaxDocument {
				lastMod, lastSize = fi.ModTime(), fi.Size()
				if data, err := os.ReadFile(src.Path); err == nil {
					if recs, err := parse(data); err == nil {
						n := int64(len(recs))
						if holdLast && still < 2 && n > 0 {
							n--
						}
						for i := off; i < n; i++ {
							r := recs[i]
							capText(&r)
							emit(Event{Record: r, Off: i})
						}
						off = max(off, n)
					}
				}
			}
		}
		if !sleep(ctx, poll) {
			return nil
		}
	}
}

// followSQLite re-reads the session's turns when the database or its WAL
// changes and emits turns past the count already emitted.
func followSQLite(ctx context.Context, src Source, off int64, sqlite string, poll time.Duration, emit func(Event)) error {
	if sqlite == "" {
		return errors.New("harnesstail: sqlite3 is not on PATH")
	}
	as := agentstore.Source{Format: agentstore.Format(src.Dialect), Path: src.Path, SessionID: src.SessionID}
	var last time.Time
	for {
		m := mtime(src.Path)
		if w := mtime(src.Path + "-wal"); w.After(m) {
			m = w
		}
		if !m.Equal(last) {
			last = m
			if !sleep(ctx, 250*time.Millisecond) {
				return nil
			}
			if turns, err := agentstore.SQLiteTurns(sqlite, as); err == nil {
				for i := off; i < int64(len(turns)); i++ {
					t := turns[i]
					r := agentstore.Record{Role: t.Role, Text: t.Text, At: t.At, NativeType: "message", SessionID: src.SessionID}
					if r.Role != "user" && r.Role != "assistant" {
						r.Role = "system"
					}
					capText(&r)
					emit(Event{Record: r, Off: i})
				}
				off = max(off, int64(len(turns)))
			}
		}
		if !sleep(ctx, poll) {
			return nil
		}
	}
}

func realDir(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// sameDir compares two directories as written and by real path.
func sameDir(a, b string) bool {
	return a != "" && (filepath.Clean(a) == filepath.Clean(b) || realDir(a) == realDir(b))
}
