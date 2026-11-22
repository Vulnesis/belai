package e2e

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sessionFile finds a session's transcript under a belai home.
func sessionFile(t *testing.T, home, sid string) string {
	t.Helper()
	var found string
	_ = filepath.WalkDir(home, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && d.Name() == sid+".jsonl" {
			found = p
		}
		return nil
	})
	if found == "" {
		t.Fatalf("no transcript for session %s under %s", sid, home)
	}
	return found
}

// transcriptEntry is one line of a belai session file.
type transcriptEntry struct {
	ID      string         `json:"id"`
	Type    string         `json:"type"`
	Content string         `json:"content"`
	Meta    map[string]any `json:"meta"`
}

func readTranscript(t *testing.T, path string) []transcriptEntry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []transcriptEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		var e transcriptEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

// resumeOut starts a resume or fork from Keleustes and returns the new
// session id.
func (k *keleustes) resume(args ...string) string {
	k.t.Helper()
	out := k.kel(append([]string{"sessions", "resume"}, args...)...)
	for _, line := range strings.Split(out, "\n") {
		if s, ok := strings.CutPrefix(line, "session "); ok {
			return strings.TrimSpace(s)
		}
	}
	k.t.Fatalf("resume did not start a session:\n%s", out)
	return ""
}

// TestKeleustesResumeForkAndActions is the real-binary check for
// belai-counterparts #45 and #46: a session dispatched from Keleustes takes a
// console action (rename) over the inbox and reports it back on its upsert;
// after it stops, Keleustes resumes it (a new session on the host that
// continues the stored conversation) and forks it at an entry, and belai
// starts `rc-session -resume ID [-fork ENTRY]` for each, copying the
// conversation into the new session's transcript.
func TestKeleustesResumeForkAndActions(t *testing.T) {
	k := startKeleustes(t)
	model := newKeleustesModel(t)
	h := startRC(t, k, "e2e-resume", model.URL)

	sid := k.dispatch(h.label, h.project, "say hello")
	waitTranscript(t, k.kel, sid, 90*time.Second, func(tr string) bool {
		return strings.Contains(tr, "say hello") && strings.Contains(tr, "mock reply")
	})

	// Console action round trip: rename is listed, queued, applied by the
	// host and comes back as the session's title.
	var accepts struct {
		Accepts struct {
			ControlsAllowed []string `json:"controlsAllowed"`
		} `json:"accepts"`
	}
	_ = json.Unmarshal([]byte(k.kel("sessions", "show", sid)), &accepts)
	if !contains(accepts.Accepts.ControlsAllowed, "rename") && !strings.Contains(k.kel("sessions", "show", sid), `"rename"`) {
		t.Errorf("the session does not list rename: %s", k.kel("sessions", "show", sid))
	}
	k.kel("sessions", "command", sid, "rename", "Renamed", "by", "console")
	deadline := time.Now().Add(60 * time.Second)
	for {
		var v struct {
			Title string `json:"title"`
		}
		_ = json.Unmarshal([]byte(k.kel("sessions", "show", sid)), &v)
		if v.Title == "Renamed by console" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the rename never came back; show:\n%s\ntranscript:\n%s", k.kel("sessions", "show", sid), tail(k.kel("sessions", "transcript", sid), 2000))
		}
		time.Sleep(500 * time.Millisecond)
	}
	// An action the session does not take is refused by Keleustes.
	if out, err := k.try("sessions", "command", sid, "rewind"); err == nil {
		t.Errorf("rewind without a checkpoint id was queued: %s", out)
	}

	k.kel("sessions", "command", sid, "stop")
	k.waitShow(sid, 60*time.Second, "session ended after stop", func(v sessionView) bool { return v.State == "ended" })

	// The assistant reply the fork continues from, by its belai entry id.
	old := readTranscript(t, sessionFile(t, h.home, sid))
	var reply string
	for _, e := range old {
		if e.Type == "assistant" && strings.Contains(e.Content, "mock reply") {
			reply = e.ID
		}
	}
	if reply == "" {
		t.Fatal("no assistant entry in the old session")
	}

	// Resume: a new session continues the stored conversation.
	rid := k.resume(sid, "--prompt", "continue from here", "--wait", "90")
	if rid == sid {
		t.Fatal("resume reused the session id")
	}
	eventually(t, 60*time.Second, "rc-session -resume", func() bool {
		return len(procsWith(h.home, []string{"rc-session"}, []string{"-resume", sid})) > 0 ||
			strings.Contains(k.kel("sessions", "transcript", rid), "continue from here")
	})
	waitTranscript(t, k.kel, rid, 90*time.Second, func(tr string) bool {
		return strings.Contains(tr, "say hello") && strings.Contains(tr, "continue from here")
	})
	resumed := readTranscript(t, sessionFile(t, h.home, rid))
	from := false
	for _, e := range resumed {
		if e.Type == "session_meta" && strings.Contains(e.Content, `"resumedFrom":"`+sid+`"`) {
			from = true
		}
	}
	if !from {
		t.Error("the resumed transcript does not record the session it continues")
	}
	k.kel("sessions", "command", rid, "stop")

	// Fork at the first reply: the new session holds the chain up to it.
	fid := k.resume(sid, "--fork", reply, "--prompt", "take another path", "--wait", "90")
	waitTranscript(t, k.kel, fid, 90*time.Second, func(tr string) bool {
		return strings.Contains(tr, "say hello") && strings.Contains(tr, "take another path")
	})
	forked := readTranscript(t, sessionFile(t, h.home, fid))
	for _, e := range forked {
		if e.Type == "user" && e.Content == "continue from here" {
			t.Error("the fork holds the resumed session's prompt")
		}
	}

	// A fork at an entry the session does not have is refused by the host.
	if out, err := k.try("sessions", "resume", sid, "--fork", "no-such-entry", "--prompt", "x", "--wait", "30"); err == nil && !strings.Contains(out, "no such entry") {
		t.Errorf("a fork at a missing entry started: %s", out)
	}
}
