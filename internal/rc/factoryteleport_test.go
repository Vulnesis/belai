package rc

import (
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/session"
	"github.com/vulnetix/belai/internal/sessionsync"
	"github.com/vulnetix/belai/internal/teleport"
)

const (
	tpSession = "11111111-2222-4333-8444-555555555555"
	tpElse    = "99999999-2222-4333-8444-555555555555"
	tpID      = "0190f0a2-6b7e-7c1d-8a52-0d9e4f1b7a33"
)

// tpOrigin is an origin clone with unpushed and uncommitted work, offered by
// the daemon, and a session store holding one session that ran there and one
// that ran in a directory the daemon does not offer.
func tpOrigin(t *testing.T) (dir string, store *session.Store) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	t.Setenv("BELAI_HOME", t.TempDir())
	root := t.TempDir()
	bare, origin := filepath.Join(root, "bare.git"), filepath.Join(root, "origin")
	tcGit(t, root, "init", "--bare", "-b", "main", bare)
	tcGit(t, root, "clone", bare, origin)
	tcWrite(t, origin, "main.go", "package main\n\nfunc main() {}\n")
	tcGit(t, origin, "add", "-A")
	tcGit(t, origin, "commit", "--no-gpg-sign", "-m", "init")
	tcGit(t, origin, "push", "origin", "HEAD:main")
	tcGit(t, origin, "branch", "--set-upstream-to=origin/main")
	tcGit(t, origin, "remote", "set-url", "origin", "https://github.com/acme/app.git")
	tcGit(t, origin, "config", "url."+bare+".insteadOf", "https://github.com/acme/app.git")
	tcWrite(t, origin, "main.go", "package main\n\nfunc main() { feature() }\n")
	tcWrite(t, origin, ".env", "SECRET=1\n")
	dir, _ = Normalize(origin)

	store = session.NewStoreAt(t.TempDir())
	write := func(id, cwd string) {
		key, err := session.KeyFor(cwd)
		if err != nil {
			t.Fatal(err)
		}
		meta := session.Meta{Schema: session.SchemaVersion, Cwd: cwd}.ToEntry("")
		u := session.Entry{ID: "u-" + id[:8], ParentID: meta.ID, Type: "user", Role: "user", Content: "add feature()", Timestamp: 2}
		a := session.Entry{ID: "a-" + id[:8], ParentID: u.ID, Type: "assistant", Role: "assistant", Content: "done", Timestamp: 3,
			Meta: map[string]any{"model": "m-1"}}
		if err := store.Import(key, id, []session.Entry{meta, u, a}); err != nil {
			t.Fatal(err)
		}
	}
	write(tpSession, dir)
	write(tpElse, root)
	return dir, store
}

func teleportJobFrame(id, payload string) *nodev1.Job {
	return &nodev1.Job{Id: id, Kind: "teleport", PayloadJson: payload}
}

// A teleport job bundles a session of this host (its lines, its repository
// facts and its changes as a replay, never a credential file) and uploads it
// under the teleport id Keleustes named. A session this host does not hold, or
// one that ran in a directory it does not offer, is refused; so is a payload
// that names no teleport, session or node.
func TestKeleustesTeleportJobUploadsTheSessionBundle(t *testing.T) {
	dir, store := tpOrigin(t)
	ff := newFake()
	good := `{"task":"teleport_upload","teleportId":"` + tpID + `","sessionId":"` + tpSession + `","toNode":"node-2"}`
	ff.jobs = []*nodev1.Job{
		teleportJobFrame("t1", good),
		teleportJobFrame("t2", `{"task":"teleport_upload","teleportId":"`+tpID+`","sessionId":"aaaaaaaa-2222-4333-8444-555555555555","toNode":"node-2"}`),
		teleportJobFrame("t3", `{"task":"teleport_upload","teleportId":"`+tpID+`","sessionId":"`+tpElse+`","toNode":"node-2"}`),
		teleportJobFrame("t4", `{"task":"teleport_download","teleportId":"`+tpID+`","sessionId":"`+tpSession+`","toNode":"node-2"}`),
		teleportJobFrame("t5", `{"task":"teleport_upload","teleportId":"../x","sessionId":"`+tpSession+`","toNode":"node-2"}`),
		teleportJobFrame("t6", `{"task":"teleport_upload","teleportId":"`+tpID+`","sessionId":"`+tpSession+`","toNode":"a b"}`),
	}
	got, _ := runFactoryDaemon(t, ff, Options{
		Dirs: []Dir{{Path: dir, Name: "app", Source: SourceArg}}, Sessions: store, TeleportGit: tcAllowFile,
	})

	if r := got["t1"]; r.GetStatus() != jobOK {
		t.Fatalf("t1 = %+v", r)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(got["t1"].GetOutputJson()), &out); err != nil || out["teleportId"] != tpID || out["code"] != sessionsync.CodeReplay {
		t.Errorf("t1 output = %s", got["t1"].GetOutputJson())
	}
	for id, want := range map[string]string{
		"t2": "did not run on this host", "t3": "does not offer", "t4": "teleport task",
		"t5": "names no teleport", "t6": "names no target node",
	} {
		if r := got[id]; r.GetStatus() != jobRefused || !strings.Contains(r.GetError(), want) {
			t.Errorf("%s = %+v, want refused with %q", id, r, want)
		}
	}

	ff.mu.Lock()
	defer ff.mu.Unlock()
	if len(ff.uploads) != 1 {
		t.Fatalf("uploads = %d, want 1", len(ff.uploads))
	}
	up := ff.uploads[0]
	if up.u.TeleportID != tpID || up.u.SessionID != tpSession || up.u.ToNode != "node-2" || up.u.Title == "" {
		t.Errorf("upload = %+v", up.u)
	}
	b, err := teleport.DecodeBundle(up.data)
	if err != nil {
		t.Fatal(err)
	}
	if b.SessionID != tpSession || len(b.Entries) != 3 || b.Entries[2].Seq != 2 || !strings.Contains(string(b.Entries[2].Meta), "m-1") {
		t.Errorf("bundle = %+v", b)
	}
	if !strings.Contains(string(b.Git), `"remote":"acme/app"`) || !strings.Contains(string(b.Git), `"host":"github.com"`) {
		t.Errorf("git facts = %s", b.Git)
	}
	c := b.Code
	if c == nil || c.Mode != sessionsync.CodeReplay || !strings.Contains(c.Patch, "feature()") || !strings.Contains(c.Reason, "Keleustes") {
		t.Fatalf("code = %+v", c)
	}
	if strings.Contains(c.Patch, "SECRET") {
		t.Error("a credential file left the origin")
	}
	skipped := false
	for _, s := range c.Skipped {
		skipped = skipped || s.Path == ".env"
	}
	if !skipped {
		t.Errorf("skipped = %+v, want .env listed", c.Skipped)
	}
}

// An upload Keleustes refuses fails the job with the reason.
func TestKeleustesTeleportJobFailsWhenTheUploadIsRefused(t *testing.T) {
	dir, store := tpOrigin(t)
	ff := newFake()
	ff.uploadErr = errors.New("rpc error: code = FailedPrecondition desc = teleport is expired")
	ff.jobs = []*nodev1.Job{teleportJobFrame("t1",
		`{"task":"teleport_upload","teleportId":"`+tpID+`","sessionId":"`+tpSession+`","toNode":"node-2"}`)}
	got, _ := runFactoryDaemon(t, ff, Options{
		Dirs: []Dir{{Path: dir, Name: "app", Source: SourceArg}}, Sessions: store, TeleportGit: tcAllowFile,
	})
	if r := got["t1"]; r.GetStatus() != jobFailed || !strings.Contains(r.GetError(), "expired") {
		t.Errorf("t1 = %+v", r)
	}
}
