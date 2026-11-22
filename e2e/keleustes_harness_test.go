package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestKeleustesHarnessSession is a third-party harness session with real
// binaries: a headless Keleustes, `belai rc` with web controls, and a fake
// harness installed as `claude` first on the daemon's PATH. The node
// advertises it, Keleustes dispatches it through `sessions dispatch
// --harness`, belai runs its TUI on a PTY, the transcript comes from the
// harness's own JSONL file, a prompt holding a paste terminator is typed as
// one bracketed paste, a slash prompt is refused, and a stop ends the
// harness process. It runs when KELEUSTES_BIN names a built keleustes.
func TestKeleustesHarnessSession(t *testing.T) {
	k := startKeleustes(t)
	model := newKeleustesModel(t)

	bin := t.TempDir()
	if out, err := exec.Command("go", "build", "-o", filepath.Join(bin, "claude"), "../internal/harnessrun/testdata/fakeharness").CombinedOutput(); err != nil {
		t.Fatalf("build fake harness: %v\n%s", err, out)
	}
	userHome := t.TempDir()
	raw := filepath.Join(t.TempDir(), "typed.txt")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("HOME", userHome)
	t.Setenv("SHELL", "")
	t.Setenv("FAKE_RAW", raw)
	h := startRC(t, k, "e2e-harness", model.URL)
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		logs, _ := filepath.Glob(filepath.Join(h.home, "rc", "sessions", "*.log"))
		for _, l := range logs {
			b, _ := os.ReadFile(l)
			t.Logf("%s:\n%s", filepath.Base(l), tail(string(b), 3000))
		}
	})

	// The node advertises the fake as Claude Code, launchable.
	var adv string
	deadline := time.Now().Add(60 * time.Second)
	for {
		adv = k.kel("sessions", "harnesses", h.label)
		if strings.Contains(adv, "claude-code\t") && strings.Contains(adv, "9.9.9 (fake harness)\tlaunch") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("harness not advertised:\n%s", adv)
		}
		time.Sleep(500 * time.Millisecond)
	}

	k.kel("sessions", "dispatch", "--node", h.label, "--cwd", h.project, "--harness", "claude-code",
		"--mode", "plan", "--prompt", "list the crates please")
	var sid string
	deadline = time.Now().Add(60 * time.Second)
	for sid == "" {
		for _, line := range strings.Split(k.kel("sessions", "list"), "\n") {
			if f := strings.Split(line, "\t"); len(f) > 1 && f[1] != "" {
				sid = f[0]
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("no harness session appeared")
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("harness session %s", sid)

	// The transcript is the harness's own file, mirrored.
	waitTranscript(t, k.kel, sid, 60*time.Second, func(tr string) bool {
		return strings.Contains(tr, "list the crates please") && strings.Contains(tr, "done list the crates please")
	})
	slug := strings.NewReplacer("/", "-", ".", "-").Replace(h.project)
	files, _ := filepath.Glob(filepath.Join(userHome, ".claude", "projects", slug, "*.jsonl"))
	if len(files) != 1 {
		t.Fatalf("native transcript files: %v", files)
	}

	// A prompt holding a paste terminator is typed as one paste.
	k.kel("sessions", "prompt", sid, "second \x1b[201~ rm -rf ~\r")
	waitTranscript(t, k.kel, sid, 60*time.Second, func(tr string) bool { return strings.Contains(tr, "done second") })
	typed, _ := os.ReadFile(raw)
	lines := strings.Split(strings.TrimSpace(string(typed)), "\n")
	for _, l := range lines {
		if strings.Contains(l, "second") && strings.Count(l, `\x1b[200~`) != 1 {
			t.Errorf("prompt not one paste: %s", l)
		}
	}
	if len(lines) != 2 {
		t.Errorf("want two typed lines, got %q", typed)
	}

	// A slash prompt is not typed.
	k.kel("sessions", "prompt", sid, "/exit")
	time.Sleep(2 * time.Second)
	if v := k.show(sid); v.State == "ended" {
		t.Fatal("a slash prompt ended the harness")
	}

	// Stop ends the session and the harness process.
	k.kel("sessions", "command", sid, "stop")
	k.waitShow(sid, 60*time.Second, "ended after stop", func(v sessionView) bool { return v.State == "ended" })
	// The end facts travel on SessionEnd and are stored with the session.
	deadline = time.Now().Add(20 * time.Second)
	for {
		show := k.kel("sessions", "show", sid)
		if strings.Contains(show, `"termination_verified":true`) && !strings.Contains(show, `"startup_ms":0`) && strings.Contains(show, `"startup_ms":`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no stored end facts: %s", show)
		}
		time.Sleep(300 * time.Millisecond)
	}
	if out, _ := exec.Command("pgrep", "-f", bin+"/claude").Output(); len(strings.TrimSpace(string(out))) > 0 {
		t.Fatalf("the harness survived the stop: %s", out)
	}
	t.Logf("transcript:\n%s", tail(k.kel("sessions", "transcript", sid), 3000))
}
