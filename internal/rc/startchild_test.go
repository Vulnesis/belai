//go:build !windows

package rc

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/vulnetix/belai/internal/factorylink"
)

// startChild once failed every dispatched start with "exec: command with a
// non-nil Cancel was not created with CommandContext".
func TestStartChildSpawnsInOwnProcessGroup(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "fake-belai")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nsleep 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	pid, wait, err := startChild(Child{
		Exe: exe, Cwd: dir, Dispatch: "d1", SessionID: "s1", Idle: time.Minute,
		Prompt: "hello", LogPath: filepath.Join(dir, "sessions", "s1.log"),
	})
	if err != nil {
		t.Fatalf("startChild: %v", err)
	}
	if pgid, err := syscall.Getpgid(pid); err != nil || pgid != pid {
		t.Errorf("child pgid = %d (err %v), want its own group %d", pgid, err, pid)
	}
	if err := wait(); err != nil {
		t.Errorf("wait: %v", err)
	}
}

// The daemon's control flags reach every session as fixed argv, and only
// those two words: nothing from the request is added.
func TestStartChildPassesControlFlags(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "fake-belai")
	out := filepath.Join(dir, "argv")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\necho \"$@\" > "+out+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		controls, off bool
		want          string
	}{
		{false, false, ""},
		{true, false, " -controls"},
		{true, true, " -controls -allow-guardrails-off"},
	} {
		_, wait, err := startChild(Child{Exe: exe, Cwd: dir, Dispatch: "d1", SessionID: "s1", Idle: time.Minute,
			Prompt: "hi", Controls: c.controls, GuardrailsOff: c.off})
		if err != nil {
			t.Fatal(err)
		}
		_ = wait()
		got, _ := os.ReadFile(out)
		want := "rc-session -dispatch d1 -session-id s1 -idle 1m0s" + c.want + "\n"
		if string(got) != want {
			t.Fatalf("argv = %q, want %q", got, want)
		}
	}
}

// A dispatch's vault grant reaches the session on an inherited pipe: the
// child's environment carries only the descriptor number, its argv nothing,
// and the session log nothing.
func TestStartChildPassesTheGrantOnAPipe(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "fake-belai")
	script := "#!/bin/sh\nenv > " + dir + "/env\necho \"$@\" > " + dir + "/argv\n" +
		"eval \"cat <&$BELAI_KELEUSTES_GRANT_FD\" > " + dir + "/got\necho started\n"
	if err := os.WriteFile(exe, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	g := factorylink.GrantFrom(testGrant(time.Now().Add(time.Hour)), time.Now())
	logPath := filepath.Join(dir, "sessions", "s1.log")
	_, wait, err := startChild(Child{Exe: exe, Cwd: dir, Dispatch: "d1", SessionID: "s1", Idle: time.Minute,
		Prompt: "hello", LogPath: logPath, Grant: g})
	if err != nil {
		t.Fatal(err)
	}
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "got"))
	read, err := factorylink.ReadGrant(bytes.NewReader(got), time.Now())
	if err != nil {
		t.Fatalf("the child could not read its grant: %v", err)
	}
	if s := read.Secrets(time.Now()); len(s) != 1 || s[0].Value != grantSecret || s[0].Provider != "anthropic" {
		t.Errorf("grant read = %v", read)
	}
	env, _ := os.ReadFile(filepath.Join(dir, "env"))
	if !bytes.Contains(env, []byte(factorylink.GrantFDEnv+"=3")) {
		t.Errorf("the child was not told its descriptor")
	}
	for _, f := range []string{"env", "argv"} {
		data, _ := os.ReadFile(filepath.Join(dir, f))
		if bytes.Contains(data, []byte(grantSecret)) {
			t.Errorf("the grant reached the child's %s", f)
		}
	}
	if data, _ := os.ReadFile(logPath); bytes.Contains(data, []byte(grantSecret)) {
		t.Error("the grant reached the session log")
	}
}
