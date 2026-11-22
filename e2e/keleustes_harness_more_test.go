package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeHarnessEnv builds the fake harness as `claude` first on PATH, with a
// fresh HOME for its transcripts, for every belai started after it.
func fakeHarnessEnv(t *testing.T, extra ...string) {
	t.Helper()
	bin := t.TempDir()
	if out, err := exec.Command("go", "build", "-o", filepath.Join(bin, "claude"), "../internal/harnessrun/testdata/fakeharness").CombinedOutput(); err != nil {
		t.Fatalf("build fake harness: %v\n%s", err, out)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SHELL", "")
	for i := 0; i+1 < len(extra); i += 2 {
		t.Setenv(extra[i], extra[i+1])
	}
}

// waitAdvert waits until node advertises the fake Claude Code as launchable.
func (k *keleustes) waitAdvert(node string) {
	k.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		if strings.Contains(k.kel("sessions", "harnesses", node), "9.9.9 (fake harness)\tlaunch") {
			return
		}
		if time.Now().After(deadline) {
			k.t.Fatalf("%s never advertised the harness", node)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// harnessSession dispatches the fake on node and returns the new session's
// id and its node id.
func (k *keleustes) harnessSession(node, cwd, prompt string, extra ...string) (string, string) {
	k.t.Helper()
	before := map[string]bool{}
	for _, l := range strings.Split(k.kel("sessions", "list"), "\n") {
		before[strings.Split(l, "\t")[0]] = true
	}
	k.kel(append([]string{"sessions", "dispatch", "--node", node, "--cwd", cwd, "--harness", "claude-code", "--prompt", prompt}, extra...)...)
	deadline := time.Now().Add(60 * time.Second)
	for {
		for _, l := range strings.Split(k.kel("sessions", "list"), "\n") {
			f := strings.Split(l, "\t")
			if len(f) > 2 && f[0] != "" && !before[f[0]] {
				return f[0], f[2]
			}
		}
		if time.Now().After(deadline) {
			k.t.Fatalf("no harness session started on %s", node)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func (k *keleustes) stopSession(sid string) {
	k.t.Helper()
	k.kel("sessions", "command", sid, "stop")
	k.waitShow(sid, 60*time.Second, "ended", func(v sessionView) bool { return v.State == "ended" })
}

// TestKeleustesHarnessA2A is two belai hosts joined to one Keleustes, each
// running a fake harness session. A's harness lists peers and sends B a
// message through its belai a2a-mcp bridge; B's harness is typed only the
// notice line and reads the text with its inbox tool (as untrusted peer
// content). The owner messages B too. Under the A2A blackout the bridge and
// the owner's send are refused.
func TestKeleustesHarnessA2A(t *testing.T) {
	k := startKeleustes(t)
	model := newKeleustesModel(t)
	fakeHarnessEnv(t)
	a := startRC(t, k, "h-a", model.URL)
	b := startRC(t, k, "h-b", model.URL)
	t.Cleanup(func() {
		if t.Failed() {
			for _, h := range []rcHost{a, b} {
				logs, _ := filepath.Glob(filepath.Join(h.home, "rc", "sessions", "*.log"))
				for _, l := range logs {
					data, _ := os.ReadFile(l)
					t.Logf("%s %s:\n%s", h.label, filepath.Base(l), tail(string(data), 2000))
				}
			}
			t.Logf("A:\n%s", tail(k.kel("sessions", "transcript", sidAOf(k, a.label)), 3000))
			q, _ := exec.Command("sqlite3", "-readonly", filepath.Join(k.data, "keleustes.db"), "select seq, from_agent, to_agent, substr(text,1,60) from a2a_messages").CombinedOutput()
			t.Logf("a2a_messages:\n%s", q)
			for _, h := range []rcHost{a, b} {
				au, _ := os.ReadFile(filepath.Join(h.home, "a2a", "audit.jsonl"))
				t.Logf("%s a2a audit:\n%s", h.label, tail(string(au), 2500))
			}
		}
	})
	k.waitAdvert(a.label)
	k.waitAdvert(b.label)

	sidB, nodeB := k.harnessSession(b.label, b.project, "hello from b")
	sidA, _ := k.harnessSession(a.label, a.project, "hello from a")
	waitTranscript(t, k.kel, sidB, 60*time.Second, func(s string) bool { return strings.Contains(s, "done hello from b") })
	waitTranscript(t, k.kel, sidA, 60*time.Second, func(s string) bool { return strings.Contains(s, "done hello from a") })
	peerB := nodeB + ":" + sidB

	k.kel("sessions", "prompt", sidA, "a2a peers")
	waitTranscript(t, k.kel, sidA, 60*time.Second, func(s string) bool { return strings.Contains(s, "a2a-result") && strings.Contains(s, sidB) })

	k.kel("sessions", "prompt", sidA, "a2a send "+peerB+" ping-from-a")
	waitTranscript(t, k.kel, sidA, 60*time.Second, func(s string) bool { return strings.Contains(s, `"messageId"`) })
	// B is told a message waits, never its text, and reads it from the bridge.
	waitTranscript(t, k.kel, sidB, 90*time.Second, func(s string) bool { return strings.Contains(s, "peer message waiting") })
	if tr := k.kel("sessions", "transcript", sidB); strings.Contains(tr, "user\tping-from-a") {
		t.Fatalf("peer text was typed into B:\n%s", tr)
	}
	k.kel("sessions", "prompt", sidB, "a2a inbox")
	waitTranscript(t, k.kel, sidB, 60*time.Second, func(s string) bool {
		return strings.Contains(s, "untrusted_peer_message") && strings.Contains(s, "ping-from-a")
	})

	// The owner is a participant: classified on B like any peer.
	k.kel("sessions", "a2a-send", peerB, "hello-from-owner")
	waitTranscript(t, k.kel, sidB, 90*time.Second, func(s string) bool { return strings.Count(s, "peer message waiting") >= 2 })
	k.kel("sessions", "prompt", sidB, "a2a inbox")
	waitTranscript(t, k.kel, sidB, 90*time.Second, func(s string) bool { return strings.Contains(s, "hello-from-owner") })

	// Blackout: the owner's send and the bridge's send are refused.
	k.kel("sessions", "a2a-blackout", "on", "--reason", "e2e drill")
	if out, err := k.try("sessions", "a2a-send", peerB, "during blackout"); err == nil {
		t.Fatalf("owner send went through the blackout: %s", out)
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		k.kel("sessions", "prompt", sidA, "a2a send "+peerB+" blacked-out")
		time.Sleep(3 * time.Second)
		tr := k.kel("sessions", "transcript", sidA)
		if strings.Contains(tr, "a2a blackout") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the bridge never refused under the blackout:\n%s", tail(tr, 3000))
		}
	}
	time.Sleep(3 * time.Second)
	if strings.Contains(k.kel("sessions", "transcript", sidB), "blacked-out") {
		t.Fatal("a message crossed the blackout")
	}
	k.kel("sessions", "a2a-blackout", "off", "--reason", "drill over")
	k.stopSession(sidA)
	k.stopSession(sidB)
}

// TestKeleustesHarnessKeyHandoff checks the three key modes with a fake
// harness that reports only whether ANTHROPIC_API_KEY is set: own login
// (the default) hands nothing even when a key is picked, hand-off passes the
// picked key, always passes the provider's key unpicked, and the kill switch
// refuses a dispatch that would hand one off. The value never reaches a
// transcript.
func TestKeleustesHarnessKeyHandoff(t *testing.T) {
	k := startKeleustes(t)
	model := newKeleustesModel(t)
	fakeHarnessEnv(t, "FAKE_KEY_ENV", "ANTHROPIC_API_KEY")
	h := startRC(t, k, "h-keys", model.URL)
	k.waitAdvert(h.label)
	const secret = "sk-ant-e2e-handoff-0123456789abcdef"
	cmd := exec.Command(k.bin, "--data", k.data, "sessions", "vault-key", "--provider", "anthropic", "--env", "ANTHROPIC_API_KEY")
	cmd.Env, cmd.Stdin = k.env, strings.NewReader(secret)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("vault-key: %v", err)
	}
	keyID := strings.TrimSpace(string(out))

	run := func(want string, extra ...string) string {
		t.Helper()
		sid, _ := k.harnessSession(h.label, h.project, "show key", extra...)
		waitTranscript(t, k.kel, sid, 60*time.Second, func(s string) bool { return strings.Contains(s, "key-present: ") })
		tr := k.kel("sessions", "transcript", sid)
		if !strings.Contains(tr, "key-present: "+want) {
			t.Fatalf("want key-present %s:\n%s", want, tail(tr, 3000))
		}
		if strings.Contains(tr, secret) {
			t.Fatal("the key value reached the transcript")
		}
		k.stopSession(sid)
		return tr
	}

	tr := run("false", "--key", keyID)
	if strings.Contains(tr, "vault keys handed") {
		t.Fatal("own login handed a key off")
	}
	k.kel("sessions", "harness-keys", "--set", `{"global":"handoff"}`)
	if tr := run("true", "--key", keyID); !strings.Contains(tr, "vault keys handed to the harness: ANTHROPIC_API_KEY") {
		t.Fatalf("hand-off not recorded:\n%s", tail(tr, 2000))
	}
	run("false") // hand-off needs a pick for the session
	k.kel("sessions", "harness-keys", "--set", `{"global":"always"}`)
	run("true")

	k.kel("host", "stop", "--reason", "e2e kill switch")
	if out, err := k.try("sessions", "dispatch", "--node", h.label, "--cwd", h.project, "--harness", "claude-code",
		"--prompt", "show key", "--key", keyID); err == nil {
		t.Fatalf("a hand-off dispatch passed the kill switch: %s", out)
	}
	k.kel("host", "resume")
	if out := k.kel("host", "verify"); !strings.Contains(out, `"ok":true`) {
		t.Fatalf("audit: %s", out)
	}
}

// sidAOf is the newest session on node (for failure logs).
func sidAOf(k *keleustes, node string) string {
	out, _ := k.try("sessions", "list", "--node", node)
	return strings.Split(strings.Split(out, "\n")[0], "\t")[0]
}
