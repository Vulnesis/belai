package e2e

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vulnetix/belai/internal/testutil"
)

// keleustes is a headless Keleustes on a free loopback port, driven through
// its command line.
type keleustes struct {
	t    *testing.T
	bin  string
	data string
	env  []string
	log  string // the server's log file
}

// kel runs a keleustes command against the fixture's data directory and
// returns its trimmed stdout, failing the test on a non-zero exit.
func (k *keleustes) kel(args ...string) string {
	k.t.Helper()
	out, err := k.try(args...)
	if err != nil {
		k.t.Fatalf("keleustes %v: %v\n%s", args, err, out)
	}
	return out
}

// try is kel without failing: the output (stdout, then stderr on failure).
func (k *keleustes) try(args ...string) (string, error) {
	cmd := exec.Command(k.bin, append([]string{"--data", k.data}, args...)...)
	cmd.Env = k.env
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			out = append(out, ee.Stderr...)
		}
	}
	return strings.TrimSpace(string(out)), err
}

func startKeleustes(t *testing.T) *keleustes {
	t.Helper()
	kbin := os.Getenv("KELEUSTES_BIN")
	if kbin == "" {
		t.Skip("KELEUSTES_BIN not set")
	}
	k := &keleustes{t: t, bin: kbin, data: t.TempDir(), env: append(os.Environ(), "RUST_LOG=info,sqlx=warn")}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	k.kel("config", "node.listen_addr", addr)
	server := exec.Command(kbin, "--data", k.data, "--headless")
	server.Env = k.env
	klog, _ := os.Create(filepath.Join(t.TempDir(), "keleustes.log"))
	server.Stdout, server.Stderr = klog, klog
	k.log = klog.Name()
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = server.Process.Kill()
		_ = server.Wait()
		if t.Failed() {
			b, _ := os.ReadFile(klog.Name())
			t.Logf("keleustes log:\n%s", tail(string(b), 4000))
		}
	})
	waitTCP(t, addr)
	return k
}

// rcHost is one belai host joined to Keleustes and running `belai rc`.
type rcHost struct {
	label, home, project string
}

// startRC joins a fresh belai home to k under label and runs `belai rc`
// with web controls on a new project directory.
func startRC(t *testing.T, k *keleustes, label, modelURL string) rcHost {
	t.Helper()
	h := rcHost{label: label, home: t.TempDir(), project: t.TempDir()}
	if err := os.WriteFile(filepath.Join(h.project, "README.md"), []byte("demo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The mock provider, and no OS keyring (the node key falls back to a
	// 0600 file under the home).
	benv := belaiEnv(modelURL, h.home,
		"BELAI_PROVIDER=openai",
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent/keleustes-e2e",
	)
	token := k.kel("token", "new", "--label", label)
	connect := exec.Command(belaiBin, "connect", token)
	connect.Env = benv
	if out, err := connect.CombinedOutput(); err != nil {
		t.Fatalf("belai connect: %v\n%s", err, out)
	} else if !strings.Contains(string(out), "joined Keleustes") {
		t.Fatalf("belai connect said: %s", out)
	}
	if _, err := os.Stat(filepath.Join(h.home, "factory")); err != nil {
		t.Fatalf("no profile under the belai home: %v", err)
	}
	rc := exec.Command(belaiBin, "rc", "--dir", h.project, "--max", "2", "--web-controls")
	rc.Env = benv
	rc.Dir = h.project
	rlog, _ := os.Create(filepath.Join(t.TempDir(), label+"-rc.log"))
	rc.Stdout, rc.Stderr = rlog, rlog
	if err := rc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = rc.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _ = rc.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = rc.Process.Kill()
			<-done
		}
		if t.Failed() {
			b, _ := os.ReadFile(rlog.Name())
			t.Logf("belai rc %s log:\n%s", label, tail(string(b), 6000))
		}
	})
	return h
}

// newKeleustesModel is the mock provider for the Keleustes tests: classifier
// roles answer as newMockServer's do; a prompt asking for the marker file
// gets one Write call, and every other chat turn "mock reply" with usage.
func newKeleustesModel(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := testutil.DecodeChat(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		var system, user string
		toolResult := false
		for _, m := range req.Messages {
			switch m.Role {
			case "system":
				system = m.Content
			case "user":
				user = m.Content
			case "tool":
				toolResult = true
			}
		}
		reply := "mock reply"
		switch {
		case strings.Contains(system, "security classifier"):
			reply = securitySentinelFor(user)
		case strings.Contains(system, "operating-mode classifier"):
			reply = modeSentinelFor(user)
		case strings.Contains(system, "clarification questionnaire"):
			reply = `{"groups":[]}`
		case strings.Contains(system, "classifier"):
			reply = "SAFE"
		case strings.Contains(user, "write the marker") && !toolResult && len(req.Tools) > 0:
			testutil.WriteToolCall(w, "Write", `{"file_path":"marker.txt","content":"from keleustes\n"}`)
			return
		}
		if req.Stream {
			testutil.WriteChatStream(w, reply)
			return
		}
		testutil.WriteChatWithUsage(w, reply, 50, 5)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// dispatch starts a session on node and returns its id.
func (k *keleustes) dispatch(node, cwd, prompt string) string {
	k.t.Helper()
	out := k.kel("sessions", "dispatch", "--node", node, "--cwd", cwd, "--prompt", prompt,
		"--provider", "openai", "--model", "test", "--mode", "agent", "--wait", "90")
	for _, line := range strings.Split(out, "\n") {
		if s, ok := strings.CutPrefix(line, "session "); ok {
			return strings.TrimSpace(s)
		}
	}
	k.t.Fatalf("dispatch did not start a session:\n%s", out)
	return ""
}

// sessionView is `keleustes sessions show`.
type sessionView struct {
	State      string `json:"state"`
	EndReason  string `json:"endReason"`
	PendingAsk *struct {
		ID      string `json:"id"`
		Kind    string `json:"kind"`
		Title   string `json:"title"`
		Options []struct {
			ID string `json:"id"`
		} `json:"options"`
	} `json:"pendingAsk"`
	Accepts *struct {
		Prompts  bool `json:"prompts"`
		Answers  bool `json:"answers"`
		Controls bool `json:"controls"`
	} `json:"accepts"`
	Usage []struct {
		Provider    string `json:"provider"`
		Model       string `json:"model"`
		InputTokens int64  `json:"input_tokens"`
	} `json:"usage"`
}

func (k *keleustes) show(sid string) sessionView {
	k.t.Helper()
	var v sessionView
	if err := json.Unmarshal([]byte(k.kel("sessions", "show", sid)), &v); err != nil {
		k.t.Fatalf("sessions show: %v", err)
	}
	return v
}

// waitShow polls `sessions show` until ok holds.
func (k *keleustes) waitShow(sid string, d time.Duration, what string, ok func(sessionView) bool) sessionView {
	k.t.Helper()
	deadline := time.Now().Add(d)
	for {
		v := k.show(sid)
		if ok(v) {
			return v
		}
		if time.Now().After(deadline) {
			k.t.Fatalf("%s: last %+v\ntranscript:\n%s", what, v, tail(k.kel("sessions", "transcript", sid), 3000))
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// TestKeleustesRemoteControl is the Keleustes acceptance path with real
// binaries: a headless Keleustes mints a join token, `belai connect`
// redeems it, `belai rc` owns the node link, and Keleustes dispatches a
// session to it, reads its transcript and usage, prompts it again, turns its
// ask on, answers its permission ask with a structured decision, and stops
// it. The model is a mock provider. It runs when KELEUSTES_BIN names a built
// `keleustes` binary.
func TestKeleustesRemoteControl(t *testing.T) {
	k := startKeleustes(t)
	model := newKeleustesModel(t)
	h := startRC(t, k, "e2e-rc", model.URL)

	// Dispatch from Keleustes; it queues until rc's link is up.
	sid := k.dispatch(h.label, h.project, "say hello")
	t.Logf("dispatched session %s", sid)

	// The transcript reaches Keleustes: the prompt and the model's reply.
	waitTranscript(t, k.kel, sid, 90*time.Second, func(tr string) bool {
		return strings.Contains(tr, "say hello") && strings.Contains(tr, "mock reply")
	})
	// Usage per model reaches Keleustes with the session.
	v := k.waitShow(sid, 60*time.Second, "usage reported", func(v sessionView) bool {
		return len(v.Usage) > 0 && v.Usage[0].InputTokens > 0
	})
	if v.Accepts == nil || !v.Accepts.Controls || !v.Accepts.Prompts {
		t.Errorf("accepts = %+v, want prompts and controls (rc --web-controls)", v.Accepts)
	}

	// A prompt typed in Keleustes runs in the session.
	k.kel("sessions", "prompt", sid, "and now a follow-up")
	waitTranscript(t, k.kel, sid, 90*time.Second, func(tr string) bool {
		return strings.Contains(tr, "and now a follow-up") &&
			strings.Count(tr, "mock reply") >= 2
	})

	// Ask on (a session control), then a prompt whose tool call asks: the
	// structured ask reaches Keleustes with its options and is answered there.
	k.kel("sessions", "command", sid, "ask", "on")
	k.waitShow(sid, 60*time.Second, "answers on", func(v sessionView) bool {
		return v.Accepts != nil && v.Accepts.Answers
	})
	k.kel("sessions", "prompt", sid, "please write the marker")
	v = k.waitShow(sid, 90*time.Second, "a permission ask", func(v sessionView) bool {
		return v.PendingAsk != nil && v.PendingAsk.Kind == "permission"
	})
	if v.State != "waiting" || len(v.PendingAsk.Options) < 2 {
		t.Errorf("ask view = %+v", v)
	}
	// A decision the ask does not list is refused by Keleustes.
	if out, err := k.try("sessions", "answer", sid, v.PendingAsk.ID, "allow_forever"); err == nil {
		t.Errorf("an unlisted decision was queued: %s", out)
	}
	k.kel("sessions", "answer", sid, v.PendingAsk.ID, "allow_once")
	deadline := time.Now().Add(60 * time.Second)
	for {
		if b, err := os.ReadFile(filepath.Join(h.project, "marker.txt")); err == nil && strings.Contains(string(b), "from keleustes") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the allowed Write never ran; transcript:\n%s", tail(k.kel("sessions", "transcript", sid), 3000))
		}
		time.Sleep(250 * time.Millisecond)
	}
	k.waitShow(sid, 60*time.Second, "the ask cleared", func(v sessionView) bool { return v.PendingAsk == nil })

	t.Logf("transcript in Keleustes:\n%s", tail(k.kel("sessions", "transcript", sid), 3000))

	// A stop from Keleustes ends it.
	k.kel("sessions", "command", sid, "stop")
	k.waitShow(sid, 60*time.Second, "session ended after stop", func(v sessionView) bool { return v.State == "ended" })
}

func waitTCP(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s", addr)
}

func waitTranscript(t *testing.T, kel func(...string) string, sid string, d time.Duration, ok func(string) bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	var last string
	for ctx.Err() == nil {
		last = kel("sessions", "transcript", sid)
		if ok(last) {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("transcript never matched; last:\n%s", tail(last, 4000))
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// TestKeleustesCrossHost is host A → Keleustes → host B with real binaries:
// A's user asks for a session on B with `belai connect dispatch`; with the
// node policy off Keleustes refuses; with it on (rule "ask") the request
// waits until the owner approves it in Keleustes; B's rc then runs it, and
// A's watch reports the session B started.
func TestKeleustesCrossHost(t *testing.T) {
	k := startKeleustes(t)
	model := newKeleustesModel(t)
	a := startRC(t, k, "e2e-a", model.URL)
	b := startRC(t, k, "e2e-b", model.URL)
	fromA := func(args ...string) (string, error) {
		cmd := exec.Command(belaiBin, append([]string{"connect"}, args...)...)
		cmd.Env = belaiEnv(model.URL, a.home, "DBUS_SESSION_BUS_ADDRESS=unix:path=/nonexistent/keleustes-e2e")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	// Both links up before asking.
	deadline := time.Now().Add(60 * time.Second)
	for {
		if out, _ := fromA("status"); strings.Contains(out, "online") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("host A never came online")
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Off by default.
	if out, err := fromA("dispatch", "-on", b.label, "-cwd", b.project, "-prompt", "say hello"); err == nil || !strings.Contains(out, "off") {
		t.Fatalf("policy off: err %v, out %s", err, out)
	}

	k.kel("config", "fleet.policy", `{"enabled":true}`)
	// B advertises remote control once its own link is up.
	deadline = time.Now().Add(60 * time.Second)
	for {
		out, _ := fromA("nodes")
		if strings.Contains(out, "\t"+b.label+"\tonline,rc\t") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("host B never listed online: %s", out)
		}
		time.Sleep(500 * time.Millisecond)
	}
	out, err := fromA("dispatch", "-on", b.label, "-cwd", b.project, "-prompt", "say hello from a")
	if err != nil || !strings.Contains(out, "awaiting_approval") {
		t.Fatalf("dispatch: %v\n%s", err, out)
	}
	var rid string
	for _, f := range strings.Fields(out) {
		if len(f) == 36 && strings.Count(f, "-") == 4 {
			rid = f
			break
		}
	}
	if rid == "" {
		t.Fatalf("no request id in %q", out)
	}
	if reqs := k.kel("sessions", "requests", "--state", "awaiting_approval"); !strings.Contains(reqs, rid) {
		t.Fatalf("requests = %s", reqs)
	}

	// A's watch waits while the owner approves in Keleustes.
	type result struct {
		out string
		err error
	}
	got := make(chan result, 1)
	go func() {
		// A second request, so the watch covers one approved after it opened.
		o, e := fromA("dispatch", "-on", "any", "-cwd", b.project, "-prompt", "say hello again", "-wait", "120")
		got <- result{o, e}
	}()
	var second string
	deadline = time.Now().Add(30 * time.Second)
	for second == "" {
		for _, line := range strings.Split(k.kel("sessions", "requests", "--state", "awaiting_approval"), "\n") {
			if f := strings.Fields(line); len(f) > 0 && f[0] != rid {
				second = f[0]
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the second request never arrived")
		}
		time.Sleep(250 * time.Millisecond)
	}
	k.kel("sessions", "decline", rid)
	k.kel("sessions", "approve", second)
	r := <-got
	if r.err != nil {
		t.Fatalf("watch: %v\n%s", r.err, r.out)
	}
	var sid string
	for _, line := range strings.Split(r.out, "\n") {
		if s, ok := strings.CutPrefix(line, "session "); ok {
			sid = strings.TrimSpace(s)
		}
	}
	if sid == "" {
		t.Fatalf("no session from the watch:\n%s", r.out)
	}
	// The session runs on B, with the prompt A sent.
	// The watch reports the session as the dispatch starts; it reaches the
	// server with B's first upsert a moment later (not found until then).
	waitTranscript(t, func(a ...string) string { out, _ := k.try(a...); return out }, sid, 90*time.Second, func(tr string) bool {
		return strings.Contains(tr, "say hello again") && strings.Contains(tr, "mock reply")
	})
	var bNode string
	for _, line := range strings.Split(k.kel("nodes", "list"), "\n") {
		if f := strings.Split(line, "\t"); len(f) > 1 && f[1] == b.label {
			bNode = f[0]
		}
	}
	if !strings.Contains(k.kel("sessions", "list"), sid+"\t") || bNode == "" {
		t.Fatal("session or node B missing")
	}
	for _, line := range strings.Split(k.kel("sessions", "list"), "\n") {
		if strings.HasPrefix(line, sid+"\t") && !strings.Contains(line, "\t"+bNode+"\t") {
			t.Errorf("session ran elsewhere than B: %s", line)
		}
	}
}
