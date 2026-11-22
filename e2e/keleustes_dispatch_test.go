package e2e

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// procsWith lists the processes running under BELAI_HOME=home whose argv
// holds every one of seqs as consecutive words.
func procsWith(home string, seqs ...[]string) []int {
	var out []int
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		env, err := os.ReadFile(filepath.Join("/proc", e.Name(), "environ"))
		if err != nil || !bytes.Contains(env, []byte("\x00BELAI_HOME="+home+"\x00")) && !bytes.HasPrefix(env, []byte("BELAI_HOME="+home+"\x00")) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		argv := "\x00" + string(raw)
		ok := true
		for _, s := range seqs {
			want := ""
			for _, w := range s {
				want += "\x00" + w
			}
			ok = ok && bytes.Contains([]byte(argv+"\x00"), []byte(want+"\x00"))
		}
		if ok {
			out = append(out, pid)
		}
	}
	return out
}

// TestKeleustesDispatchFidelity is the real-binary check for Keleustes P3
// (docs/gaps/belai-counterparts.md #7, #8): a workflow session step's
// extra directory and effort, and a worker step's stay and idle wait, cross
// the node link and `belai rc` turns them into the argv of the session
// (`rc-session -add-dir DIR -effort high`) and of the detached worker
// (`agent run ... -stay -stay-idle-max 10m0s`). Linux only: it reads /proc.
func TestKeleustesDispatchFidelity(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc")
	}
	k := startKeleustes(t)
	d := driver(t, k)
	model := featuresModel(t)
	extra := t.TempDir()
	h := startFeatureRC(t, k, "f-fidelity", model.URL, "--dir", extra)
	d.waitNode(h.label)
	t.Cleanup(func() {
		for _, pid := range procsWith(h.home, []string{"agent", "run"}) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})

	step := func(id string, cfg map[string]any) string {
		return d.workflow(mustJSON(map[string]any{
			"nodes": []any{
				map[string]any{"id": "t", "type": "trigger", "title": "Go", "config": map[string]any{"kind": "manual"}},
				map[string]any{"id": "b", "type": "crew", "title": id, "config": cfg},
			},
			"edges": []any{map[string]any{"from": "t", "to": "b"}},
		}))
	}

	// A session with an extra trusted directory and high effort.
	wf := step("Session", map[string]any{
		"dispatch": "session", "brief": "say hello", "cwd": h.project,
		"dirs": []string{extra}, "effort": "high",
	})
	rid := d.start(wf, "acme/api")
	eventually(t, 90*time.Second, "rc-session with -add-dir and -effort", func() bool {
		return len(procsWith(h.home, []string{"rc-session"}, []string{"-add-dir", extra}, []string{"-effort", "high"})) > 0
	})
	r := d.runView(rid)
	for _, s := range r.Steps {
		if s.NodeID == "b" {
			f, _ := s.Details["fields"].(map[string]any)
			if f == nil || f["effort"] != "high" {
				t.Errorf("step details fields = %v", s.Details["fields"])
			}
		}
	}

	// A worker that stays, with a 10 minute idle wait.
	wf = step("Worker", map[string]any{
		"dispatch": "worker", "agent": "belai:ci-explainer", "brief": "Explain the failing check.",
		"cwd": h.project, "stay": true, "stayIdleMaxS": 600,
	})
	d.start(wf, "acme/api")
	eventually(t, 120*time.Second, "agent run with -stay -stay-idle-max 10m0s", func() bool {
		return len(procsWith(h.home, []string{"agent", "run"}, []string{"-stay", "-stay-idle-max", "10m0s"})) > 0
	})
}
