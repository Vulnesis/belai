package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Real-binary checks for the Keleustes P6 wiring (keleustes
// docs/gaps/belai-counterparts.md #33, rows 49 and 54): a headless
// Keleustes, `belai connect` + `belai rc`, the mock provider and the
// kls_e2e driver.

// TestKeleustesBudgetPush (#33): a budget saved in Keleustes goes out as a
// budget_update dispatch to the host that runs a worker; belai lowers that
// worker's caps through its control file and reports the count. Under the
// kill switch the save pushes nothing (refused, audited).
func TestKeleustesBudgetPush(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("reads /proc")
	}
	k := startKeleustes(t)
	d := driver(t, k)
	model := featuresModel(t)
	h := startFeatureRC(t, k, "f-budget", model.URL)
	node := d.waitNode(h.label)
	t.Cleanup(func() {
		for _, pid := range procsWith(h.home, []string{"agent", "run"}) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	wf := d.workflow(mustJSON(map[string]any{
		"nodes": []any{
			map[string]any{"id": "t", "type": "trigger", "title": "Go", "config": map[string]any{"kind": "manual"}},
			map[string]any{"id": "b", "type": "crew", "title": "Worker", "config": map[string]any{
				"dispatch": "worker", "agent": "belai:ci-explainer", "brief": "Explain the failing check.",
				"cwd": h.project, "stay": true, "stayIdleMaxS": 600,
			}},
		},
		"edges": []any{map[string]any{"from": "t", "to": "b"}},
	}))
	d.start(wf, "acme/api")
	eventually(t, 120*time.Second, "a staying worker on the host", func() bool {
		return len(procsWith(h.home, []string{"agent", "run"}, []string{"-stay"})) > 0
	})
	eventually(t, 90*time.Second, "the host reports its worker", func() bool {
		var st struct {
			Workers []struct {
				ID string `json:"id"`
			} `json:"workers"`
		}
		d.json(&st, "node-status", node.ID)
		return len(st.Workers) > 0
	})

	var b struct{ ID string }
	d.json(&b, "budget", `{"name":"E2E push","applies_to":"all","provider":"all","period":"month","limit_usd":5,"action_at_limit":"pause_run"}`)
	e := d.waitLedger("budget_push", "", b.ID, `"limits"`, node.ID)
	var pay struct {
		Sent [][]string `json:"sent"`
	}
	_ = json.Unmarshal(e.Payload, &pay)
	if len(pay.Sent) != 1 || pay.Sent[0][0] != node.ID {
		t.Fatalf("budget_push sent = %v", pay.Sent)
	}
	dispatch := pay.Sent[0][1]
	eventually(t, 60*time.Second, "belai applied the push to its worker", func() bool {
		log, _ := os.ReadFile(h.rlog)
		return strings.Contains(string(log), "keleustes budget limits: 1 worker")
	})
	var dv struct {
		Status string `json:"status"`
		Kind   string `json:"kind"`
	}
	eventually(t, 30*time.Second, "the dispatch resolved", func() bool {
		d.json(&dv, "dispatch", dispatch)
		return dv.Status != "queued" && dv.Status != "delivered"
	})
	if dv.Kind != "budget_update" || dv.Status == "failed" {
		t.Fatalf("dispatch = %+v", dv)
	}
	// The worker's control file carries the lowered cap.
	var ctl []string
	_ = filepath.Walk(h.home, func(p string, _ os.FileInfo, _ error) error {
		if strings.HasSuffix(p, ".control.json") {
			ctl = append(ctl, p)
		}
		return nil
	})
	found := false
	for _, p := range ctl {
		if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), "limits") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no worker control file with limits under %s (%v)", h.home, ctl)
	}

	// The kill switch: a save pushes nothing, and the refusal is audited.
	k.kel("host", "stop", "--reason", "e2e budget drill")
	before := len(d.ledger("budget_push", ""))
	d.json(&b, "budget", `{"name":"E2E stopped","applies_to":"all","provider":"all","period":"month","limit_usd":3,"action_at_limit":"pause_run"}`)
	d.waitLedger("", "factory.refused", "budget_update")
	time.Sleep(2 * time.Second)
	if after := len(d.ledger("budget_push", "")); after != before {
		t.Fatalf("a budget push went out under the kill switch (%d -> %d)", before, after)
	}
	k.kel("host", "resume")
}

// TestKeleustesKnowledgeAcrossHosts (row 49): Keleustes asks the host to
// reindex its project (the host's own ingestion, through its classifier),
// then one search fans out as a knowledge_search job and the hit comes back
// naming the node. Under the kill switch the search is refused.
func TestKeleustesKnowledgeAcrossHosts(t *testing.T) {
	k := startKeleustes(t)
	d := driver(t, k)
	model := featuresModel(t)
	h := startFeatureRC(t, k, "f-knowledge", model.URL)
	vx := filepath.Join(h.project, ".vulnetix")
	if err := os.MkdirAll(vx, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vx, "memory.yaml"), []byte("notes: releases ship with the zephyrine pipeline\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	node := d.waitNode(h.label)
	var r struct{ Dispatch string }
	d.json(&r, "kb-reindex", node.ID, "project", h.project)
	eventually(t, 120*time.Second, "the host reindexed its project", func() bool {
		log, _ := os.ReadFile(h.rlog)
		return strings.Contains(string(log), "keleustes reindexed the project knowledge")
	})
	d.waitLedger("knowledge_reindex", "", node.ID)

	type hit struct {
		NodeID  string `json:"node_id"`
		Address string `json:"address"`
		Snippet string `json:"snippet"`
	}
	var rep struct {
		Hits    []hit      `json:"hits"`
		Nodes   [][]string `json:"nodes"`
		Refused *string    `json:"refused"`
	}
	eventually(t, 60*time.Second, "a knowledge hit from the host", func() bool {
		d.json(&rep, "kb-search", "zephyrine")
		return len(rep.Hits) > 0
	})
	if rep.Hits[0].NodeID != node.ID || !strings.Contains(rep.Hits[0].Address, "memory.yaml") {
		t.Fatalf("hit = %+v", rep.Hits[0])
	}
	if len(rep.Nodes) != 1 || rep.Nodes[0][1] != "ok" {
		t.Fatalf("nodes = %v", rep.Nodes)
	}
	d.waitLedger("knowledge_search", "", node.ID)

	k.kel("host", "stop", "--reason", "e2e knowledge drill")
	d.json(&rep, "kb-search", "zephyrine")
	if rep.Refused == nil || len(rep.Hits) != 0 {
		t.Fatalf("a search ran under the kill switch: %+v", rep)
	}
	k.kel("host", "resume")
}

// TestKeleustesAgentsDraft (row 54): the host drafts an AGENTS.md from its
// repository facts with its own model; Keleustes keeps it pending review
// with its hash, and nothing is written on the host.
func TestKeleustesAgentsDraft(t *testing.T) {
	k := startKeleustes(t)
	d := driver(t, k)
	model := featuresModel(t)
	h := startFeatureRC(t, k, "f-initdraft", model.URL)
	node := d.waitNode(h.label)
	var dr struct {
		Status string `json:"status"`
		Path   string `json:"path"`
		SHA    string `json:"sha256"`
		NodeID string `json:"node_id"`
		Cwd    string `json:"cwd"`
	}
	d.json(&dr, "init-draft", node.ID, h.project)
	if dr.Status != "pending" || dr.Path != "AGENTS.md" || len(dr.SHA) != 64 || dr.NodeID != node.ID {
		t.Fatalf("draft = %+v", dr)
	}
	if _, err := os.Stat(filepath.Join(h.project, "AGENTS.md")); err == nil {
		t.Fatal("the host wrote AGENTS.md; a draft writes nothing")
	}
	d.waitLedger("init_draft", "", node.ID, "pending")
}
