package agentstore

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

func picks(t *testing.T, f Format, path string) []Record {
	t.Helper()
	fh, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	var out []Record
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		r, ok := PickLine(f, sc.Bytes())
		if !ok {
			t.Fatalf("line not picked: %s", sc.Text())
		}
		out = append(out, r)
	}
	return out
}

func roles(rs []Record) string {
	var b []string
	for _, r := range rs {
		b = append(b, r.Role)
	}
	return strings.Join(b, ",")
}

func TestPickClaude(t *testing.T) {
	rs := picks(t, FormatJSONLClaude, "testdata/claude-live.jsonl")
	if got := roles(rs); got != "system,user,tool,tool_result,assistant,system,assistant" {
		t.Fatal(got)
	}
	if rs[0].Text != "Fix flaky test" {
		t.Errorf("summary: %q", rs[0].Text)
	}
	if rs[2].Tool != "Bash" || !strings.Contains(rs[2].ToolArgs, "ls crates") || rs[2].InputTokens != 120 || rs[2].TurnEnd {
		t.Errorf("tool_use: %+v", rs[2])
	}
	if rs[3].Text != "kls-core\nkls-ui" {
		t.Errorf("tool_result: %q", rs[3].Text)
	}
	if !rs[4].Subagent {
		t.Error("sidechain not marked")
	}
	if !rs[6].TurnEnd || rs[6].NativeID != "u6" || rs[6].SessionID != "s1" || rs[6].At.IsZero() {
		t.Errorf("end: %+v", rs[6])
	}
}

func TestPickCodex(t *testing.T) {
	rs := picks(t, FormatJSONLCodex, "testdata/codex-live.jsonl")
	if got := roles(rs); got != "system,system,system,user,tool,tool_result,assistant,system,system" {
		t.Fatal(got)
	}
	if rs[0].SessionID != "c1" || rs[0].Cwd != "/w" {
		t.Errorf("meta: %+v", rs[0])
	}
	if rs[4].Tool != "shell" || rs[5].Text != "kls-core\n" {
		t.Errorf("tool: %+v %+v", rs[4], rs[5])
	}
	if rs[7].InputTokens != 50 || !rs[8].TurnEnd {
		t.Errorf("usage/end: %+v %+v", rs[7], rs[8])
	}
}

func TestPickPi(t *testing.T) {
	rs := picks(t, FormatJSONLPi, "testdata/pi-live.jsonl")
	if got := roles(rs); got != "system,system,user,tool,tool_result,system,assistant" {
		t.Fatal(got)
	}
	if rs[3].Tool != "bash" || rs[3].TurnEnd || !rs[6].TurnEnd || rs[6].OutputTokens != 3 {
		t.Errorf("pi: %+v %+v", rs[3], rs[6])
	}
}

func TestPickTurnMatchesSearch(t *testing.T) {
	// The search view of a picked line is what the adapters return.
	for _, c := range []struct {
		f    Format
		path string
		a    Adapter
	}{
		{FormatJSONLClaude, "testdata/claude-live.jsonl", claudeAdapter{}},
		{FormatJSONLCodex, "testdata/codex-live.jsonl", codexAdapter{}},
		{FormatJSONLPi, "testdata/pi-live.jsonl", piAdapter{}},
	} {
		want, err := c.a.Turns(Source{Path: c.path, Format: c.f}, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		var got []Turn
		for _, r := range picks(t, c.f, c.path) {
			if tu, ok := r.Turn(); ok {
				got = append(got, tu)
			}
		}
		if len(got) != len(want) {
			t.Fatalf("%s: %d turns, adapter %d", c.f, len(got), len(want))
		}
		for i := range got {
			if got[i].Role != want[i].Role || got[i].Text != want[i].Text {
				t.Errorf("%s turn %d: %+v vs %+v", c.f, i, got[i], want[i])
			}
		}
	}
}

func TestPickRefusesJunk(t *testing.T) {
	for _, f := range []Format{FormatJSONLClaude, FormatJSONLCodex, FormatJSONLPi} {
		if _, ok := PickLine(f, []byte("not json")); ok {
			t.Errorf("%s picked junk", f)
		}
	}
}

func TestGeminiRecords(t *testing.T) {
	doc := `{"sessionId":"g1","messages":[
	 {"id":"1","type":"user","content":"hi","timestamp":"2026-11-21T10:00:00Z"},
	 {"id":"2","type":"gemini","content":"","toolCalls":[{"name":"read_file","args":{"p":"a"},"status":"success"}]},
	 {"id":"3","type":"gemini","content":"done"}]}`
	rs, err := GeminiRecords([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if got := roles(rs); got != "user,tool,assistant" || !rs[2].TurnEnd || rs[1].Tool != "read_file" {
		t.Fatalf("%s %+v", got, rs)
	}
	if _, err := GeminiRecords([]byte("nope")); err == nil {
		t.Fatal("junk parsed")
	}
}

func TestAiderRecords(t *testing.T) {
	md := "# aider chat started at 2026-11-21\n\n#### list the crates\n#### please\n\nkls-core\nkls-ui\n\n#### thanks\n"
	rs := AiderRecords(md)
	if got := roles(rs); got != "system,user,assistant,user" {
		t.Fatalf("%s %+v", got, rs)
	}
	if rs[1].Text != "list the crates\nplease" || rs[2].Text != "kls-core\nkls-ui" {
		t.Fatalf("%+v", rs)
	}
}

func TestPickUsage(t *testing.T) {
	c := picks(t, FormatJSONLClaude, "testdata/claude-live.jsonl")
	if c[2].CacheRead != 3000 || c[2].CacheWrite != 40 || c[2].Provider != "anthropic" {
		t.Errorf("claude usage: %+v", c[2])
	}
	if c[6].Model != "claude-opus-4-1" || c[6].MessageID != "msg_2" {
		t.Errorf("claude model: %+v", c[6])
	}
	x := picks(t, FormatJSONLCodex, "testdata/codex-live.jsonl")
	if x[1].Model != "gpt-5.1-codex" || x[7].Provider != "openai" {
		t.Errorf("codex: %+v %+v", x[1], x[7])
	}
	p := picks(t, FormatJSONLPi, "testdata/pi-live.jsonl")
	if p[6].Model != "claude-x" || p[6].CacheRead != 7 {
		t.Errorf("pi: %+v", p[6])
	}
}
