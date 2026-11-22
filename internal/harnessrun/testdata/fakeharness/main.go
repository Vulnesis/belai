// Command fakeharness stands in for a third-party TUI harness in tests. It
// turns on bracketed paste, reads prompts from its terminal, and writes a
// Claude-shaped native transcript under $HOME.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

func main() {
	sid, mcpFile := "", ""
	for i, a := range os.Args {
		if a == "--version" {
			fmt.Println("9.9.9 (fake harness)")
			return
		}
		if a == "--session-id" && i+1 < len(os.Args) {
			sid = os.Args[i+1]
		}
		if a == "--resume" && i+1 < len(os.Args) {
			sid = os.Args[i+1]
			if os.Getenv("FAKE_FORK") != "" {
				sid = "f0f0f0f0-0000-4000-8000-000000000001"
			}
		}
		if a == "--mcp-config" && i+1 < len(os.Args) {
			mcpFile = os.Args[i+1]
		}
	}
	if os.Getenv("FAKE_IGNORE_EXIT") != "" {
		signal.Ignore(syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	}
	if f := os.Getenv("FAKE_ENV_FILE"); f != "" {
		var names []string
		for _, kv := range os.Environ() {
			k, _, _ := strings.Cut(kv, "=")
			names = append(names, k)
		}
		sort.Strings(names)
		_ = os.WriteFile(f, []byte(strings.Join(names, "\n")), 0o600)
	}
	if v := os.Getenv("FAKE_ECHO"); v != "" {
		fmt.Printf("key is %s\n", os.Getenv(v))
	}
	cwd, _ := os.Getwd()
	slug := strings.NewReplacer("/", "-", ".", "-").Replace(cwd)
	dir := filepath.Join(os.Getenv("HOME"), ".claude", "projects", slug)
	_ = os.MkdirAll(dir, 0o700)
	tr, _ := os.OpenFile(filepath.Join(dir, sid+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	write := func(v map[string]any) {
		v["sessionId"], v["cwd"], v["timestamp"] = sid, cwd, time.Now().UTC().Format(time.RFC3339Nano)
		b, _ := json.Marshal(v)
		_, _ = tr.Write(append(b, '\n'))
	}
	raw, _ := os.OpenFile(os.Getenv("FAKE_RAW"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	rd := bufio.NewReader(os.Stdin)
	if os.Getenv("FAKE_TRUST") != "" {
		fmt.Print("Quick safety check: do you trust this folder?\r\n\x1b[1C❯ No, exit\r\n   Yes, I trust this folder\r\n")
		line, err := rd.ReadString('\n')
		if err != nil || !strings.Contains(line, "\x1b[B") {
			os.Exit(1)
		}
		fmt.Print("\x1b[2J\x1b[Htrusted\r\n")
	}
	if os.Getenv("FAKE_NOPASTE") == "" {
		fmt.Print("\x1b[?2004h")
	}
	fmt.Print("> ")
	n := 0
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		if raw != nil {
			_, _ = raw.WriteString(fmt.Sprintf("%q\n", line))
		}
		line = strings.TrimRight(line, "\r\n")
		text := strings.ReplaceAll(strings.ReplaceAll(line, "\x1b[200~", ""), "\x1b[201~", "")
		if text == "/exit" {
			if os.Getenv("FAKE_IGNORE_EXIT") != "" {
				continue
			}
			return
		}
		if strings.TrimSpace(text) == "" || len(text) == 1 {
			fmt.Printf("key %q\n", text)
			continue
		}
		n++
		write(map[string]any{"type": "user", "uuid": fmt.Sprintf("u%d", n), "message": map[string]any{"role": "user", "content": text}})
		fmt.Printf("working on %q\n", text)
		if os.Getenv("FAKE_NO_REPLY") != "" {
			fmt.Print("> ")
			continue
		}
		time.Sleep(50 * time.Millisecond)
		reply := "done " + text
		if rest, ok := strings.CutPrefix(text, "a2a "); ok {
			reply = "a2a-result: " + mcpCall(mcpFile, rest)
		}
		if strings.Contains(text, "ask me") {
			reply = "I can do A or B.\n\nWhich option would you like, A or B?"
		}
		if v := os.Getenv("FAKE_KEY_ENV"); v != "" && text == "show key" {
			reply = "key-present: " + fmt.Sprint(os.Getenv(v) != "")
		}
		fmt.Printf("working on %q\n", text)
		time.Sleep(50 * time.Millisecond)
		write(map[string]any{"type": "assistant", "uuid": fmt.Sprintf("a%d", n), "message": map[string]any{"role": "assistant",
			"content": []map[string]any{{"type": "text", "text": reply}}, "stop_reason": "end_turn",
			"usage": map[string]any{"input_tokens": 10, "output_tokens": 2}}})
		fmt.Print("> ")
	}
}

// mcpCall runs the belai bridge named in the --mcp-config file and calls one
// tool: "peers", "inbox", or "send <to> <text>".
func mcpCall(file, cmd string) string {
	var cfg struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	b, err := os.ReadFile(file)
	if err != nil || json.Unmarshal(b, &cfg) != nil {
		return "no mcp config"
	}
	srv, ok := cfg.MCPServers["belai"]
	if !ok {
		return "no belai server"
	}
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return "no tool"
	}
	args := map[string]any{}
	if f[0] == "send" && len(f) >= 3 {
		args["to"], args["text"] = f[1], strings.Join(f[2:], " ")
	}
	c := exec.Command(srv.Command, srv.Args...)
	c.Env = os.Environ()
	in, _ := c.StdinPipe()
	out, _ := c.StdoutPipe()
	if err := c.Start(); err != nil {
		return "bridge: " + err.Error()
	}
	defer func() { _ = in.Close(); _ = c.Wait() }()
	call, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]any{"name": f[0], "arguments": args}})
	fmt.Fprintln(in, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`)
	fmt.Fprintln(in, string(call))
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		var r struct {
			ID     int `json:"id"`
			Result struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		if json.Unmarshal(sc.Bytes(), &r) == nil && r.ID == 2 && len(r.Result.Content) > 0 {
			return r.Result.Content[0].Text
		}
	}
	return "no answer"
}
