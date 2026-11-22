package agentstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Record is one native transcript line reduced to what a live tail shows:
// the harness's own record, mapped onto Keleustes's entry roles (user,
// assistant, tool, tool_result, system, error). The search adapters read the
// same pick functions through Turn, so one parser serves search and tail.
//
// Text is harness-written, untrusted content. Nothing here classifies or
// sanitizes it; a caller that sends it on scrubs and caps it.
type Record struct {
	Role       string
	Text       string
	At         time.Time
	NativeType string
	NativeID   string
	SessionID  string
	Cwd        string
	// Tool and ToolArgs name a tool call (args as JSON, capped).
	Tool     string
	ToolArgs string
	// Subagent marks a Claude sidechain line.
	Subagent bool
	// TurnEnd is set on the record that ends the assistant's turn.
	TurnEnd                   bool
	InputTokens, OutputTokens int64
	// CacheRead and CacheWrite are prompt-cache tokens; Model and Provider
	// name what the usage was spent on (empty when the line does not say).
	// MessageID groups the lines of one model message (Claude writes one line
	// per content block, each with the message's full usage).
	CacheRead, CacheWrite int64
	Model, Provider       string
	MessageID             string
	// msgRole and turnText are the search view (Turn): set only on the lines
	// the search adapters count as a turn.
	msgRole, turnText string
}

// MaxToolArgs caps a tool call's arguments in a Record.
const MaxToolArgs = 2 << 10

// Turn is the record as SearchSessions and ReadSession see it.
func (r Record) Turn() (Turn, bool) {
	if r.msgRole == "" {
		return Turn{}, false
	}
	return Turn{Role: r.msgRole, Text: r.turnText, At: r.At}, true
}

// PickLine reads one line of a JSONL dialect. ok is false for a line the
// dialect does not know or that is not JSON.
func PickLine(f Format, line []byte) (Record, bool) {
	switch f {
	case FormatJSONLClaude:
		return PickClaude(line)
	case FormatJSONLCodex:
		return PickCodex(line)
	case FormatJSONLPi:
		return PickPi(line)
	}
	return Record{}, false
}

type block struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	Thinking  string          `json:"thinking"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	Arguments json.RawMessage `json:"arguments"`
	Content   json.RawMessage `json:"content"`
	IsError   bool            `json:"is_error"`
}

func blocks(raw json.RawMessage) []block {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return nil
	}
	var out []block
	_ = json.Unmarshal(raw, &out)
	return out
}

func capArgs(raw json.RawMessage) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > MaxToolArgs {
		s = s[:MaxToolArgs] + "…"
	}
	return s
}

// rawText is a JSON string's value, or the text of a content array.
func rawText(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '"' {
		var s string
		_ = json.Unmarshal(raw, &s)
		return s
	}
	var parts []string
	for _, b := range blocks(raw) {
		if b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}

func num(raw json.RawMessage) int64 {
	var n json.Number
	if json.Unmarshal(raw, &n) != nil {
		return 0
	}
	i, _ := n.Int64()
	return i
}

type claudeLine struct {
	Type        string          `json:"type"`
	UUID        string          `json:"uuid"`
	SessionID   string          `json:"sessionId"`
	Cwd         string          `json:"cwd"`
	Timestamp   string          `json:"timestamp"`
	IsSidechain json.RawMessage `json:"isSidechain"`
	Summary     string          `json:"summary"`
	Message     struct {
		ID         string          `json:"id"`
		Model      string          `json:"model"`
		Role       string          `json:"role"`
		Content    json.RawMessage `json:"content"`
		StopReason string          `json:"stop_reason"`
		Usage      struct {
			Input      json.RawMessage `json:"input_tokens"`
			Output     json.RawMessage `json:"output_tokens"`
			CacheRead  json.RawMessage `json:"cache_read_input_tokens"`
			CacheWrite json.RawMessage `json:"cache_creation_input_tokens"`
		} `json:"usage"`
	} `json:"message"`
}

// PickClaude reads one Claude Code project transcript line.
func PickClaude(line []byte) (Record, bool) {
	var t claudeLine
	if json.Unmarshal(line, &t) != nil || t.Type == "" {
		return Record{}, false
	}
	r := Record{NativeType: t.Type, NativeID: t.UUID, SessionID: t.SessionID, Cwd: t.Cwd,
		At: parseTime(t.Timestamp), Subagent: string(bytes.TrimSpace(t.IsSidechain)) == "true", Role: "system"}
	if (t.Type == "user" || t.Type == "assistant") && t.Message.Role != "" {
		r.msgRole, r.turnText = t.Message.Role, contentText(t.Message.Content)
	}
	switch t.Type {
	case "user":
		r.Role, r.Text = "user", contentText(t.Message.Content)
		for _, b := range blocks(t.Message.Content) {
			if b.Type == "tool_result" {
				r.Role, r.Text = "tool_result", rawText(b.Content)
				if b.IsError {
					r.Role = "error"
				}
				break
			}
		}
	case "assistant":
		r.Role, r.Text = "assistant", contentText(t.Message.Content)
		for _, b := range blocks(t.Message.Content) {
			if b.Type == "tool_use" {
				r.Role, r.Tool, r.ToolArgs = "tool", b.Name, capArgs(b.Input)
				break
			}
		}
		r.TurnEnd = t.Message.StopReason == "end_turn"
		r.InputTokens, r.OutputTokens = num(t.Message.Usage.Input), num(t.Message.Usage.Output)
		r.CacheRead, r.CacheWrite = num(t.Message.Usage.CacheRead), num(t.Message.Usage.CacheWrite)
		r.Model, r.MessageID, r.Provider = t.Message.Model, t.Message.ID, "anthropic"
	case "summary":
		r.Text = t.Summary
	}
	return r, true
}

type codexLine struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Payload   struct {
		Type      string          `json:"type"`
		ID        string          `json:"id"`
		Cwd       string          `json:"cwd"`
		Role      string          `json:"role"`
		Content   json.RawMessage `json:"content"`
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Output    json.RawMessage `json:"output"`
		CallID    string          `json:"call_id"`
		Message   string          `json:"message"`
		Model     string          `json:"model"`
		Info      struct {
			Last struct {
				Cached json.RawMessage `json:"cached_input_tokens"`
				Input  json.RawMessage `json:"input_tokens"`
				Output json.RawMessage `json:"output_tokens"`
			} `json:"last_token_usage"`
		} `json:"info"`
	} `json:"payload"`
}

// PickCodex reads one Codex rollout line.
func PickCodex(line []byte) (Record, bool) {
	var t codexLine
	if json.Unmarshal(line, &t) != nil || t.Type == "" {
		return Record{}, false
	}
	p := t.Payload
	r := Record{NativeType: t.Type, At: parseTime(t.Timestamp), Role: "system"}
	if p.Type != "" {
		r.NativeType = t.Type + "." + p.Type
	}
	switch t.Type {
	case "session_meta":
		r.SessionID, r.Cwd, r.NativeType = p.ID, p.Cwd, t.Type
	case "turn_context":
		r.Model, r.NativeType = p.Model, t.Type
	case "response_item":
		switch p.Type {
		case "message":
			role := p.Role
			if role == "" {
				role = p.Type
			}
			r.msgRole, r.turnText = role, contentText(p.Content)
			r.Text = r.turnText
			switch role {
			case "user", "assistant":
				r.Role = role
			}
		case "function_call", "custom_tool_call", "local_shell_call":
			r.Role, r.Tool, r.ToolArgs, r.NativeID = "tool", p.Name, capArgs(p.Arguments), p.CallID
		case "function_call_output", "custom_tool_call_output":
			r.Role, r.NativeID = "tool_result", p.CallID
			// The output is a string, often itself {"output": ..., "metadata": ...}.
			r.Text = rawText(p.Output)
			var o struct {
				Output *string `json:"output"`
			}
			if raw := []byte(r.Text); r.Text == "" {
				if json.Unmarshal(p.Output, &o) == nil && o.Output != nil {
					r.Text = *o.Output
				}
			} else if json.Unmarshal(raw, &o) == nil && o.Output != nil {
				r.Text = *o.Output
			}
		}
	case "event_msg":
		switch p.Type {
		case "task_complete":
			r.TurnEnd = true
		case "token_count":
			r.InputTokens, r.OutputTokens = num(p.Info.Last.Input), num(p.Info.Last.Output)
			r.CacheRead, r.Provider = num(p.Info.Last.Cached), "openai"
		case "error":
			r.Role, r.Text = "error", p.Message
		}
	}
	return r, true
}

type piLine struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Cwd       string `json:"cwd"`
	Timestamp string `json:"timestamp"`
	Message   struct {
		Role       string          `json:"role"`
		Content    json.RawMessage `json:"content"`
		StopReason string          `json:"stopReason"`
		ToolName   string          `json:"toolName"`
		IsError    bool            `json:"isError"`
		Provider   string          `json:"provider"`
		Model      string          `json:"model"`
		Usage      struct {
			Input      json.RawMessage `json:"input"`
			Output     json.RawMessage `json:"output"`
			CacheRead  json.RawMessage `json:"cacheRead"`
			CacheWrite json.RawMessage `json:"cacheWrite"`
		} `json:"usage"`
	} `json:"message"`
}

// PickPi reads one pi session line.
func PickPi(line []byte) (Record, bool) {
	var t piLine
	if json.Unmarshal(line, &t) != nil || t.Type == "" {
		return Record{}, false
	}
	r := Record{NativeType: t.Type, NativeID: t.ID, At: parseTime(t.Timestamp), Role: "system"}
	switch t.Type {
	case "session":
		r.SessionID, r.Cwd = t.ID, t.Cwd
	case "message":
		m := t.Message
		if m.Role != "" {
			r.msgRole, r.turnText = m.Role, contentText(m.Content)
		}
		r.Text = contentText(m.Content)
		switch m.Role {
		case "user":
			r.Role = "user"
		case "assistant":
			r.Role = "assistant"
			for _, b := range blocks(m.Content) {
				if b.Type == "toolCall" {
					r.Role, r.Tool, r.ToolArgs = "tool", b.Name, capArgs(b.Arguments)
					break
				}
			}
			r.TurnEnd = m.StopReason != "" && m.StopReason != "toolUse"
			r.InputTokens, r.OutputTokens = num(m.Usage.Input), num(m.Usage.Output)
			r.CacheRead, r.CacheWrite = num(m.Usage.CacheRead), num(m.Usage.CacheWrite)
			r.Provider, r.Model = m.Provider, m.Model
		case "toolResult":
			r.Role, r.Tool, r.Text = "tool_result", m.ToolName, rawText(m.Content)
			if m.IsError {
				r.Role = "error"
			}
		}
	}
	return r, true
}

// GeminiRecords reads a Gemini CLI chat file (one JSON document the CLI
// rewrites each turn) into records, in message order.
func GeminiRecords(doc []byte) ([]Record, error) {
	var d struct {
		SessionID string `json:"sessionId"`
		Messages  []struct {
			ID        string          `json:"id"`
			Type      string          `json:"type"`
			Content   json.RawMessage `json:"content"`
			Timestamp string          `json:"timestamp"`
			ToolCalls []struct {
				Name   string          `json:"name"`
				Args   json.RawMessage `json:"args"`
				Status string          `json:"status"`
			} `json:"toolCalls"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(doc, &d); err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(d.Messages))
	for i, m := range d.Messages {
		r := Record{NativeType: m.Type, NativeID: m.ID, SessionID: d.SessionID, At: parseTime(m.Timestamp),
			Role: "system", Text: rawText(m.Content)}
		switch m.Type {
		case "user":
			r.Role = "user"
		case "gemini", "model", "assistant":
			r.Role = "assistant"
			pending := false
			for _, c := range m.ToolCalls {
				if r.Tool == "" {
					r.Tool, r.ToolArgs = c.Name, capArgs(c.Args)
				}
				pending = pending || (c.Status != "" && c.Status != "success" && c.Status != "error" && c.Status != "cancelled")
			}
			if r.Tool != "" && strings.TrimSpace(r.Text) == "" {
				r.Role = "tool"
			}
			r.TurnEnd = i == len(d.Messages)-1 && !pending
		case "error":
			r.Role = "error"
		}
		out = append(out, r)
	}
	return out, nil
}

// AiderRecords reads an aider chat history (Markdown, append-only): a
// "#### " line is the person's prompt, the rest is aider's answer, and a
// "# aider chat started" line opens a session.
func AiderRecords(md string) []Record {
	var out []Record
	var cur *Record
	flush := func() {
		if cur != nil {
			cur.Text = strings.TrimSpace(cur.Text)
			if cur.Text != "" {
				out = append(out, *cur)
			}
			cur = nil
		}
	}
	for _, line := range strings.Split(md, "\n") {
		switch {
		case strings.HasPrefix(line, "# aider chat started"):
			flush()
			out = append(out, Record{Role: "system", NativeType: "session", Text: strings.TrimPrefix(line, "# ")})
		case strings.HasPrefix(line, "#### "):
			if cur == nil || cur.Role != "user" {
				flush()
				cur = &Record{Role: "user", NativeType: "user"}
			}
			cur.Text += strings.TrimPrefix(line, "#### ") + "\n"
		default:
			if cur == nil || cur.Role != "assistant" {
				if strings.TrimSpace(line) == "" {
					continue
				}
				flush()
				cur = &Record{Role: "assistant", NativeType: "assistant"}
			}
			cur.Text += line + "\n"
		}
	}
	flush()
	return out
}

func claudeTurn(line []byte) (Turn, bool) {
	r, ok := PickClaude(line)
	if !ok {
		return Turn{}, false
	}
	return r.Turn()
}

func codexTurn(line []byte) (Turn, bool) {
	r, ok := PickCodex(line)
	if !ok {
		return Turn{}, false
	}
	return r.Turn()
}

func piTurn(line []byte) (Turn, bool) {
	r, ok := PickPi(line)
	if !ok {
		return Turn{}, false
	}
	return r.Turn()
}

// SQLiteSessions lists the sessions stored in a goose or opencode database,
// read through the read-only sqlite3 binary at sqlite.
func SQLiteSessions(sqlite string, f Format, db string) ([]Source, error) {
	switch f {
	case FormatSQLiteGoose:
		return gooseAdapter{sqlite: sqlite}.Sources(db)
	case FormatSQLiteOpenCode:
		return opencodeAdapter{sqlite: sqlite}.Sources(db)
	}
	return nil, errUnknownFormat
}

// SQLiteTurns reads every turn of one stored session, in order.
func SQLiteTurns(sqlite string, src Source) ([]Turn, error) {
	switch src.Format {
	case FormatSQLiteGoose:
		return gooseAdapter{sqlite: sqlite}.Turns(src, 0, 0)
	case FormatSQLiteOpenCode:
		return opencodeAdapter{sqlite: sqlite}.Turns(src, 0, 0)
	}
	return nil, errUnknownFormat
}

var errUnknownFormat = errors.New("agentstore: not a SQLite dialect")
