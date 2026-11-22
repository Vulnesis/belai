package harnessrun

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vulnetix/belai/internal/a2a"
	"github.com/vulnetix/belai/internal/a2alink"
	"github.com/vulnetix/belai/internal/agent"
	"github.com/vulnetix/belai/internal/sanitize"
)

// MaxA2AText caps a message the harness sends (as tools.MaxA2AText).
const MaxA2AText = 4 << 10

// MaxHook caps a hook payload.
const MaxHook = 64 << 10

// Peer is one agent the harness may message.
type Peer struct {
	ID      string `json:"id"`
	Display string `json:"display"`
	Profile string `json:"profile,omitempty"`
	Repo    string `json:"repo,omitempty"`
	Branch  string `json:"branch,omitempty"`
	Seen    int64  `json:"seenAtMs,omitempty"`
}

// A2A is the session's A2A endpoint (an a2alink.Link through LinkA2A).
type A2A interface {
	Peers() []Peer
	Send(ctx context.Context, to, text string) (id, display string, err error)
	Reply(ctx context.Context, messageID, text string) (string, error)
	Ack(ctx context.Context, messageID, decision, reason string) (bool, error)
	Blackout() bool
}

// Message is one received peer message, already classified KindPeer by
// a2alink before it reaches the bridge.
type Message struct {
	Seq       int64  `json:"seq"`
	Kind      string `json:"kind"` // message, reply
	MessageID string `json:"messageId,omitempty"`
	ContextID string `json:"contextId,omitempty"`
	From      string `json:"from"`
	Text      string `json:"text"`
	At        int64  `json:"atMs"`
}

type bridge struct {
	s   *Session
	a2a A2A

	mu    sync.Mutex
	inbox []Message
	seq   int64
}

func newBridge(s *Session, a A2A) *bridge { return &bridge{s: s, a2a: a} }

// deliver queues a classified message and types the notice line.
func (b *bridge) deliver(m Message) {
	b.mu.Lock()
	b.seq++
	m.Seq, m.At = b.seq, time.Now().UnixMilli()
	b.inbox = append(b.inbox, m)
	if len(b.inbox) > 256 {
		b.inbox = b.inbox[len(b.inbox)-256:]
	}
	b.mu.Unlock()
	if b.a2a != nil && b.a2a.Blackout() {
		return
	}
	b.s.notify()
}

// listen serves the per-session socket: hook events from belai harness-hook
// and the A2A tools from belai a2a-mcp. One JSON request line, one JSON
// response line, per connection.
func (b *bridge) listen(path string) (net.Listener, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go b.serve(c)
		}
	}()
	return ln, nil
}

// Request is one socket request.
type Request struct {
	Op        string          `json:"op"`
	Event     string          `json:"event,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	To        string          `json:"to,omitempty"`
	Text      string          `json:"text,omitempty"`
	MessageID string          `json:"messageId,omitempty"`
	Decision  string          `json:"decision,omitempty"`
	Reason    string          `json:"reason,omitempty"`
	After     int64           `json:"after,omitempty"`
}

func (b *bridge) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(c, MaxHook+4096)).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var req Request
	var out any
	if json.Unmarshal(line, &req) != nil {
		out = map[string]string{"error": "bad request"}
	} else {
		out = b.handle(context.Background(), req)
	}
	resp, _ := json.Marshal(out)
	_, _ = c.Write(append(resp, '\n'))
}

func errOut(msg string) map[string]string { return map[string]string{"error": msg} }

func (b *bridge) handle(ctx context.Context, req Request) any {
	s := b.s
	if req.Op == "hook" {
		s.hook(req.Event, req.Payload)
		return map[string]bool{"ok": true}
	}
	if b.a2a == nil {
		return errOut("A2A is not available in this session")
	}
	stopped, _ := s.c.Stopped()
	switch req.Op {
	case "peers":
		return map[string]any{"peers": b.a2a.Peers()}
	case "inbox":
		if b.a2a.Blackout() {
			return map[string]any{"messages": []any{}, "state": "a2a blackout"}
		}
		b.mu.Lock()
		var items []any
		for _, m := range b.inbox {
			if m.Seq > req.After {
				items = append(items, map[string]any{"untrusted_peer_message": m})
			}
		}
		b.mu.Unlock()
		if items == nil {
			items = []any{}
		}
		return map[string]any{"messages": items}
	case "send", "reply":
		switch {
		case stopped:
			s.audit("a2a_refused", "factory stopped", nil)
			return errOut("refused: the factory is stopped")
		case b.a2a.Blackout():
			s.audit("a2a_refused", "a2a blackout", nil)
			return errOut("refused: a2a blackout")
		case len(req.Text) > MaxA2AText:
			return errOut("a message carries at most 4096 bytes")
		case strings.TrimSpace(req.Text) == "":
			return errOut("the message has no text")
		}
		if req.Op == "reply" {
			id, err := b.a2a.Reply(ctx, sanitize.Ident(req.MessageID, 64), req.Text)
			if err != nil {
				return errOut(err.Error())
			}
			return map[string]string{"messageId": id}
		}
		id, to, err := b.a2a.Send(ctx, strings.TrimSpace(req.To), req.Text)
		if err != nil {
			return errOut(err.Error())
		}
		return map[string]string{"messageId": id, "to": to}
	case "ack":
		if stopped || b.a2a.Blackout() {
			return errOut("refused: A2A is held")
		}
		sent, err := b.a2a.Ack(ctx, sanitize.Ident(req.MessageID, 64), req.Decision, sanitize.Line(req.Reason, 140))
		if err != nil {
			return errOut(err.Error())
		}
		return map[string]bool{"sent": sent}
	}
	return errOut("unknown op")
}

// hook takes one harness hook event. The payload is harness text; only the
// event name and, for a submitted prompt, its text (for confirmation) are
// used.
func (s *Session) hook(event string, payload json.RawMessage) {
	switch event {
	case "Stop":
		s.idle()
	case "UserPromptSubmit":
		var p struct {
			Prompt    string `json:"prompt"`
			SessionID string `json:"session_id"`
		}
		if json.Unmarshal(payload, &p) == nil && p.SessionID != "" {
			s.checkContinuity(p.SessionID)
		}
		if json.Unmarshal(payload, &p) == nil && p.Prompt != "" {
			select {
			case s.userSeen <- "\x00" + p.Prompt:
			default:
			}
		}
	case "Notification":
		var p struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(payload, &p) == nil && p.Message != "" {
			s.own("system", "harness_waiting", "waiting: "+sanitize.Line(p.Message, 300), nil)
		}
	}
}

// ---- a2alink adapter -------------------------------------------------------

// LinkSession is the a2alink.Session a harness session attaches: a reply is
// queued for the harness's inbox tool; a direct message is queued too and
// answered with a fixed harness reply, since the third-party model answers
// in its own time with the send tool. Both arrive here only after a2alink
// classified them (KindPeer); a withheld one never does.
type LinkSession struct{ b *bridge }

var _ a2alink.Session = LinkSession{}

// DeliveredReply is the fixed reply to a message handed to a harness.
const DeliveredReply = "Delivered to a third-party harness session. Its agent reads it with its belai inbox tool and answers with a separate message."

// Peer queues a classified reply. A broadcast's directive is not queued.
func (l LinkSession) Peer(n agent.PeerNote) bool {
	if l.b == nil || len(n.Attachments) == 0 {
		return true
	}
	for _, a := range n.Attachments {
		l.b.deliver(Message{Kind: "reply", From: sanitize.Line(a.Label, 120), Text: a.Body})
	}
	return true
}

// SideReply queues a classified direct message.
func (l LinkSession) SideReply(_ context.Context, in agent.SideReplyInput) (agent.SideReplyResult, error) {
	if l.b == nil {
		return agent.SideReplyResult{}, errors.New("no harness session")
	}
	l.b.deliver(Message{Kind: "message", MessageID: in.MessageID, ContextID: in.ContextID, From: in.From, Text: in.Question})
	return agent.SideReplyResult{Reply: DeliveredReply}, nil
}

// SetFilesHook does nothing: belai cannot see a harness's file changes.
func (LinkSession) SetFilesHook(func([]string)) {}

// AttachLink binds an open a2alink.Link to the session's bridge. Call after
// Run has started (Session is passed through OnStart).
func (s *Session) AttachLink(l *a2alink.Link) {
	if l == nil || s.bridge == nil {
		return
	}
	l.SetRecorder(func(typ, content string, meta map[string]any) {
		s.own(typ, typ, content, meta)
	})
	l.Attach(LinkSession{b: s.bridge})
}

// LinkA2A is A2A over an a2alink.Link's node. Directory, when set, lists the
// live sessions Keleustes knows (Board.A2APeers), so the harness may message
// a peer whose broadcast it has not seen.
type LinkA2A struct {
	L         *a2alink.Link
	Directory func(ctx context.Context) ([]Peer, error)
}

// Peers lists the node's mailbox.
func (x LinkA2A) Peers() []Peer {
	var out []Peer
	seen := map[string]bool{}
	for _, p := range x.L.Node().Mailbox().Peers() {
		out = append(out, Peer{ID: p.Card.ID, Display: p.Card.Display(), Profile: p.Card.Profile, Repo: p.Work.Repo,
			Branch: p.Work.Branch, Seen: p.Seen.UnixMilli()})
		seen[p.Card.ID] = true
	}
	self := ":" + x.L.Node().Self().SessionID
	for _, p := range x.directory(context.Background()) {
		if !seen[p.ID] && !strings.HasSuffix(p.ID, self) {
			out = append(out, p)
		}
	}
	return out
}

// Send sends a direct message.
func (x LinkA2A) Send(ctx context.Context, to, text string) (string, string, error) {
	if _, ok := x.L.Node().Mailbox().Peer(to); !ok {
		for _, p := range x.directory(ctx) {
			if p.ID == to {
				x.admitPeer(p)
			}
		}
	}
	return x.L.Hub().A2AMessage(ctx, to, text)
}

// Reply answers a received message.
func (x LinkA2A) Reply(_ context.Context, id, text string) (string, error) {
	q, ok := x.L.Node().Mailbox().Message(id)
	if !ok {
		return "", errors.New("no such message")
	}
	env, err := x.L.Node().Reply(q, text)
	return env.MessageID, err
}

// Ack acknowledges a message.
func (x LinkA2A) Ack(ctx context.Context, id, decision, reason string) (bool, error) {
	return x.L.Hub().A2AAck(ctx, id, decision, reason)
}

// Blackout reports the A2A blackout.
func (x LinkA2A) Blackout() bool { return x.L.Node().State() == a2a.StateBlackout }

func (x LinkA2A) directory(ctx context.Context) []Peer {
	if x.Directory == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	ps, err := x.Directory(ctx)
	if err != nil {
		return nil
	}
	return ps
}

// admitPeer records a directory peer in the mailbox as a card that takes
// messages, so A2AMessage can address it. Only identifier-shaped ids pass;
// every field is cleaned by the mailbox's envelope rules on send.
func (x LinkA2A) admitPeer(p Peer) {
	host, sid, ok := strings.Cut(p.ID, ":")
	if !ok || !a2a.ValidAgentID(p.ID) {
		return
	}
	card := a2a.AgentCard{ID: p.ID, HostID: host, SessionID: sid, Capabilities: []string{a2a.CapMessage}}
	x.L.Node().Mailbox().Observe(a2a.Envelope{Kind: a2a.KindBroadcast, Agent: card,
		Work: a2a.Work{Repo: p.Repo, Branch: p.Branch}}, time.Now(), false)
}
