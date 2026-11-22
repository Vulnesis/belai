package factorylink

import (
	"google.golang.org/grpc"

	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vulnetix/belai/internal/a2a"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sessionsync"
	"google.golang.org/protobuf/proto"
)

// A2ARelay carries cross-host A2A through Keleustes: it is the a2a.Relay's
// client for outbound envelopes (A2ASend) and runs its inbound stream
// (A2AReceive). The relay itself (de-duplication, the age limit, the
// blackout, the audit) is the website's code unchanged.
//
// Keleustes names an agent "<nodeId>:<sessionId>". An envelope this host
// sends goes out from "<this nodeId>:<sessionId>" with the whole belai
// envelope in meta_json; one received from another node is handed to the
// relay with its Agent Card's host set to the sending node, so the agent's
// id on this host is its Keleustes id and a reply addressed to it goes back
// through Keleustes unchanged. Envelopes from this node are skipped (the
// local bus already carried them).
//
// Received text is remote content: the relay cleans the envelope
// (a2a.Envelope.Clean) and the receiving harness classifies its text parts
// (KindPeer) before any model reads them. No exemption.
type A2ARelay struct {
	c *Client

	mu sync.Mutex
	// state polls Board.State; swapped in tests.
	stateEvery time.Duration
	host       string
}

var _ a2a.RelayClient = (*A2ARelay)(nil)

// NewA2ARelay builds the relay client on c.
func NewA2ARelay(c *Client) *A2ARelay { return &A2ARelay{c: c, stateEvery: time.Minute} }

// ActiveA2A returns the relay client for this host's active, unrevoked
// profile, or ErrNoProfile.
func ActiveA2A(home string) (*A2ARelay, error) {
	c, err := activeClient(home)
	if err != nil {
		return nil, err
	}
	return NewA2ARelay(c), nil
}

// Close drops the connection.
func (r *A2ARelay) Close() error { return r.c.Close() }

// AgentID is a session's agent id on Keleustes.
func (r *A2ARelay) AgentID(sessionID string) string { return r.c.Profile().NodeID + ":" + sessionID }

// blackoutRefusal is what Keleustes says when it holds an envelope back.
const blackoutRefusal = "a2a blackout"

// PostA2A sends a batch of this process's envelopes. A blackout refusal is
// reported as Blackout, which stops the relay.
func (r *A2ARelay) PostA2A(ctx context.Context, _ string, envelopes []json.RawMessage) (sessionsync.A2APostResult, error) {
	var res sessionsync.A2APostResult
	for _, raw := range envelopes {
		var env a2a.Envelope
		if json.Unmarshal(raw, &env) != nil || env.Agent.SessionID == "" {
			continue
		}
		pb := &nodev1.A2AEnvelope{
			Id: env.MessageID, From: r.AgentID(env.Agent.SessionID), To: env.To,
			ThreadId: env.ContextID, Text: env.Text(), AtMs: env.TS, MetaJson: string(raw),
		}
		if !env.Directed() {
			pb.To = "" // a broadcast reaches every agent
		} else if env.To == OwnerBelaiID {
			pb.To = OwnerAgent // a reply to the Keleustes owner
		} else if h, s, ok := strings.Cut(env.To, ":"); ok && h == r.hostID() {
			pb.To = r.AgentID(s) // a local agent, by its Keleustes id
		}
		out, err := r.c.A2ASend(ctx, pb)
		if err != nil {
			return res, mapErr(err)
		}
		if out.GetRefused() == blackoutRefusal {
			res.Blackout = true
			return res, nil
		}
		if out.GetDelivered() {
			res.Accepted++
		}
	}
	return res, nil
}

// Receive streams the envelopes addressed to this process's session into
// relay until ctx ends. It follows the session (session names it; the stream
// is reopened when it changes), stops during a blackout, and reads
// Board.State at the start and every minute so a blackout reaches a process
// that does not own the node link.
func (r *A2ARelay) Receive(ctx context.Context, relay *a2a.Relay, session func() string) {
	after := r.loadCursor()
	backoff := time.Second
	lastState := time.Time{}
	for ctx.Err() == nil {
		if time.Since(lastState) >= r.stateEvery {
			lastState = time.Now()
			if ctl, err := RefreshControl(ctx, r.c); err == nil {
				relay.SetBlackout(ctl.A2ABlackout)
			}
		}
		sid := session()
		if relay.Blackout() || sid == "" {
			if !sleepCtx(ctx, 5*time.Second) {
				return
			}
			continue
		}
		next, got, err := r.receiveOnce(ctx, relay, sid, after, func() bool {
			return relay.Blackout() || session() != sid || time.Since(lastState) >= r.stateEvery
		})
		if next > after {
			after = next
			r.saveCursor(after)
		}
		if got {
			backoff = time.Second
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			if !sleepCtx(ctx, backoff) {
				return
			}
			backoff = min(2*backoff, 30*time.Second)
		}
	}
}

// receiveOnce holds one stream until it ends, fails or stop says so (checked
// every second). It returns the highest seq delivered.
func (r *A2ARelay) receiveOnce(ctx context.Context, relay *a2a.Relay, sid string, after uint64, stop func() bool) (uint64, bool, error) {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := r.c.A2AReceive(sctx, []string{r.AgentID(sid)}, after)
	if err != nil {
		return after, false, err
	}
	watched := make(chan struct{})
	// The watcher has ended before this returns, so stop never runs
	// alongside the caller.
	defer func() { cancel(); <-watched }()
	go func() {
		defer close(watched)
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case <-t.C:
				if stop() {
					cancel()
					return
				}
			}
		}
	}()
	got := false
	for {
		e, err := st.Recv()
		if err != nil {
			if sctx.Err() != nil {
				return after, got, nil
			}
			return after, got, err
		}
		got = true
		if e.GetSeq() > after {
			after = e.GetSeq()
		}
		if item, ok := r.inbound(e); ok {
			relay.Deliver([]sessionsync.A2AItem{item})
		}
	}
}

// inbound turns a Keleustes envelope into the relay's item. The item's seq
// is left zero: Keleustes's cursor is kept apart from the website's.
func (r *A2ARelay) inbound(e *nodev1.A2AEnvelope) (sessionsync.A2AItem, bool) {
	if e.GetFrom() == OwnerAgent {
		// The owner has no uuid-shaped id; on this host it is a fixed reserved
		// agent, and its text is classified (KindPeer) like any peer's.
		e = proto.Clone(e).(*nodev1.A2AEnvelope)
		e.From = OwnerBelaiID
	}
	node, sess, ok := strings.Cut(e.GetFrom(), ":")
	if !ok || node == "" || sess == "" || node == r.c.Profile().NodeID {
		return sessionsync.A2AItem{}, false
	}
	var env a2a.Envelope
	if e.GetMetaJson() == "" || json.Unmarshal([]byte(e.GetMetaJson()), &env) != nil || env.Kind == "" {
		// Not a belai envelope: a plain message to one of this host's agents.
		if e.GetTo() == "" || strings.TrimSpace(e.GetText()) == "" {
			return sessionsync.A2AItem{}, false
		}
		env = a2a.Envelope{Kind: a2a.KindMessage, To: e.GetTo(), Parts: []a2a.Part{{Text: e.GetText()}}}
		env.MessageID = e.GetId()
		if !a2a.ValidMessageID(env.MessageID) {
			env.MessageID = derivedMessageID(e.GetId(), e.GetFrom())
		}
		if a2a.ValidMessageID(e.GetThreadId()) {
			env.ContextID = e.GetThreadId()
		}
		env.TS = e.GetAtMs()
	}
	// An agent of this host is addressed by its Keleustes id; the local bus
	// knows it by this host's id.
	if h, s, ok := strings.Cut(env.To, ":"); ok && h == r.c.Profile().NodeID {
		env.To = r.hostID() + ":" + s
	}
	// The sender is who Keleustes authenticated, whatever the envelope says.
	env.Agent.HostID, env.Agent.SessionID, env.Agent.ID = node, sess, ""
	if env.TS == 0 {
		env.TS = e.GetAtMs()
	}
	b, err := json.Marshal(env)
	if err != nil {
		return sessionsync.A2AItem{}, false
	}
	return sessionsync.A2AItem{Envelope: b}, true
}

// derivedMessageID is a stable "a2a-<26 crockford>" id for an envelope whose
// own id is not one.
func derivedMessageID(id, from string) string {
	const crockford = "0123456789abcdefghjkmnpqrstvwxyz"
	sum := sha256.Sum256([]byte("keleustes-a2a:" + from + ":" + id))
	var b strings.Builder
	b.WriteString("a2a-")
	var acc uint64
	bits := 0
	for _, c := range sum {
		acc = acc<<8 | uint64(c)
		bits += 8
		for bits >= 5 && b.Len() < 30 {
			bits -= 5
			b.WriteByte(crockford[(acc>>uint(bits))&31])
		}
	}
	return b.String()
}

func (r *A2ARelay) cursorPath() string { return filepath.Join(r.c.Profile().Dir(), "a2a.cursor") }

func (r *A2ARelay) loadCursor() uint64 {
	data, err := os.ReadFile(r.cursorPath())
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// saveCursor keeps the highest seq any process on the host reached.
func (r *A2ARelay) saveCursor(n uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= r.loadCursor() {
		return
	}
	_ = writeFile(r.cursorPath(), []byte(strconv.FormatUint(n, 10)), 0o600)
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// hostID is this host's belai host id (the local bus's agent ids).
func (r *A2ARelay) hostID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.host == "" {
		r.host, _ = sessionsync.HostID(r.c.Profile().home())
	}
	return r.host
}

// Peers lists the live sessions on any node this host's agents may message
// (Board.A2APeers), newest first. Keleustes returns none under the A2A
// blackout. Every field is another host's text: callers show it, cleaned,
// and never hand it to a model as instructions.
func (r *A2ARelay) Peers(ctx context.Context, repo string, limit int) ([]*nodev1.A2APeer, error) {
	out, err := call(ctx, r.c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.A2APeerList, error) {
		return nodev1.NewBoardClient(conn).A2APeers(ctx, &nodev1.A2APeersRequest{Repo: repo, Limit: uint32(max(limit, 0))})
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return out.GetPeers(), nil
}

// OwnerAgent is the Keleustes owner's A2A id; OwnerBelaiID is the reserved
// agent id it has on a belai host (a uuid pair no node or session takes:
// version 4 ids are random, these are all zeros but the last digit).
const (
	OwnerAgent   = "keleustes:owner"
	OwnerBelaiID = "00000000-0000-4000-8000-000000000000:00000000-0000-4000-8000-000000000001"
)
