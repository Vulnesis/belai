package sessionsync

import (
	"context"
	"encoding/json"
	"time"
)

// Backend is the server half a Syncer mirrors a session to and takes its
// inbox from. *Client (the Vulnetix website) is one; a Keleustes node
// (internal/factorylink.SyncBackend) is the other. The Syncer owns the tail,
// the ordering of acks after uploads, the gates (RemotePrompts, RemoteAnswers,
// RemoteCommands, RemoteShell) and the queueing, so every backend gets the
// same semantics; a backend only moves bytes.
//
// Everything a backend returns from InboxBatchA2A is untrusted remote content:
// the host admits it exactly as it admits a website prompt, answer or command.
type Backend interface {
	// PutHost registers the machine. A backend whose host is known some other
	// way (a Keleustes node's link) may do nothing.
	PutHost(ctx context.Context, hostID string, h Host) error
	// PutSessionControls registers or refreshes the session and returns the
	// highest line index the server holds (-1 for none) and its pending
	// controls.
	PutSessionControls(ctx context.Context, sessionID string, m SessionMeta) (int64, Controls, error)
	// HeartbeatControls keeps the session live.
	HeartbeatControls(ctx context.Context, sessionID string) (Controls, error)
	// PostEntries uploads lines by index; repeats are ignored. It returns the
	// highest index the server holds.
	PostEntries(ctx context.Context, sessionID string, entries []Entry) (int64, error)
	// EndWith moves the session to history and says why.
	EndWith(ctx context.Context, sessionID string, info EndInfo) error
	// InboxBatchA2A waits up to wait for the session's prompts, answers and
	// commands (and, when a2aAfter >= 0 and the backend relays A2A, the
	// envelopes after it).
	InboxBatchA2A(ctx context.Context, hostID, sessionID string, wait time.Duration, a2aAfter int64) (Inbox, error)
	// Ack, AckAnswer and AckCommand report what the host did with one item.
	Ack(ctx context.Context, promptID, status, reason, entryID string) error
	AckAnswer(ctx context.Context, answerID, status, reason, entryID string) error
	AckCommand(ctx context.Context, commandID, status, reason string, state json.RawMessage) error
	// DraftResult answers an agent-draft request; a backend that never sends
	// drafts may do nothing.
	DraftResult(ctx context.Context, draftID, status, reason string, result any) error
}

var _ Backend = (*Client)(nil)

// backend is the server the syncer talks to: Options.Backend, else the
// website client.
func (o Options) backend() Backend {
	if o.Backend != nil {
		return o.Backend
	}
	if o.Client != nil {
		return o.Client
	}
	return nil
}
