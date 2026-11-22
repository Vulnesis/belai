package factorylink

import (
	"context"
	"encoding/json"

	"google.golang.org/grpc"

	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// AuditSink sends this host's audit streams to Keleustes (Sessions.Audit
// with a stream id), which chains them into its ledger. The sessionsync
// AuditSyncer drives it exactly as it drives the website: the stream file,
// its cursor and its order are the syncer's; this only maps the calls.
type AuditSink struct{ c *Client }

var _ sessionsync.AuditBackend = (*AuditSink)(nil)

// NewAuditSink sends audit streams through c.
func NewAuditSink(c *Client) *AuditSink { return &AuditSink{c: c} }

// ActiveAudit is an AuditSink for this host's active Keleustes profile.
func ActiveAudit(home string) (*AuditSink, error) {
	c, err := activeClient(home)
	if err != nil {
		return nil, err
	}
	return NewAuditSink(c), nil
}

// Close drops the connection.
func (s *AuditSink) Close() error { return s.c.Close() }

// PutHost does nothing: the host is known by its node certificate.
func (s *AuditSink) PutHost(context.Context, string, sessionsync.Host) error { return nil }

// PutAuditStream reads where Keleustes's copy of the stream ends.
func (s *AuditSink) PutAuditStream(ctx context.Context, _, streamID string) (sessionsync.AuditCursor, error) {
	h, err := call(ctx, s.c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.AuditStreamHead, error) {
		return nodev1.NewSessionsClient(conn).AuditHead(ctx, &nodev1.AuditStreamRequest{StreamId: streamID})
	})
	if err != nil {
		return sessionsync.AuditCursor{}, mapErr(err)
	}
	return sessionsync.AuditCursor{LastSeq: h.GetLastIndex(), ChainOK: true}, nil
}

// PostAudit uploads events by their sequence number; repeats are ignored
// by the server.
func (s *AuditSink) PostAudit(ctx context.Context, _, streamID string, events []audit.Event) (sessionsync.AuditCursor, error) {
	batch := &nodev1.AuditBatch{StreamId: streamID}
	last := int64(-1)
	for _, e := range events {
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		batch.Lines = append(batch.Lines, &nodev1.AuditLine{Index: uint64(max(e.Seq, 0)), AtMs: e.At, Kind: e.Kind, Json: string(b)})
		last = max(last, e.Seq)
	}
	_, err := call(ctx, s.c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.Ok, error) {
		return nodev1.NewSessionsClient(conn).Audit(ctx, batch)
	})
	if err != nil {
		return sessionsync.AuditCursor{}, mapErr(err)
	}
	return sessionsync.AuditCursor{LastSeq: last, ChainOK: true}, nil
}
