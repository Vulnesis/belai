package factorylink

import (
	"context"

	"google.golang.org/grpc"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// The Board service: the kanban board, shared repository memory, A2A relay
// and the factory's control state. Any belai process on the host may call it
// with the node certificate. Everything it returns is remote content.

// KanbanPull reads the cards changed after sinceMs (the server's cursor).
func (c *Client) KanbanPull(ctx context.Context, sinceMs int64, limit uint32) (*nodev1.KanbanPage, error) {
	return call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.KanbanPage, error) {
		return nodev1.NewBoardClient(conn).KanbanPull(ctx, &nodev1.KanbanPullRequest{SinceMs: sinceMs, Limit: limit})
	})
}

// KanbanPush sends node-side edits, each carrying the version it was based
// on. A stale one comes back as a conflict with the server's copy.
func (c *Client) KanbanPush(ctx context.Context, items []*nodev1.KanbanItem) (*nodev1.KanbanPushResult, error) {
	return call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.KanbanPushResult, error) {
		return nodev1.NewBoardClient(conn).KanbanPush(ctx, &nodev1.KanbanBatch{Items: items})
	})
}

// MemoryPull reads the memory notes changed after sinceMs; scope "" is all.
func (c *Client) MemoryPull(ctx context.Context, scope string, sinceMs int64) (*nodev1.MemoryPage, error) {
	return call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.MemoryPage, error) {
		return nodev1.NewBoardClient(conn).MemoryPull(ctx, &nodev1.MemoryPullRequest{Scope: scope, SinceMs: sinceMs})
	})
}

// MemoryPush stores one note (newest change wins) and returns the stored copy.
func (c *Client) MemoryPush(ctx context.Context, n *nodev1.MemoryNote) (*nodev1.MemoryNote, error) {
	return call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.MemoryNote, error) {
		return nodev1.NewBoardClient(conn).MemoryPush(ctx, n)
	})
}

// A2ASend relays one envelope. It is refused while the A2A blackout is on.
func (c *Client) A2ASend(ctx context.Context, e *nodev1.A2AEnvelope) (*nodev1.A2ASendResult, error) {
	return call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.A2ASendResult, error) {
		return nodev1.NewBoardClient(conn).A2ASend(ctx, e)
	})
}

// A2AReceive opens the envelope stream for agents on this node after seq
// after. It lives until ctx ends or the server closes it.
func (c *Client) A2AReceive(ctx context.Context, to []string, after uint64) (nodev1.Board_A2AReceiveClient, error) {
	conn, err := c.cc()
	if err != nil {
		return nil, err
	}
	st, err := nodev1.NewBoardClient(conn).A2AReceive(ctx, &nodev1.A2AReceiveRequest{To: to, After: after})
	if err != nil {
		c.failed(conn, err)
		return nil, err
	}
	return st, nil
}

// State reads the factory's control state (stopped, A2A blackout).
func (c *Client) State(ctx context.Context) (*nodev1.FactoryControl, error) {
	return call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.FactoryControl, error) {
		return nodev1.NewBoardClient(conn).State(ctx, &nodev1.StateRequest{})
	})
}
