package factorylink

import (
	"context"
	"errors"
	"io"

	"google.golang.org/grpc"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// Cross-host dispatch (docs/keleustes.md#cross-host-dispatch): this host
// asks Keleustes to run work on another node. Keleustes decides through
// its node policy (off by default) and parks a request a model made for a
// person to approve; the target admits the work as any Keleustes dispatch,
// with a "node" trigger naming this host.

// Initiators of a request. A model's request is always "agent".
const (
	InitiatedByUser  = "user"
	InitiatedByAgent = "agent"
)

// FleetNodes lists the nodes this host may address.
func (c *Client) FleetNodes(ctx context.Context) ([]*nodev1.NodeSummary, error) {
	out, err := call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.NodeList, error) {
		return nodev1.NewFleetClient(conn).Nodes(ctx, &nodev1.NodesRequest{})
	})
	return out.GetNodes(), err
}

// FleetRequest asks for spec on target ("" or "any": Keleustes picks).
func (c *Client) FleetRequest(ctx context.Context, target string, spec *nodev1.Dispatch, originSession, initiatedBy string) (*nodev1.DispatchTicket, error) {
	if initiatedBy != InitiatedByUser {
		initiatedBy = InitiatedByAgent
	}
	return call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.DispatchTicket, error) {
		return nodev1.NewFleetClient(conn).Request(ctx, &nodev1.DispatchRequest{TargetNode: target, Spec: spec,
			OriginSession: originSession, InitiatedBy: initiatedBy})
	})
}

// FleetPrompt prompts a session on another node ("<nodeId>:<sessionId>").
func (c *Client) FleetPrompt(ctx context.Context, targetSession, text, originSession, initiatedBy string) (*nodev1.DispatchTicket, error) {
	if initiatedBy != InitiatedByUser {
		initiatedBy = InitiatedByAgent
	}
	return call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.DispatchTicket, error) {
		return nodev1.NewFleetClient(conn).Prompt(ctx, &nodev1.PeerPrompt{TargetSession: targetSession, Text: text,
			OriginSession: originSession, InitiatedBy: initiatedBy})
	})
}

// FleetWatch calls fn with each change to the named requests until fn
// returns false, the stream ends or ctx is done.
func (c *Client) FleetWatch(ctx context.Context, ids []string, fn func(*nodev1.DispatchStatus) bool) error {
	conn, err := c.cc()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := nodev1.NewFleetClient(conn).Watch(ctx, &nodev1.WatchRequest{RequestIds: ids})
	if err != nil {
		return mapErr(err)
	}
	for {
		s, err := st.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return mapErr(err)
		}
		if !fn(s) {
			return nil
		}
	}
}

// Settled reports whether a request state is final for a watcher waiting
// on the start.
func Settled(state string) bool {
	switch state {
	case "started", "refused", "failed", "finished":
		return true
	}
	return false
}
