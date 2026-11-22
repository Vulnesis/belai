package factorylink

import (
	"context"
	"errors"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/status"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// Client calls the per-host services (Sessions, Jobs) with the node
// certificate. Unlike the Link it needs no lock: any belai process on the
// host may hold one. It is safe for concurrent use.
type Client struct {
	p *Profile

	mu   sync.Mutex
	conn *grpc.ClientConn
	addr int // index into p.Addrs of conn
}

// rpcTimeout bounds every unary call.
const rpcTimeout = 20 * time.Second

// NewClient prepares a client for p. Nothing is dialled until the first call.
func NewClient(p *Profile) (*Client, error) {
	if p == nil || len(p.Addrs) == 0 {
		return nil, errors.New("keleustes profile has no address")
	}
	if p.Revoked != "" {
		return nil, errors.New("this node was revoked by Keleustes")
	}
	return &Client{p: p}, nil
}

// Profile is the server the client calls.
func (c *Client) Profile() *Profile { return c.p }

// Close drops the connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

func (c *Client) cc() (*grpc.ClientConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn, nil
	}
	conn, err := c.p.dial(c.p.Addrs[c.addr%len(c.p.Addrs)])
	if err != nil {
		return nil, err
	}
	c.conn = conn
	return conn, nil
}

// failed moves to the next address after a call found the server
// unreachable, so a host with several listed addresses finds the live one.
func (c *Client) failed(conn *grpc.ClientConn, err error) {
	if status.Code(err) != codes.Unavailable || len(c.p.Addrs) < 2 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != conn {
		return
	}
	_ = c.conn.Close()
	c.conn = nil
	c.addr++
}

// call runs one unary RPC on the current connection.
func call[T any](ctx context.Context, c *Client, f func(ctx context.Context, conn *grpc.ClientConn) (T, error)) (T, error) {
	var zero T
	conn, err := c.cc()
	if err != nil {
		return zero, err
	}
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	out, err := f(ctx, conn)
	if err != nil {
		c.failed(conn, err)
		return zero, err
	}
	return out, nil
}

// Upsert creates or updates a session's metadata.
func (c *Client) Upsert(ctx context.Context, in *nodev1.SessionUpsert) error {
	_, err := call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.Ok, error) {
		return nodev1.NewSessionsClient(conn).Upsert(ctx, in)
	})
	return err
}

// Append uploads transcript entries (idempotent by index) and returns the
// next index the server expects.
func (c *Client) Append(ctx context.Context, sessionID string, entries []*nodev1.Entry) (uint64, error) {
	out, err := call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.AppendResult, error) {
		return nodev1.NewSessionsClient(conn).Append(ctx, &nodev1.SessionEntries{SessionId: sessionID, Entries: entries})
	})
	if err != nil {
		return 0, err
	}
	return out.GetNextIndex(), nil
}

// End moves a session to history.
func (c *Client) End(ctx context.Context, in *nodev1.SessionEnd) error {
	_, err := call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.Ok, error) {
		return nodev1.NewSessionsClient(conn).End(ctx, in)
	})
	return err
}

// Ack settles one inbox item.
func (c *Client) Ack(ctx context.Context, in *nodev1.InboxAck) error {
	_, err := call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.Ok, error) {
		return nodev1.NewSessionsClient(conn).Ack(ctx, in)
	})
	return err
}

// Complete reports the outcome of a job or a dispatch (job_id = dispatch id).
func (c *Client) Complete(ctx context.Context, in *nodev1.JobResult) error {
	_, err := call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.Ok, error) {
		return nodev1.NewJobsClient(conn).Complete(ctx, in)
	})
	return err
}

// Inbox opens the session's inbox stream after seq `after`. The stream lives
// until ctx ends or the server closes it.
func (c *Client) Inbox(ctx context.Context, sessionID string, after uint64) (nodev1.Sessions_InboxClient, error) {
	conn, err := c.cc()
	if err != nil {
		return nil, err
	}
	st, err := nodev1.NewSessionsClient(conn).Inbox(ctx, &nodev1.InboxRequest{SessionId: sessionID, After: after})
	if err != nil {
		c.failed(conn, err)
		return nil, err
	}
	return st, nil
}

// Reachable reports whether the server accepts this node's certificate. It
// opens a connection and waits for the mutual TLS handshake, without an RPC
// that changes anything, and without the link (which another process may
// own).
func (c *Client) Reachable(ctx context.Context) error {
	conn, err := c.cc()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn.Connect()
	for {
		s := conn.GetState()
		switch s {
		case connectivity.Ready:
			return nil
		case connectivity.Shutdown:
			return errors.New("connection closed")
		}
		if !conn.WaitForStateChange(ctx, s) {
			c.failed(conn, status.Error(codes.Unavailable, "unreachable"))
			return errors.New("keleustes unreachable at " + c.p.Addrs[0])
		}
	}
}

// Conn is the client's connection to Keleustes, dialled with the node
// certificate on first use (host management calls the Host service on it).
func (c *Client) Conn(ctx context.Context) (*grpc.ClientConn, error) { return c.cc() }
