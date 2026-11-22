package factorylink

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// ErrForgeRefused is a forge request Keleustes will never take (a bad
// shape): the relay drops it rather than retrying.
var ErrForgeRefused = errors.New("keleustes refused the forge request")

// FileForge files a worker's forge request with Keleustes (WP-H). Only the
// request travels; the bundle stays in this host's state directory. It
// reports whether Keleustes already had it.
func (c *Client) FileForge(ctx context.Context, r sessionsync.ForgeRequest) (bool, error) {
	conn, err := c.cc()
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	st, err := nodev1.NewForgeClient(conn).File(ctx)
	if err != nil {
		c.failed(conn, err)
		return false, mapErr(err)
	}
	req := &nodev1.ForgeRequest{RequestId: r.RequestID, ItemId: r.ItemID, WorkerId: r.WorkerID, Kind: r.Kind,
		RepoOwner: r.RepoOwner, RepoName: r.RepoName, Branch: r.Branch, BaseSha: r.BaseSHA, HeadSha: r.HeadSHA,
		BundleSha256: r.BundleSHA256, BundleBytes: r.BundleBytes, Failure: r.Failure, Title: r.Title}
	if err := st.Send(&nodev1.ForgePart{Request: req, Last: true}); err != nil {
		return false, mapErr(err)
	}
	out, err := st.CloseAndRecv()
	if s, ok := status.FromError(err); ok && s.Code() == codes.InvalidArgument {
		return false, ErrForgeRefused
	}
	if err != nil {
		return false, mapErr(err)
	}
	return out.GetDuplicate(), nil
}

// FileForge on the daemon's connection.
func (r *RC) FileForge(ctx context.Context, req sessionsync.ForgeRequest) (bool, error) {
	return r.c.FileForge(ctx, req)
}
