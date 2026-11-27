package factorylink

import (
	"context"
	"errors"

	"google.golang.org/grpc"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// Library distribution (WP-E, docs/keleustes.md#library): documents are
// fetched for the dispatch that named them, never pushed. Everything
// fetched is untrusted: the rc daemon validates a profile as a profile and an
// item with its kind's own validator before it writes anything.

// LibraryFetch reads one document for a delivered library_install dispatch.
func (c *Client) LibraryFetch(ctx context.Context, dispatchID string, ref *nodev1.LibraryRef) (*nodev1.LibraryDoc, error) {
	d, err := call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.LibraryDoc, error) {
		return nodev1.NewLibraryClient(conn).Fetch(ctx, &nodev1.LibraryFetch{DispatchId: dispatchID, Ref: ref})
	})
	return d, mapErr(err)
}

// LibraryFetchTeleport reads a profile or crew the teleport id needs
// (Library.Fetch with the teleport id): Keleustes answers only for the node
// the teleport is addressed to, while it is ready or delivered, and only for
// a need it stored with the teleport. The document is untrusted; the caller
// validates it as its kind before writing anything.
func (c *Client) LibraryFetchTeleport(ctx context.Context, teleportID string, ref *nodev1.LibraryRef) (*nodev1.LibraryDoc, error) {
	if !teleportIDShape.MatchString(teleportID) {
		return nil, errors.New("that is not a Keleustes teleport id")
	}
	d, err := call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.LibraryDoc, error) {
		return nodev1.NewLibraryClient(conn).Fetch(ctx, &nodev1.LibraryFetch{TeleportId: teleportID, Ref: ref})
	})
	return d, mapErr(err)
}

// LibraryBackup stores this host's copy for a library_backup dispatch.
func (c *Client) LibraryBackup(ctx context.Context, doc *nodev1.LibraryDoc) (*nodev1.LibraryRef, error) {
	r, err := call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.LibraryReceipt, error) {
		return nodev1.NewLibraryClient(conn).Backup(ctx, doc)
	})
	return r.GetStored(), mapErr(err)
}

// LibraryReconcile sends this host's hashes and returns one verdict per item.
func (c *Client) LibraryReconcile(ctx context.Context, items []*nodev1.LibraryRef) ([]*nodev1.LibraryVerdict, error) {
	v, err := call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.LibraryVerdicts, error) {
		return nodev1.NewLibraryClient(conn).Reconcile(ctx, &nodev1.LibraryInventory{Items: items})
	})
	return v.GetVerdicts(), mapErr(err)
}

// LibraryFetch on the daemon's connection.
func (r *RC) LibraryFetch(ctx context.Context, dispatchID string, ref *nodev1.LibraryRef) (*nodev1.LibraryDoc, error) {
	return r.c.LibraryFetch(ctx, dispatchID, ref)
}

// LibraryBackup on the daemon's connection.
func (r *RC) LibraryBackup(ctx context.Context, doc *nodev1.LibraryDoc) (*nodev1.LibraryRef, error) {
	return r.c.LibraryBackup(ctx, doc)
}

// LibraryScanReport sends what a library_scan dispatch found (names, paths,
// hashes and verdicts only).
func (c *Client) LibraryScanReport(ctx context.Context, r *nodev1.LibraryScanReport) error {
	_, err := call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.Ok, error) {
		return nodev1.NewLibraryClient(conn).ScanReport(ctx, r)
	})
	return mapErr(err)
}

// LibraryScanReport on the daemon's connection.
func (r *RC) LibraryScanReport(ctx context.Context, rep *nodev1.LibraryScanReport) error {
	return r.c.LibraryScanReport(ctx, rep)
}
