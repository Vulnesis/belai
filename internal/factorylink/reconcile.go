package factorylink

import (
	"context"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// LibraryReconcile on the daemon's connection: the factory-mode automatic
// sync's one call (rc/autosync.go). Hashes go out, verdicts come back; no
// document travels.
func (r *RC) LibraryReconcile(ctx context.Context, items []*nodev1.LibraryRef) ([]*nodev1.LibraryVerdict, error) {
	return r.c.LibraryReconcile(ctx, items)
}
