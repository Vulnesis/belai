package rc

import (
	"context"
	"testing"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// queuedReconciler answers every item "push" or "install", the first ones
// with the dispatch Keleustes's automatic sync queued for them.
type queuedReconciler struct{ queued int }

func (q queuedReconciler) LibraryReconcile(_ context.Context, items []*nodev1.LibraryRef) ([]*nodev1.LibraryVerdict, error) {
	var out []*nodev1.LibraryVerdict
	for i, r := range items {
		v := &nodev1.LibraryVerdict{Ref: r, Verdict: []string{"push", "install"}[i%2]}
		if i < q.queued {
			v.DispatchId = "d-1"
		}
		out = append(out, v)
	}
	return out, nil
}

// A push or install Keleustes queued a dispatch for asks nobody; one it did
// not (an older Keleustes, a refusal) still asks the owner. A malformed
// dispatch id counts as none.
func TestFactoryReconcileQueuedVerdicts(t *testing.T) {
	t.Setenv("BELAI_HOME", t.TempDir())
	d, err := New(Options{Factory: newFake(), HostID: testHost, Inventory: func() Inventory {
		return Inventory{Profiles: []sessionsync.RCProfile{{ID: "a", Name: "alpha", SHA256: "h1"}, {ID: "b", Name: "beta", SHA256: "h2"}},
			Items: []sessionsync.RCItem{{Kind: "skill", Name: "notes", SHA256: "h3"}}}
	}})
	if err != nil {
		t.Fatal(err)
	}
	c, status := d.factoryReconcile(context.Background(), queuedReconciler{queued: 3})
	if status != jobOK || c.queued != 3 || c.push+c.install != 0 {
		t.Fatalf("all queued: %+v %s", c, status)
	}
	c, _ = d.factoryReconcile(context.Background(), queuedReconciler{queued: 1})
	if c.queued != 1 || c.push+c.install != 2 {
		t.Fatalf("one queued: %+v", c)
	}
	bad := reconcilerFunc(func(items []*nodev1.LibraryRef) []*nodev1.LibraryVerdict {
		return []*nodev1.LibraryVerdict{{Ref: items[0], Verdict: "push", DispatchId: "not an id!"}}
	})
	if c, _ = d.factoryReconcile(context.Background(), bad); c.queued != 0 || c.push != 1 {
		t.Fatalf("malformed id: %+v", c)
	}
}

type reconcilerFunc func([]*nodev1.LibraryRef) []*nodev1.LibraryVerdict

func (f reconcilerFunc) LibraryReconcile(_ context.Context, items []*nodev1.LibraryRef) ([]*nodev1.LibraryVerdict, error) {
	return f(items), nil
}
