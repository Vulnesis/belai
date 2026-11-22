package rc

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sessionsync"
)

type fakeReconciler struct {
	mu    sync.Mutex
	calls [][]*nodev1.LibraryRef
	err   error
}

func (f *fakeReconciler) LibraryReconcile(_ context.Context, items []*nodev1.LibraryRef) ([]*nodev1.LibraryVerdict, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, items)
	if f.err != nil {
		return nil, f.err
	}
	var out []*nodev1.LibraryVerdict
	for i, r := range items {
		v := []string{"current", "push", "install", "diverged"}[i%4]
		out = append(out, &nodev1.LibraryVerdict{Ref: r, Verdict: v})
	}
	return out, nil
}

func TestFactoryReconcile(t *testing.T) {
	t.Setenv("BELAI_HOME", t.TempDir())
	rec, err := audit.Open(t.TempDir(), "host-a")
	if err != nil {
		t.Fatal(err)
	}
	audit.SetDefault(rec)
	t.Cleanup(func() { audit.SetDefault(nil); rec.Close() })

	ff := newFake()
	d, err := New(Options{Factory: ff, HostID: testHost, Inventory: func() Inventory {
		return Inventory{
			Profiles: []sessionsync.RCProfile{{ID: "a", Name: "alpha", SHA256: "h1"}, {ID: "b", Name: "beta", SHA256: "h2"},
				{ID: "c", Name: "off"}},
			Items: []sessionsync.RCItem{{Kind: "skill", Name: "notes", SHA256: "h3"}, {Kind: "prompt", Name: "p", SHA256: "h4"}},
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	fr := &fakeReconciler{}
	c, status := d.factoryReconcile(context.Background(), fr)
	if status != jobOK || c.total != 4 || c.current != 1 || c.push != 1 || c.install != 1 || c.diverged != 1 {
		t.Fatalf("pass = %+v %s", c, status)
	}
	if len(fr.calls) != 1 || len(fr.calls[0]) != 4 {
		t.Fatalf("sent %v (an item with no hash is not offered)", fr.calls)
	}
	for _, r := range fr.calls[0] {
		if r.GetSha256() == "" {
			t.Errorf("sent an unhashed item %v", r)
		}
	}

	// Kill switch: no call, and the skipped pass is audited.
	d.setFactoryControl(factorylink.Control{Stopped: true, Reason: "freeze"})
	if _, status := d.factoryReconcile(context.Background(), fr); status != "stopped" || len(fr.calls) != 1 {
		t.Errorf("stopped pass = %s, calls %d", status, len(fr.calls))
	}
	d.setFactoryControl(factorylink.Control{})
	fr.err = errors.New("offline")
	if _, status := d.factoryReconcile(context.Background(), fr); status != jobFailed {
		t.Errorf("failed pass = %s", status)
	}

	rec.Close()
	evs := readStream(t, rec.Path())
	if bad := audit.Verify(evs); bad != -1 {
		t.Fatalf("chain breaks at %d", bad)
	}
	var got []string
	for _, e := range evs {
		if e.Kind == string(audit.HostDispatch) && e.Data["dispatch"] == "library_reconcile" {
			got = append(got, e.Data["status"]+"/"+e.Data["total"]+"/"+e.Data["count"])
		}
	}
	want := []string{"ok/4/2", "stopped/0/0", "failed/0/0"}
	if len(got) != len(want) {
		t.Fatalf("reconcile facts = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("fact %d = %s, want %s", i, got[i], want[i])
		}
	}
}
