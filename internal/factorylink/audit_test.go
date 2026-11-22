package factorylink

import (
	"context"
	"testing"

	"github.com/vulnetix/belai/internal/audit"
)

// WP-C: a host audit stream goes to Keleustes by sequence number, and the
// head says where to resume.
func TestAuditSinkStreams(t *testing.T) {
	f := newFakeKeleustes(t)
	s, err := ActiveAudit(f.home)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	cur, err := s.PutAuditStream(ctx, "host", "s1")
	if err != nil || cur.LastSeq != -1 {
		t.Fatalf("head = %+v, %v", cur, err)
	}
	cur, err = s.PostAudit(ctx, "host", "s1", []audit.Event{{Seq: 0, Kind: "host.rc_online"}, {Seq: 1, Kind: "host.dispatch"}})
	if err != nil || cur.LastSeq != 1 {
		t.Fatalf("post = %+v, %v", cur, err)
	}
	if cur, _ = s.PutAuditStream(ctx, "host", "s1"); cur.LastSeq != 1 {
		t.Errorf("head after = %+v", cur)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if l := f.audit["stream:s1"][1]; l.GetKind() != "host.dispatch" || l.GetJson() == "" {
		t.Errorf("line = %v", l)
	}
}
