package factorylink

import (
	"context"
	"testing"

	"github.com/vulnetix/belai/internal/schedule"
	"github.com/vulnetix/belai/internal/sessionsync"
)

var _ schedule.Remote = (*ScheduleRemote)(nil)

// WP-G: the host's schedules round-trip through Keleustes, and a stale
// push comes back acked at the server's version (the owner's edit wins).
func TestScheduleRemoteRoundTrip(t *testing.T) {
	f := newFakeKeleustes(t)
	r, err := ActiveSchedules(f.home)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ctx := context.Background()
	ran := int64(42)
	acks, err := r.ScheduleBatch(ctx, "h", []sessionsync.Schedule{{ID: "s1", Profile: "belai:scout", Cron: "@daily", Dir: "/w", Enabled: true, LastRunAt: &ran}})
	if err != nil || len(acks) != 1 || !acks[0].Applied || acks[0].Version != 1 {
		t.Fatalf("acks = %+v, %v", acks, err)
	}
	items, next, _, err := r.ScheduleList(ctx, "h", 0, 100)
	if err != nil || len(items) != 1 || items[0].Dir != "/w" || items[0].LastRunAt == nil || *items[0].LastRunAt != 42 || next == 0 {
		t.Fatalf("items = %+v next %d %v", items, next, err)
	}
	// The owner edits it in Keleustes (version 2); a push based on 0 conflicts.
	f.board.mu.Lock()
	f.board.scheds["s1"].Version, f.board.scheds["s1"].Enabled = 5, false
	f.board.mu.Unlock()
	acks, err = r.ScheduleBatch(ctx, "h", []sessionsync.Schedule{{ID: "s1", Profile: "belai:scout", Cron: "@daily", Dir: "/w", Enabled: true}})
	if err != nil || len(acks) != 1 || acks[0].Applied || acks[0].Version != 5 {
		t.Fatalf("conflict acks = %+v, %v", acks, err)
	}
}
