package factorylink

import (
	"context"

	"google.golang.org/grpc"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// ScheduleRemote syncs this host's schedules with Keleustes (Board
// SchedulePull/SchedulePush, WP-G): the schedule.Remote the website's
// client is, over the node link's certificate. Pulled definitions are
// untrusted: internal/schedule cleans them and the scheduler checks the
// profile, directory and cron before it fires one, exactly as for the
// website's.
type ScheduleRemote struct{ c *Client }

// NewScheduleRemote syncs schedules through c.
func NewScheduleRemote(c *Client) *ScheduleRemote { return &ScheduleRemote{c: c} }

// ActiveSchedules is a ScheduleRemote for this host's active profile.
func ActiveSchedules(home string) (*ScheduleRemote, error) {
	c, err := activeClient(home)
	if err != nil {
		return nil, err
	}
	return NewScheduleRemote(c), nil
}

// Close drops the connection.
func (s *ScheduleRemote) Close() error { return s.c.Close() }

func ms(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func msPtr(v int64) *int64 {
	if v == 0 {
		return nil
	}
	return &v
}

func scheduleToPB(w sessionsync.Schedule) *nodev1.ScheduleItem {
	return &nodev1.ScheduleItem{Id: w.ID, Profile: w.Profile, Cron: w.Cron, Cwd: w.Dir, Enabled: w.Enabled,
		LastFiredMs: ms(w.LastRunAt), LastStatus: w.LastStatus, NextRunMs: ms(w.NextRunAt), Version: w.Version,
		Deleted: w.Deleted, CreatedAtMs: w.CreatedAt, UpdatedAtMs: w.UpdatedAt}
}

func scheduleFromPB(k *nodev1.ScheduleItem) sessionsync.Schedule {
	return sessionsync.Schedule{ID: k.GetId(), Profile: k.GetProfile(), Cron: k.GetCron(), Dir: k.GetCwd(),
		Enabled: k.GetEnabled(), LastRunAt: msPtr(k.GetLastFiredMs()), LastStatus: k.GetLastStatus(),
		NextRunAt: msPtr(k.GetNextRunMs()), CreatedAt: k.GetCreatedAtMs(), UpdatedAt: k.GetUpdatedAtMs(),
		Version: k.GetVersion(), Deleted: k.GetDeleted()}
}

// ScheduleList returns the schedules Keleustes changed after since.
func (s *ScheduleRemote) ScheduleList(ctx context.Context, _ string, since int64, limit int) ([]sessionsync.Schedule, int64, bool, error) {
	page, err := call(ctx, s.c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.SchedulePage, error) {
		return nodev1.NewBoardClient(conn).SchedulePull(ctx, &nodev1.SchedulePullRequest{SinceMs: since, Limit: uint32(max(limit, 0))})
	})
	if err != nil {
		return nil, since, false, mapErr(err)
	}
	out := make([]sessionsync.Schedule, 0, len(page.GetItems()))
	for _, k := range page.GetItems() {
		out = append(out, scheduleFromPB(k))
	}
	return out, page.GetNextSinceMs(), page.GetMore(), nil
}

// ScheduleBatch pushes this host's changes. A stale one comes back as a
// conflict acked at the server's version, so the next pull brings the
// owner's edit (and this host's run record, which Keleustes kept).
func (s *ScheduleRemote) ScheduleBatch(ctx context.Context, _ string, items []sessionsync.Schedule) ([]sessionsync.ScheduleAck, error) {
	batch := &nodev1.ScheduleBatch{}
	for _, w := range items {
		batch.Items = append(batch.Items, scheduleToPB(w))
	}
	res, err := call(ctx, s.c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.SchedulePushResult, error) {
		return nodev1.NewBoardClient(conn).SchedulePush(ctx, batch)
	})
	if err != nil {
		return nil, mapErr(err)
	}
	var acks []sessionsync.ScheduleAck
	for _, a := range res.GetAccepted() {
		acks = append(acks, sessionsync.ScheduleAck{ID: a.GetId(), UpdatedAt: a.GetUpdatedAtMs(), Version: a.GetVersion(), Applied: true})
	}
	for _, c := range res.GetConflicts() {
		acks = append(acks, sessionsync.ScheduleAck{ID: c.GetId(), UpdatedAt: c.GetUpdatedAtMs(), Version: c.GetVersion()})
	}
	return acks, nil
}
