package factorylink

import (
	"context"
	"encoding/json"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// RCHooks are what a `belai rc` daemon supplies to serve Keleustes.
type RCHooks struct {
	// Advert describes the daemon on every connection (RemoteControl is
	// always set).
	Advert func() HostOptions
	// Dispatch applies one Dispatch frame. It must report the outcome itself
	// (Complete); returning acks the frame, so a dispatch is never started
	// twice by a replay.
	Dispatch func(ctx context.Context, d *nodev1.Dispatch)
	// Job applies one Job frame (GitHub or model work). Like Dispatch it
	// reports the outcome itself; nil refuses every job.
	Job func(ctx context.Context, j *nodev1.Job)
	// Control is told the factory's control state from every Welcome and
	// Control frame, after it is recorded for the host.
	Control func(Control)
	// State is called whenever the link's state may have changed.
	State func(NodeStatus)
	// Status is the host's live workers, crew runs and spend, sent on change
	// and at least every minute while this process owns the link. nil sends
	// none.
	Status func() *nodev1.HostStatus
	// Attention is told the owner's decision on a request this host filed.
	// A replay may repeat one; the hook settles each id once.
	Attention func(*nodev1.AttentionDecided)
	// Readvert, when it receives, sends the advert again (the detected
	// harnesses changed).
	Readvert <-chan struct{}
}

// RC is a Keleustes server as a `belai rc` daemon serves it: it owns the
// node link (claiming it from a TUI that holds it) and reports outcomes
// through Jobs.Complete.
type RC struct {
	home string
	p    *Profile
	c    *Client
}

// NewRC prepares the daemon side for the active profile p.
func NewRC(home string, p *Profile) (*RC, error) {
	c, err := NewClient(p)
	if err != nil {
		return nil, err
	}
	return &RC{home: home, p: p, c: c}, nil
}

// Name is the server's name.
func (r *RC) Name() string { return r.p.ServerName }

// Complete reports a dispatch's or a job's outcome.
func (r *RC) Complete(ctx context.Context, res *nodev1.JobResult) error {
	return r.c.Complete(ctx, res)
}

// Serve owns the link until ctx ends.
func (r *RC) Serve(ctx context.Context, h RCHooks) error {
	defer r.c.Close()
	advert := func(ctx context.Context) *nodev1.HostAdvert {
		var o HostOptions
		if h.Advert != nil {
			o = h.Advert()
		}
		o.RemoteControl = true
		return HostAdvert(ctx, r.home, o)
	}
	handler := func(ctx context.Context, f *nodev1.ServerFrame) error {
		switch {
		case f.GetDispatch() != nil:
			if h.Dispatch != nil {
				h.Dispatch(ctx, f.GetDispatch())
			}
		case f.GetAttentionDecided() != nil:
			if h.Attention != nil {
				h.Attention(f.GetAttentionDecided())
			}
		case f.GetJob() != nil && h.Job != nil:
			h.Job(ctx, f.GetJob())
		case f.GetJob() != nil:
			cctx, cancel := context.WithTimeout(ctx, rpcTimeout)
			_ = r.c.Complete(cctx, &nodev1.JobResult{JobId: f.GetJob().GetId(), Status: "refused", Error: "this host runs no Keleustes jobs"})
			cancel()
		}
		return nil
	}
	n := NewDispatchNode(r.p, advert, handler)
	n.OnControl(h.Control)
	n.Start(ctx)
	defer n.Stop(5 * time.Second)
	var last *nodev1.HostStatus
	var sentAt time.Time
	// readvert: the advert changed and is sent again once the link is up (a
	// frame queued before that would be lost).
	readvert := false
	for {
		st := n.Status()
		if readvert && st.Owner && st.State == StateOnline && n.Send(&nodev1.NodeFrame{Body: &nodev1.NodeFrame_Host{Host: advert(ctx)}}) {
			readvert = false
		}
		if h.State != nil {
			h.State(st)
		}
		if h.Status != nil && st.Owner && st.State == StateOnline {
			cur := h.Status()
			if cur != nil && (last == nil || !sameStatus(last, cur) || time.Since(sentAt) > time.Minute) {
				cur.AtMs = time.Now().UnixMilli()
				if n.Send(&nodev1.NodeFrame{Body: &nodev1.NodeFrame_Status{Status: cur}}) {
					last, sentAt = cur, time.Now()
				}
			}
		} else {
			last = nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-n.Changed():
		case <-h.Readvert:
			readvert = true
		case <-time.After(15 * time.Second):
		}
	}
}

// sameStatus compares two statuses apart from their time.
func sameStatus(a, b *nodev1.HostStatus) bool {
	a2, b2 := proto.Clone(a).(*nodev1.HostStatus), proto.Clone(b).(*nodev1.HostStatus)
	a2.AtMs, b2.AtMs = 0, 0
	return proto.Equal(a2, b2)
}

// HostStatusOf maps the daemon's registry snapshot (the same facts the
// website's heartbeat carries, without the log tails) onto HostStatus.
func HostStatusOf(running int, workers []sessionsync.RCWorker, runs []sessionsync.RCCrewRun) *nodev1.HostStatus {
	st := &nodev1.HostStatus{RunningSessions: uint32(max(running, 0))}
	for _, w := range workers {
		st.Workers = append(st.Workers, &nodev1.WorkerStatus{Id: w.ID, Profile: w.Profile, Crew: w.Crew, Run: w.Run,
			State: w.State, CardId: w.Item, Cwd: w.Project, SessionId: w.Session, StartedAtMs: w.Started,
			BeatAtMs: w.Beat, Reason: w.Reason, Done: uint32(max(w.Done, 0)), Failed: uint32(max(w.Failed, 0)),
			Branch: w.Branch, Tokens: int64(w.Tokens), CostMicroUsd: w.CostMicroUSD, CostLiveMicroUsd: w.CostLive})
	}
	for _, r := range runs {
		cr := &nodev1.CrewRunStatus{Id: r.ID, Crew: r.Crew, State: r.State, Reason: r.Reason,
			MaxWorkers: uint32(max(r.MaxWorkers, 0)), Stay: r.Stay}
		for _, s := range r.Scope {
			cr.ScopeDirs = append(cr.ScopeDirs, s.Path)
		}
		if b, err := json.Marshal(r.Members); err == nil {
			cr.MembersJson = string(b)
		}
		st.CrewRuns = append(st.CrewRuns, cr)
	}
	return st
}

// Attention files an attention request with the server (Board.Attention).
func (r *RC) Attention(ctx context.Context, kind, reason, subject string) (string, error) {
	return r.c.Attention(ctx, kind, reason, subject)
}
