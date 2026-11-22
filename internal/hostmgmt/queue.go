package hostmgmt

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sanitize"
)

// The durable queue: one file per action, <belai home>/rc/hostactions/<id>.json,
// mode 0600. It is written before an action is worked on and after every
// update, so a replayed action (Keleustes resends until it sees the first
// update) is answered from the file and never run again. The stored action
// has its vault grant removed.

// Action states.
const (
	stateQueued     = "queued"
	stateAccepted   = "accepted"
	stateRefused    = "refused"
	stateRunning    = "running"
	stateNeedsHuman = "needs_human"
	stateDone       = "done"
	stateFailed     = "failed"
	stateCancelled  = "cancelled"
)

func finalState(s string) bool {
	switch s {
	case stateRefused, stateNeedsHuman, stateDone, stateFailed, stateCancelled:
		return true
	}
	return false
}

// actionIDRE is an action id this host files. Anything else is never written.
var actionIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

type record struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	State    string          `json:"state"`
	Received time.Time       `json:"received"`
	Action   json.RawMessage `json:"action"`
	Updates  []storedUpdate  `json:"updates,omitempty"`
}

type storedUpdate struct {
	Update json.RawMessage `json:"update"`
	Sent   bool            `json:"sent"`
}

type queue struct {
	dir string
	mu  sync.Mutex
}

func openQueue(dir string) (*queue, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &queue{dir: dir}, nil
}

func (q *queue) path(id string) string { return filepath.Join(q.dir, id+".json") }

// get reads one record; false when there is none.
func (q *queue) get(id string) (*record, bool) {
	data, err := os.ReadFile(q.path(id))
	if err != nil {
		return nil, false
	}
	var r record
	if json.Unmarshal(data, &r) != nil || r.ID != id {
		// A record that cannot be read still exists: the action is never
		// run again.
		return &record{ID: id, State: stateFailed}, true
	}
	return &r, true
}

func (q *queue) put(r *record) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := q.path(r.ID) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, q.path(r.ID))
}

func (q *queue) list() []*record {
	ents, _ := os.ReadDir(q.dir)
	var out []*record
	for _, e := range ents {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !actionIDRE.MatchString(id) {
			continue
		}
		if r, ok := q.get(id); ok {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Received.Before(out[j].Received) })
	return out
}

// prune removes settled records older than before.
func (q *queue) prune(before time.Time) {
	for _, r := range q.list() {
		if finalState(r.State) && r.Received.Before(before) && !r.Received.IsZero() {
			_ = os.Remove(q.path(r.ID))
		}
	}
}

// storedAction is the action as it is written: without its vault grant.
func storedAction(a *nodev1.HostAction) json.RawMessage {
	c := proto.Clone(a).(*nodev1.HostAction)
	c.Vault = nil
	b, _ := protojson.Marshal(c)
	return b
}

// Receive files one action from the stream. A new action is queued for the
// worker; one this host already answered has its updates sent again and is
// never run again.
func (m *Manager) Receive(ctx context.Context, a *nodev1.HostAction) {
	id := a.GetId()
	if !actionIDRE.MatchString(id) {
		m.o.Logf("keleustes host action refused: the id is not an identifier")
		return
	}
	m.q.mu.Lock()
	r, seen := m.q.get(id)
	if seen && r.State == stateQueued {
		m.mu.Lock()
		dup := m.running == id || slices.ContainsFunc(m.pending, func(p *nodev1.HostAction) bool { return p.GetId() == id })
		if !dup {
			m.pending = append(m.pending, a)
		}
		m.mu.Unlock()
		m.q.mu.Unlock()
		m.signal()
		return
	}
	if seen {
		m.q.mu.Unlock()
		m.resend(ctx, id)
		return
	}
	r = &record{ID: id, Kind: sanitize.Ident(a.GetKind(), 40), State: stateQueued, Received: m.o.Now().UTC(), Action: storedAction(a)}
	err := m.q.put(r)
	m.q.mu.Unlock()
	if err != nil {
		m.o.Logf("keleustes host action %s: could not file it: %v", id, err)
		return
	}
	m.mu.Lock()
	m.pending = append(m.pending, a)
	m.mu.Unlock()
	m.signal()
}

func (m *Manager) signal() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// workLoop runs the queued actions one at a time.
func (m *Manager) workLoop(ctx context.Context) {
	for {
		m.mu.Lock()
		var a *nodev1.HostAction
		if len(m.pending) > 0 {
			a, m.pending = m.pending[0], m.pending[1:]
			m.running = a.GetId()
		}
		m.mu.Unlock()
		if a != nil {
			m.process(ctx, a)
			m.mu.Lock()
			m.running = ""
			m.mu.Unlock()
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-m.wake:
		}
	}
}

// RunPending runs every queued action now, in order. Tests call it in place of
// Run's worker.
func (m *Manager) RunPending(ctx context.Context) {
	for {
		m.mu.Lock()
		if len(m.pending) == 0 {
			m.mu.Unlock()
			return
		}
		a := m.pending[0]
		m.pending = m.pending[1:]
		m.mu.Unlock()
		m.process(ctx, a)
	}
}

// emit files u as the next update of the action and delivers it.
func (m *Manager) emit(ctx context.Context, id string, u *nodev1.HostActionUpdate) {
	m.q.mu.Lock()
	r, ok := m.q.get(id)
	if !ok {
		r = &record{ID: id, Received: m.o.Now().UTC()}
	}
	u.ActionId, u.Seq = id, uint32(len(r.Updates)+1)
	b, _ := protojson.Marshal(u)
	r.Updates = append(r.Updates, storedUpdate{Update: b})
	r.State = u.GetState()
	if err := m.q.put(r); err != nil {
		m.o.Logf("keleustes host action %s: could not record an update: %v", id, err)
	}
	m.q.mu.Unlock()
	m.flush(ctx, id)
}

// resend marks every update of the action unsent and delivers them again:
// Keleustes replays an action only while it has none.
func (m *Manager) resend(ctx context.Context, id string) {
	m.q.mu.Lock()
	if r, ok := m.q.get(id); ok && len(r.Updates) > 0 {
		unsent := slices.ContainsFunc(r.Updates, func(s storedUpdate) bool { return !s.Sent })
		if !unsent {
			for i := range r.Updates {
				r.Updates[i].Sent = false
			}
			_ = m.q.put(r)
		}
	}
	m.q.mu.Unlock()
	m.flush(ctx, id)
}

// flush delivers the action's unsent updates in order, stopping at the first
// that fails; the next stream sends the rest.
func (m *Manager) flush(ctx context.Context, id string) {
	m.q.mu.Lock()
	defer m.q.mu.Unlock()
	r, ok := m.q.get(id)
	if !ok {
		return
	}
	for i := range r.Updates {
		if r.Updates[i].Sent {
			continue
		}
		var u nodev1.HostActionUpdate
		if protojson.Unmarshal(r.Updates[i].Update, &u) != nil {
			r.Updates[i].Sent = true
			continue
		}
		if err := m.deliver(ctx, &u); err != nil {
			break
		}
		r.Updates[i].Sent = true
	}
	_ = m.q.put(r)
}

func (m *Manager) deliver(ctx context.Context, u *nodev1.HostActionUpdate) error {
	var err error
	for i := 0; i < 3; i++ {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
		err = m.transport().Progress(cctx, u)
		cancel()
		if err == nil || errors.Is(err, errNoTransport) {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(time.Duration(i+1) * 200 * time.Millisecond):
		}
	}
	return err
}

// flushUnsent delivers every record's unsent updates (on a new stream).
func (m *Manager) flushUnsent(ctx context.Context) {
	for _, r := range m.q.list() {
		if slices.ContainsFunc(r.Updates, func(s storedUpdate) bool { return !s.Sent }) {
			m.flush(ctx, r.ID)
		}
	}
}

// recover settles what a previous run left. An action that was accepted or
// running is never run again: it fails, except a restart, which is done by
// definition once this process is running.
func (m *Manager) recover() {
	for _, r := range m.q.list() {
		switch r.State {
		case stateAccepted:
			m.settleOffline(r.ID, stateFailed, "belai restarted before the action ran")
		case stateRunning:
			if r.Kind == "rc_restart" {
				if !m.checkRestart(r.ID) {
					m.settleOffline(r.ID, stateDone, "")
				}
				continue
			}
			m.settleOffline(r.ID, stateFailed, "belai restarted while the action ran")
		}
	}
	// A marker no running restart consumed is left from an earlier run.
	_ = os.Remove(m.markerPath())
}

// settleOffline files a final update without delivering it; the next stream
// sends it.
func (m *Manager) settleOffline(id, state, why string) {
	u := &nodev1.HostActionUpdate{State: state, Error: why}
	if state == stateDone {
		u.Lines = []string{"restarted: belai " + sanitize.Ident(m.o.Version, 64)}
	}
	m.q.mu.Lock()
	r, ok := m.q.get(id)
	if ok {
		u.ActionId, u.Seq = id, uint32(len(r.Updates)+1)
		b, _ := protojson.Marshal(u)
		r.Updates = append(r.Updates, storedUpdate{Update: b})
		r.State = state
		_ = m.q.put(r)
	}
	m.q.mu.Unlock()
	if ok {
		var a nodev1.HostAction
		_ = protojson.Unmarshal(r.Action, &a)
		m.audit(&a, state, why, "")
	}
}
