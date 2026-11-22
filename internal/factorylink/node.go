package factorylink

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// One process per host owns the node link. Every belai process (each TUI,
// `belai connect serve`) runs a Node; the one holding <profile>/link.lock
// runs the Link and publishes its status to <profile>/link.json, and the
// others read that file and take over when the owner exits. Two links with
// one node certificate would otherwise supersede each other on the server.

var errLocked = errors.New("link held by another belai process")

// takeoverInterval is how often a non-owner retries the lock.
var takeoverInterval = 10 * time.Second

// sharedStatus is what the owner publishes for other processes.
type sharedStatus struct {
	PID        int       `json:"pid"`
	State      State     `json:"state"`
	Addr       string    `json:"addr,omitempty"`
	Since      time.Time `json:"since,omitempty"`
	LastError  string    `json:"lastError,omitempty"`
	RevokedWhy string    `json:"revokedWhy,omitempty"`
	Updated    time.Time `json:"updated"`
}

// Node runs the link for a profile when this process can own it.
//
// A `belai rc` daemon is the one process that takes dispatches, so its node
// claims the link (NewDispatchNode): it holds <profile>/link.want while it
// runs, and an owner without a handler (a TUI, `belai connect serve`) that
// sees the claim hands the link over and goes back to watching. Without a
// handler an owner refuses dispatches and jobs through Jobs.Complete rather
// than acking them unseen.
type Node struct {
	p       *Profile
	advert  func(context.Context) *nodev1.HostAdvert
	handler Handler
	// claim: this node takes the link from an owner without a handler.
	claim bool
	// onControl is passed to every link this node owns.
	onControl func(Control)

	mu     sync.Mutex
	link   *Link
	lockF  *os.File
	wantF  *os.File
	cancel context.CancelFunc
	done   chan struct{}
	notify chan struct{}
}

// NewNode prepares a node for p; Start runs it. A nil handler makes the
// node a watcher: it keeps the host present and refuses work.
func NewNode(p *Profile, advert func(context.Context) *nodev1.HostAdvert, handler Handler) *Node {
	return &Node{p: p, advert: advert, handler: handler, notify: make(chan struct{}, 1)}
}

// NewDispatchNode is NewNode for the process that takes dispatches (`belai
// rc`): it claims the link from an owner that has no handler.
func NewDispatchNode(p *Profile, advert func(context.Context) *nodev1.HostAdvert, handler Handler) *Node {
	n := NewNode(p, advert, handler)
	n.claim = handler != nil
	return n
}

// Profile is the joined server.
func (n *Node) Profile() *Profile { return n.p }

// Changed fires (coalesced) when the status may have changed.
func (n *Node) Changed() <-chan struct{} { return n.notify }

func (n *Node) poke() {
	select {
	case n.notify <- struct{}{}:
	default:
	}
}

// Owner reports whether this process runs the link.
func (n *Node) Owner() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.link != nil
}

// Start begins owning the link, or waiting to.
func (n *Node) Start(ctx context.Context) {
	n.mu.Lock()
	if n.cancel != nil {
		n.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	n.cancel = cancel
	n.done = make(chan struct{})
	n.mu.Unlock()
	go func() {
		defer close(n.done)
		n.run(ctx)
	}()
}

// Stop ends the link (if owned) and releases the lock.
func (n *Node) Stop(d time.Duration) {
	n.mu.Lock()
	cancel, done := n.cancel, n.done
	n.cancel = nil
	n.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	select {
	case <-done:
	case <-time.After(d):
	}
}

func (n *Node) run(ctx context.Context) {
	if n.claim {
		n.holdWant()
		defer n.releaseWant()
	}
	for {
		if (n.claim || !wantHeld(n.p)) && n.acquire() {
			if !n.own(ctx) {
				return
			}
			continue // handed over to a claimant; watch again
		}
		n.poke()
		select {
		case <-ctx.Done():
			return
		case <-time.After(takeoverInterval):
		}
		// The profile may have been removed or revoked meanwhile.
		if p, err := Load(filepath.Dir(filepath.Dir(n.p.dir)), n.p.ServerID); err != nil || p.Revoked != "" {
			n.poke()
			return
		}
	}
}

func (n *Node) acquire() bool {
	f, err := os.OpenFile(filepath.Join(n.p.dir, "link.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return false
	}
	if err := tryLock(f); err != nil {
		f.Close()
		return false
	}
	h := n.handler
	if h == nil {
		h = refuseWork(n.p)
	}
	n.mu.Lock()
	n.lockF = f
	n.link = NewLink(n.p, n.advert, h)
	n.link.OnControl(n.onControl)
	n.mu.Unlock()
	return true
}

// own runs the link until ctx ends (false) or, for a node that does not
// claim, until a claimant wants it (true: the link was handed over).
func (n *Node) own(ctx context.Context) bool {
	n.mu.Lock()
	l, f := n.link, n.lockF
	n.mu.Unlock()
	l.Start(ctx)
	n.publish(l.Status())
	var yield <-chan time.Time
	if !n.claim {
		t := time.NewTicker(takeoverInterval)
		defer t.Stop()
		yield = t.C
	}
	release := func() {
		l.Stop(3 * time.Second)
		st := l.Status()
		st.State = StateStopped
		n.publish(st)
		n.mu.Lock()
		n.link, n.lockF = nil, nil
		n.mu.Unlock()
		f.Close() // releases the lock
		n.poke()
	}
	for {
		select {
		case <-ctx.Done():
			release()
			return false
		case <-yield:
			if wantHeld(n.p) {
				release()
				return true
			}
		case <-l.Changed():
			n.publish(l.Status())
			n.poke()
		}
	}
}

// holdWant takes <profile>/link.want for as long as the node runs.
func (n *Node) holdWant() {
	f, err := os.OpenFile(filepath.Join(n.p.dir, "link.want"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	if tryLock(f) != nil {
		f.Close()
		return
	}
	n.mu.Lock()
	n.wantF = f
	n.mu.Unlock()
}

func (n *Node) releaseWant() {
	n.mu.Lock()
	f := n.wantF
	n.wantF = nil
	n.mu.Unlock()
	if f != nil {
		f.Close()
	}
}

// wantHeld reports whether a dispatch-taking process claims the link.
func wantHeld(p *Profile) bool { return fileLocked(filepath.Join(p.dir, "link.want")) }

// refuseWork is the handler of a node that takes no work: a dispatch or a
// job is answered as refused, so Keleustes does not wait on it, and acked.
func refuseWork(p *Profile) Handler {
	return func(ctx context.Context, f *nodev1.ServerFrame) error {
		var id, why string
		switch {
		case f.GetDispatch() != nil:
			id, why = f.GetDispatch().GetId(), "no `belai rc` is running on this host to take dispatches"
		case f.GetJob() != nil:
			id, why = f.GetJob().GetId(), "this host runs no Keleustes jobs"
		default:
			return nil
		}
		c, err := NewClient(p)
		if err != nil {
			return nil
		}
		defer c.Close()
		_ = c.Complete(ctx, &nodev1.JobResult{JobId: id, Status: "refused", Error: why})
		return nil
	}
}

func (n *Node) publish(st Status) {
	s := sharedStatus{
		PID: os.Getpid(), State: st.State, Addr: st.Addr, Since: st.Since,
		LastError: st.LastError, RevokedWhy: st.RevokedWhy, Updated: time.Now().UTC(),
	}
	data, err := json.Marshal(s)
	if err != nil {
		return
	}
	_ = writeFile(filepath.Join(n.p.dir, "link.json"), data, 0o600)
}

// NodeStatus is the link state as this process sees it.
type NodeStatus struct {
	Status
	// Owner: this process runs the link. Otherwise OwnerPID runs it (0
	// when no process does) and Status is what that process published.
	Owner    bool
	OwnerPID int
}

// Status reports the link, from this process or from the owner's file.
func (n *Node) Status() NodeStatus {
	n.mu.Lock()
	l := n.link
	n.mu.Unlock()
	if l != nil {
		return NodeStatus{Status: l.Status(), Owner: true, OwnerPID: os.Getpid()}
	}
	return SharedStatus(n.p)
}

// SharedStatus reads what the owning process published; a stopped or
// missing owner reads as stopped.
func SharedStatus(p *Profile) NodeStatus {
	st := NodeStatus{Status: Status{State: StateStopped, ServerName: p.ServerName, NodeID: p.NodeID}}
	if p.Revoked != "" {
		st.State, st.RevokedWhy = StateRevoked, p.Revoked
		return st
	}
	if !lockHeld(p) {
		return st
	}
	data, err := os.ReadFile(filepath.Join(p.dir, "link.json"))
	if err != nil {
		return st
	}
	var s sharedStatus
	if json.Unmarshal(data, &s) != nil {
		return st
	}
	st.OwnerPID = s.PID
	st.State, st.Addr, st.Since, st.LastError, st.RevokedWhy = s.State, s.Addr, s.Since, s.LastError, s.RevokedWhy
	return st
}

// lockHeld reports whether some process holds the profile's link lock.
func lockHeld(p *Profile) bool { return fileLocked(filepath.Join(p.dir, "link.lock")) }

// fileLocked reports whether some process holds the lock on path.
func fileLocked(path string) bool {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return false
	}
	defer f.Close()
	// Taking it (then dropping it on Close) means nobody held it.
	return errors.Is(tryLock(f), errLocked)
}

// OnControl sets the hook told every factory control state while this node
// owns the link (docs/keleustes.md#factory-control). Call it before Start.
func (n *Node) OnControl(f func(Control)) {
	n.mu.Lock()
	n.onControl = f
	n.mu.Unlock()
}

// Send queues a live-only frame (seq 0) on the link when this process owns
// it. It reports false when it does not, or when the queue is full.
func (n *Node) Send(f *nodev1.NodeFrame) bool {
	n.mu.Lock()
	l := n.link
	n.mu.Unlock()
	return l != nil && l.Send(f)
}
