package factorylink

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// State of the link, for /connect status.
type State string

const (
	StateConnecting State = "connecting"
	StateOnline     State = "online"
	StateOffline    State = "offline"
	StateRevoked    State = "revoked"
	StateStopped    State = "stopped"
)

// Status is a snapshot of the link.
type Status struct {
	State       State
	ServerName  string
	NodeID      string
	Addr        string
	Since       time.Time
	LastError   string
	Applied     uint64
	Reconnects  int
	RevokedWhy  string
	Heartbeat   time.Duration
	LastContact time.Time
}

// Handler applies a replayable frame from the server (prompts, commands,
// dispatches…). Returning nil acks the frame; an error leaves it unacked
// so the server replays it on the next connection. Content in these
// frames is remote and untrusted.
type Handler func(ctx context.Context, f *nodev1.ServerFrame) error

// Link keeps one control stream to Keleustes open, reconnecting with backoff.
type Link struct {
	p       *Profile
	advert  func(context.Context) *nodev1.HostAdvert
	handler Handler
	// onControl, when set, is told every factory control state the server
	// sends (Welcome and Control frames), after it is recorded for the host.
	onControl func(Control)

	mu     sync.Mutex
	st     Status
	cancel context.CancelFunc
	done   chan struct{}
	notify chan struct{}
	// send carries frames from Send to the live stream.
	send chan *nodev1.NodeFrame
}

// NewLink builds a link for p. advert is called on every connection;
// handler may be nil while nothing is wired (frames are then acked).
func NewLink(p *Profile, advert func(context.Context) *nodev1.HostAdvert, handler Handler) *Link {
	return &Link{
		p:       p,
		advert:  advert,
		handler: handler,
		st:      Status{State: StateStopped, ServerName: p.ServerName, NodeID: p.NodeID, Applied: p.resumeCursor()},
		notify:  make(chan struct{}, 1),
		send:    make(chan *nodev1.NodeFrame, 64),
	}
}

// Profile is the server this link joins.
func (l *Link) Profile() *Profile { return l.p }

// Status returns a snapshot.
func (l *Link) Status() Status {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.st
}

// Changed fires (coalesced) whenever the status changes.
func (l *Link) Changed() <-chan struct{} { return l.notify }

func (l *Link) set(f func(*Status)) {
	l.mu.Lock()
	f(&l.st)
	l.mu.Unlock()
	select {
	case l.notify <- struct{}{}:
	default:
	}
}

// Start runs the link in the background until Stop.
func (l *Link) Start(ctx context.Context) {
	l.mu.Lock()
	if l.cancel != nil {
		l.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	l.cancel = cancel
	l.done = make(chan struct{})
	l.mu.Unlock()
	go func() {
		defer close(l.done)
		l.run(ctx)
	}()
}

// Stop closes the link and waits up to d for it to finish.
func (l *Link) Stop(d time.Duration) {
	l.mu.Lock()
	cancel, done := l.cancel, l.done
	l.cancel = nil
	l.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	select {
	case <-done:
	case <-time.After(d):
	}
	l.set(func(s *Status) {
		if s.State != StateRevoked {
			s.State = StateStopped
		}
	})
}

// Send queues a non-replayable frame (seq 0) for the live stream. It
// reports false when the queue is full.
func (l *Link) Send(f *nodev1.NodeFrame) bool {
	select {
	case l.send <- f:
		return true
	default:
		return false
	}
}

// errSuperseded: the server closed this link for a newer one with the same
// node certificate. The owner lock makes that rare on one host; seeing it
// means the profile is in use elsewhere, so reconnect slowly.
var errSuperseded = errors.New("another link for this node replaced this one")

// errRevoked ends the run loop for good.
var errRevoked = errors.New("node revoked")

func (l *Link) run(ctx context.Context) {
	backoff := time.Second
	for {
		l.set(func(s *Status) { s.State = StateConnecting })
		connected, err := l.connectOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errRevoked) {
			return
		}
		l.set(func(s *Status) {
			s.State = StateOffline
			if err != nil {
				s.LastError = err.Error()
			}
			s.Reconnects++
		})
		if connected {
			backoff = time.Second
		}
		if errors.Is(err, errSuperseded) {
			backoff = 30 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (l *Link) dial(addr string) (*grpc.ClientConn, error) { return l.p.dial(addr) }

// dial opens a mutual-TLS connection to one of the server's addresses: TLS
// 1.3, the server verified against the Keleustes CA under its issued server
// name, and the node certificate presented. Every RPC after Join uses it.
func (p *Profile) dial(addr string) (*grpc.ClientConn, error) {
	cert, err := p.certificate()
	if err != nil {
		return nil, err
	}
	pool, err := p.caPool()
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      pool,
		ServerName:   p.TLSServerName,
		Certificates: []tls.Certificate{cert},
	}
	return grpc.NewClient(addr,
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 20 * time.Second}),
	)
}

// connectOnce tries each address and serves one stream until it ends.
// connected reports whether a Welcome was received.
func (l *Link) connectOnce(ctx context.Context) (connected bool, err error) {
	var lastErr error
	for _, addr := range l.p.Addrs {
		connected, err := l.serve(ctx, addr)
		if connected || errors.Is(err, errRevoked) || ctx.Err() != nil {
			return connected, err
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no addresses")
	}
	return false, lastErr
}

func (l *Link) serve(ctx context.Context, addr string) (connected bool, err error) {
	conn, err := l.dial(addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := nodev1.NewNodeClient(conn).Link(sctx)
	if err != nil {
		return false, l.classify(err)
	}
	applied := l.Status().Applied
	if err := stream.Send(&nodev1.NodeFrame{Body: &nodev1.NodeFrame_Hello{Hello: &nodev1.Hello{
		ResumeAfter: applied,
	}}}); err != nil {
		return false, l.classify(err)
	}
	first, err := l.recvTimeout(stream, 15*time.Second)
	if err != nil {
		return false, l.classify(err)
	}
	w := first.GetWelcome()
	if w == nil {
		if r := first.GetRevoked(); r != nil {
			return false, l.revoked(r.GetReason())
		}
		return false, errors.New("keleustes did not welcome this node")
	}
	if c := w.GetControl(); c != nil {
		l.applyControl(c)
	}
	hb := time.Duration(w.GetHeartbeatSeconds()) * time.Second
	if hb <= 0 {
		hb = 15 * time.Second
	}
	l.set(func(s *Status) {
		s.State = StateOnline
		s.Addr = addr
		s.Since = time.Now()
		s.LastContact = s.Since
		s.LastError = ""
		s.Heartbeat = hb
		if w.GetServerName() != "" {
			s.ServerName = w.GetServerName()
		}
	})

	// Sender: everything written to the stream goes through here, so acks
	// always carry the latest applied seq.
	var sendMu sync.Mutex
	send := func(f *nodev1.NodeFrame) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		f.Ack = l.Status().Applied
		return stream.Send(f)
	}
	if l.advert != nil {
		if err := send(&nodev1.NodeFrame{Body: &nodev1.NodeFrame_Host{Host: l.advert(ctx)}}); err != nil {
			return true, l.classify(err)
		}
	}

	errc := make(chan error, 2)
	go func() {
		t := time.NewTicker(hb)
		defer t.Stop()
		for {
			select {
			case <-sctx.Done():
				return
			case <-t.C:
				if err := send(&nodev1.NodeFrame{Body: &nodev1.NodeFrame_Heartbeat{Heartbeat: &nodev1.Heartbeat{SentAtMs: time.Now().UnixMilli()}}}); err != nil {
					errc <- err
					return
				}
			case f := <-l.send:
				f.Seq = 0
				if err := send(f); err != nil {
					errc <- err
					return
				}
			}
		}
	}()
	go func() {
		for {
			f, err := stream.Recv()
			if err != nil {
				errc <- err
				return
			}
			if err := l.apply(sctx, f, send); err != nil {
				errc <- err
				return
			}
		}
	}()
	select {
	case <-ctx.Done():
		// gRPC forbids CloseSend concurrently with Send.
		sendMu.Lock()
		_ = stream.CloseSend()
		sendMu.Unlock()
		return true, ctx.Err()
	case err := <-errc:
		return true, l.classify(err)
	}
}

func (l *Link) apply(ctx context.Context, f *nodev1.ServerFrame, send func(*nodev1.NodeFrame) error) error {
	l.set(func(s *Status) { s.LastContact = time.Now() })
	if r := f.GetRevoked(); r != nil {
		return l.revoked(r.GetReason())
	}
	if c := f.GetControl(); c != nil {
		l.applyControl(c)
	}
	if f.GetSeq() == 0 {
		return nil // pings and other live-only frames
	}
	if f.GetSeq() <= l.Status().Applied {
		return nil // replay of something already applied
	}
	if l.handler != nil {
		if err := l.handler(ctx, f); err != nil {
			// Leave it unacked; the server replays it on reconnect.
			return fmt.Errorf("apply frame %d: %w", f.GetSeq(), err)
		}
	}
	seq := f.GetSeq()
	if err := l.p.setResumeCursor(seq); err != nil {
		return err
	}
	l.set(func(s *Status) { s.Applied = seq })
	// Ack promptly rather than waiting for the next heartbeat.
	return send(&nodev1.NodeFrame{})
}

func (l *Link) revoked(reason string) error {
	_ = l.p.MarkRevoked(reason)
	l.set(func(s *Status) {
		s.State = StateRevoked
		s.RevokedWhy = reason
	})
	return errRevoked
}

func (l *Link) classify(err error) error {
	if err == nil || errors.Is(err, io.EOF) {
		return errors.New("keleustes closed the link")
	}
	if errors.Is(err, errRevoked) {
		return err
	}
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.PermissionDenied:
			return l.revoked(st.Message())
		case codes.Unauthenticated:
			return fmt.Errorf("keleustes refused this node's certificate: %s", st.Message())
		case codes.Aborted:
			return fmt.Errorf("%w: %s", errSuperseded, st.Message())
		case codes.Unavailable:
			return fmt.Errorf("keleustes unreachable: %s", st.Message())
		}
	}
	return err
}

func (l *Link) recvTimeout(stream nodev1.Node_LinkClient, d time.Duration) (*nodev1.ServerFrame, error) {
	type res struct {
		f   *nodev1.ServerFrame
		err error
	}
	ch := make(chan res, 1)
	go func() {
		f, err := stream.Recv()
		ch <- res{f, err}
	}()
	select {
	case r := <-ch:
		return r.f, r.err
	case <-time.After(d):
		return nil, errors.New("timed out waiting for keleustes")
	}
}

// OnControl sets the hook told every factory control state. Call it before
// Start.
func (l *Link) OnControl(f func(Control)) { l.onControl = f }

// applyControl records the factory's control state for the host and tells
// the hook. A failure to record is not a link failure.
func (l *Link) applyControl(pc *nodev1.FactoryControl) {
	c := controlFromPB(pc)
	_ = l.p.ApplyControl(c)
	if l.onControl != nil {
		l.onControl(c)
	}
}
