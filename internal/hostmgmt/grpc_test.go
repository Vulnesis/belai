package hostmgmt

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// fakeHost is an in-process Keleustes Host service: it replays every action
// the node has not answered on each Actions stream, as the proto says, and
// records reports and updates.
type fakeHost struct {
	nodev1.UnimplementedHostServer
	mu      sync.Mutex
	actions []*nodev1.HostAction
	acked   map[string]bool
	updates []*nodev1.HostActionUpdate
	reports int
	streams int
	// cut ends a stream after it sent its replay.
	cut chan struct{}
}

func (f *fakeHost) Report(context.Context, *nodev1.HostInventory) (*nodev1.Ok, error) {
	f.mu.Lock()
	f.reports++
	f.mu.Unlock()
	return &nodev1.Ok{}, nil
}

func (f *fakeHost) Actions(_ *nodev1.HostActionsRequest, st grpc.ServerStreamingServer[nodev1.HostAction]) error {
	f.mu.Lock()
	f.streams++
	var send []*nodev1.HostAction
	for _, a := range f.actions {
		if !f.acked[a.GetId()] || f.streams > 1 {
			// From the second stream on, replay everything to prove the
			// node de-duplicates.
			send = append(send, a)
		}
	}
	f.mu.Unlock()
	for _, a := range send {
		if err := st.Send(a); err != nil {
			return err
		}
	}
	select {
	case <-f.cut:
		return nil
	case <-st.Context().Done():
		return nil
	}
}

func (f *fakeHost) Progress(_ context.Context, u *nodev1.HostActionUpdate) (*nodev1.Ok, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acked[u.GetActionId()] = true
	f.updates = append(f.updates, u)
	return &nodev1.Ok{}, nil
}

func (f *fakeHost) final(id string) (int, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n, st := 0, ""
	for _, u := range f.updates {
		if u.GetActionId() == id && finalState(u.GetState()) {
			n++
			st = u.GetState()
		}
	}
	return n, st
}

func TestHostServiceOverGRPCReplaysOnce(t *testing.T) {
	e := newEnv(t, LevelRead)
	fh := &fakeHost{acked: map[string]bool{}, cut: make(chan struct{}),
		actions: []*nodev1.HostAction{{Id: "g-1", Kind: "preflight", Class: "read", Origin: &nodev1.HostOrigin{Actor: "owner"}}}}
	ln := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	nodev1.RegisterHostServer(srv, fh)
	go func() { _ = srv.Serve(ln) }()
	defer srv.Stop()
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return ln.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.m.Run(ctx, NewGRPC(conn)) }()

	waitFor(t, func() bool { n, _ := fh.final("g-1"); return n == 1 })
	// The stream drops; the next one replays the action, which is answered
	// from the queue and not run again.
	close(fh.cut)
	waitFor(t, func() bool { fh.mu.Lock(); defer fh.mu.Unlock(); return fh.streams >= 2 })
	time.Sleep(200 * time.Millisecond)
	if n, st := fh.final("g-1"); st != stateDone || n < 1 {
		t.Fatalf("final updates %d, state %s", n, st)
	}
	accepted := 0
	for _, ev := range e.auditFor("g-1") {
		if ev.Outcome == stateAccepted {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatalf("the action was accepted %d times", accepted)
	}
	fh.mu.Lock()
	reports := fh.reports
	fh.mu.Unlock()
	if reports == 0 {
		t.Fatal("no inventory was reported on link")
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
