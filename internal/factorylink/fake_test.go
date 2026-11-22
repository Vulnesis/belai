package factorylink

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// fakeKeleustes is an in-process Keleustes: a mutual-TLS gRPC server with
// its own CA, implementing the Node link, Sessions and Jobs as the proto
// describes them, and recording what the node sent.
type fakeKeleustes struct {
	nodev1.UnimplementedNodeServer
	nodev1.UnimplementedSessionsServer
	nodev1.UnimplementedJobsServer
	nodev1.UnimplementedBoardServer
	nodev1.UnimplementedTeleportServer

	addr string
	home string
	p    *Profile

	mu       sync.Mutex
	upserts  []*nodev1.SessionUpsert
	entries  map[string][]*nodev1.Entry // stored, by index
	appended []uint64                   // every index the node sent
	ends     []*nodev1.SessionEnd
	acks     chan *nodev1.InboxAck
	inbox    map[string]chan *nodev1.InboxItem
	afters   []uint64
	results  chan *nodev1.JobResult
	frames   chan *nodev1.ServerFrame // sent on the next Link
	linkAck  uint64
	links    int
	adverts  []*nodev1.HostAdvert
	statuses []*nodev1.HostStatus
	audit    map[string]map[uint64]*nodev1.AuditLine

	board boardState
	tele  teleState
	// welcome is the control state the Welcome frame carries, if any.
	welcome *nodev1.FactoryControl
	// blobs are the attachments FetchAttachment serves, by hash (row 53),
	// and fetches the requests it saw.
	blobs   map[string][]byte
	fetches []*nodev1.AttachmentRequest
}

func newFakeKeleustes(t *testing.T) *fakeKeleustes {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake keleustes ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(ca)

	srvKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	srvTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "keleustes.node"},
		DNSNames: []string{"keleustes.node"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, ca, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	_, nodeKey, _ := ed25519.GenerateKey(rand.Reader)
	nodeTmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "node-1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	nodeDER, err := x509.CreateCertificate(rand.Reader, nodeTmpl, ca, nodeKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeKeleustes{
		addr: ln.Addr().String(), home: t.TempDir(),
		entries: map[string][]*nodev1.Entry{}, acks: make(chan *nodev1.InboxAck, 32),
		inbox: map[string]chan *nodev1.InboxItem{}, results: make(chan *nodev1.JobResult, 32),
		frames: make(chan *nodev1.ServerFrame, 32),
		board:  newBoardState(),
		tele:   newTeleState(),
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{srvDER}, PrivateKey: srvKey}},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})))
	nodev1.RegisterNodeServer(srv, f)
	nodev1.RegisterSessionsServer(srv, f)
	nodev1.RegisterJobsServer(srv, f)
	nodev1.RegisterBoardServer(srv, f)
	nodev1.RegisterTeleportServer(srv, f)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	p := &Profile{ServerID: "srv-1", ServerName: "Desk", NodeID: "node-1", Addrs: []string{f.addr},
		TLSServerName: "keleustes.node", JoinedAt: time.Now()}
	if err := save(f.home, p, nodeKey, nodeDER, caDER); err != nil {
		t.Fatal(err)
	}
	f.p = p
	return f
}

func (f *fakeKeleustes) box(sid string) chan *nodev1.InboxItem {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.inbox[sid] == nil {
		f.inbox[sid] = make(chan *nodev1.InboxItem, 32)
	}
	return f.inbox[sid]
}

func (f *fakeKeleustes) Link(st nodev1.Node_LinkServer) error {
	hello, err := st.Recv()
	if err != nil || hello.GetHello() == nil {
		return err
	}
	f.mu.Lock()
	f.links++
	f.mu.Unlock()
	if err := st.Send(&nodev1.ServerFrame{Body: &nodev1.ServerFrame_Welcome{Welcome: &nodev1.Welcome{
		NodeId: "node-1", ServerName: "Desk", HeartbeatSeconds: 1, Control: f.welcome}}}); err != nil {
		return err
	}
	errc := make(chan error, 1)
	go func() {
		for {
			fr, err := st.Recv()
			if err != nil {
				errc <- err
				return
			}
			f.mu.Lock()
			if fr.GetAck() > f.linkAck {
				f.linkAck = fr.GetAck()
			}
			if h := fr.GetHost(); h != nil {
				f.adverts = append(f.adverts, h)
			}
			if s := fr.GetStatus(); s != nil {
				f.statuses = append(f.statuses, s)
			}
			f.mu.Unlock()
		}
	}()
	for {
		select {
		case <-st.Context().Done():
			return nil
		case err := <-errc:
			return err
		case fr := <-f.frames:
			if err := st.Send(fr); err != nil {
				return err
			}
		}
	}
}

func (f *fakeKeleustes) Upsert(_ context.Context, in *nodev1.SessionUpsert) (*nodev1.Ok, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upserts = append(f.upserts, in)
	return &nodev1.Ok{}, nil
}

func (f *fakeKeleustes) Append(_ context.Context, in *nodev1.SessionEntries) (*nodev1.AppendResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	have := f.entries[in.GetSessionId()]
	for _, e := range in.GetEntries() {
		f.appended = append(f.appended, e.GetIndex())
		// Idempotent by index: only the next one is stored.
		if e.GetIndex() == uint64(len(have)) {
			have = append(have, e)
		}
	}
	f.entries[in.GetSessionId()] = have
	return &nodev1.AppendResult{NextIndex: uint64(len(have))}, nil
}

func (f *fakeKeleustes) End(_ context.Context, in *nodev1.SessionEnd) (*nodev1.Ok, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ends = append(f.ends, in)
	return &nodev1.Ok{}, nil
}

func (f *fakeKeleustes) Inbox(in *nodev1.InboxRequest, st nodev1.Sessions_InboxServer) error {
	f.mu.Lock()
	f.afters = append(f.afters, in.GetAfter())
	f.mu.Unlock()
	box := f.box(in.GetSessionId())
	for {
		select {
		case <-st.Context().Done():
			return nil
		case it := <-box:
			if it.GetSeq() <= in.GetAfter() {
				continue
			}
			if err := st.Send(it); err != nil {
				return err
			}
		}
	}
}

func (f *fakeKeleustes) Ack(_ context.Context, in *nodev1.InboxAck) (*nodev1.Ok, error) {
	f.acks <- in
	return &nodev1.Ok{}, nil
}

func (f *fakeKeleustes) Complete(_ context.Context, in *nodev1.JobResult) (*nodev1.Ok, error) {
	f.results <- in
	return &nodev1.Ok{}, nil
}

func (f *fakeKeleustes) Audit(_ context.Context, in *nodev1.AuditBatch) (*nodev1.Ok, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.audit == nil {
		f.audit = map[string]map[uint64]*nodev1.AuditLine{}
	}
	key := in.GetSessionId()
	if key == "" {
		key = "stream:" + in.GetStreamId()
	}
	if f.audit[key] == nil {
		f.audit[key] = map[uint64]*nodev1.AuditLine{}
	}
	for _, l := range in.GetLines() {
		f.audit[key][l.GetIndex()] = l
	}
	return &nodev1.Ok{}, nil
}

func (f *fakeKeleustes) AuditHead(_ context.Context, in *nodev1.AuditStreamRequest) (*nodev1.AuditStreamHead, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	last := int64(-1)
	for i := range f.audit["stream:"+in.GetStreamId()] {
		last = max(last, int64(i))
	}
	return &nodev1.AuditStreamHead{LastIndex: last}, nil
}
