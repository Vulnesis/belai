package factorylink

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/vulnetix/belai/internal/a2a"
	"github.com/vulnetix/belai/internal/credentials"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/kanban"
	"github.com/vulnetix/belai/internal/repomemory"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// fileKeychain forces the node.key fallback so tests never touch the OS keyring.
type noKeychain struct{}

func (noKeychain) Name() string               { return "none" }
func (noKeychain) Available() bool            { return false }
func (noKeychain) Get(string) (string, error) { return "", errors.New("none") }
func (noKeychain) Set(string, string) error   { return errors.New("none") }
func (noKeychain) Delete(string) error        { return nil }

var _ credentials.Keychain = noKeychain{}

func TestMain(m *testing.M) {
	keychain = func() credentials.Keychain { return noKeychain{} }
	ghAuthenticated = func(context.Context) bool { return false }
	// No real forge CLI is asked during tests.
	forgeHave = func(string) bool { return false }
	os.Exit(m.Run())
}

func mkToken(t *testing.T, mut func(*Token)) string {
	t.Helper()
	tok := Token{
		V: 1, ServerID: "srv-1", ServerName: "Desk", Addrs: []string{"127.0.0.1:1"},
		Pin:     base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		TokenID: "tid", Secret: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		Expires: time.Now().Add(time.Hour).UnixMilli(),
	}
	if mut != nil {
		mut(&tok)
	}
	b, _ := json.Marshal(tok)
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(b)
}

func TestParseToken(t *testing.T) {
	now := time.Now()
	if _, err := ParseToken(mkToken(t, nil), now); err != nil {
		t.Fatalf("valid token: %v", err)
	}
	if _, err := ParseToken("abc", now); !errors.Is(err, ErrNotToken) {
		t.Fatalf("want ErrNotToken, got %v", err)
	}
	cases := map[string]func(*Token){
		"expired": func(k *Token) { k.Expires = now.Add(-time.Minute).UnixMilli() },
		"version": func(k *Token) { k.V = 2 },
		"no addr": func(k *Token) { k.Addrs = nil },
		"pin":     func(k *Token) { k.Pin = "short" },
		"secret":  func(k *Token) { k.Secret = "" },
	}
	for name, mut := range cases {
		if _, err := ParseToken(mkToken(t, mut), now); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

// A server whose key is not the pinned one is refused before any secret is sent.
func TestJoinPinMismatch(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "x"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"x"}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		got <- buf[:n]
	}()
	tok, err := ParseToken(mkToken(t, func(k *Token) { k.Addrs = []string{ln.Addr().String()} }), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, err = Join(context.Background(), t.TempDir(), tok, &nodev1.HostAdvert{})
	if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("want ErrPinMismatch, got %v", err)
	}
	select {
	case b := <-got:
		if strings.Contains(string(b), "tid") {
			t.Fatal("token id reached an unpinned server")
		}
	case <-time.After(time.Second):
	}
}

func TestPinnedTLSAcceptsMatchingKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	leaf, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if err := pinnedTLS(sum[:]).VerifyPeerCertificate([][]byte{der}, nil); err != nil {
		t.Fatalf("matching pin refused: %v", err)
	}
	if err := pinnedTLS(make([]byte, 32)).VerifyPeerCertificate([][]byte{der}, nil); !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("wrong pin accepted: %v", err)
	}
}

func TestProfileRoundTrip(t *testing.T) {
	home := t.TempDir()
	if _, err := Active(home); !errors.Is(err, ErrNoProfile) {
		t.Fatalf("want ErrNoProfile, got %v", err)
	}
	p := &Profile{ServerID: "../evil"}
	if err := save(home, p, nil, nil, nil); err == nil {
		t.Fatal("path-escaping server id accepted")
	}
}

// TestKeleustesEndToEnd joins a real Keleustes server. It runs when
// KELEUSTES_BIN names a built `keleustes` binary.
func TestKeleustesEndToEnd(t *testing.T) {
	bin := os.Getenv("KELEUSTES_BIN")
	if bin == "" {
		t.Skip("KELEUSTES_BIN not set")
	}
	data := t.TempDir()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	run := func(args ...string) string {
		t.Helper()
		out, err := exec.Command(bin, append([]string{"--data", data}, args...)...).Output()
		if err != nil {
			t.Fatalf("keleustes %v: %v", args, err)
		}
		return strings.TrimSpace(string(out))
	}
	run("config", "node.listen_addr", addr)
	srv := exec.Command(bin, "--data", data, "--headless")
	srv.Stderr = os.Stderr
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Process.Kill(); _ = srv.Wait() })
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	tok, err := ParseToken(run("token", "new", "--label", "e2e"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	ctx := context.Background()
	p, err := Join(ctx, home, tok, HostAdvert(ctx, home, HostOptions{Terminal: true}))
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if _, err := Join(ctx, t.TempDir(), tok, &nodev1.HostAdvert{}); err == nil {
		t.Fatal("token reused")
	}
	if _, err := os.Stat(filepath.Join(p.Dir(), "node.key")); err != nil {
		t.Fatalf("node key not stored: %v", err)
	}
	active, err := Active(home)
	if err != nil || active.NodeID != p.NodeID {
		t.Fatalf("active profile: %v %+v", err, active)
	}

	link := NewLink(active, func(ctx context.Context) *nodev1.HostAdvert {
		return HostAdvert(ctx, home, HostOptions{Terminal: true})
	}, nil)
	link.Start(ctx)
	defer link.Stop(time.Second)
	waitState(t, link, StateOnline)
	if list := run("nodes", "list"); !strings.Contains(list, p.NodeID) || !strings.Contains(list, "e2e") {
		t.Fatalf("node not listed: %q", list)
	}

	link.Stop(time.Second)

	// Any process can call the per-host services with the node certificate,
	// without the link.
	c, err := NewClient(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Reachable(ctx); err != nil {
		t.Fatalf("mTLS with the node certificate: %v", err)
	}
	keleustesSessionsRoundTrip(t, c)
	keleustesBoardRoundTrip(t, c, home)
	tok2, err := ParseToken(run("token", "new", "--label", "e2e-target"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	home2 := t.TempDir()
	p2, err := Join(ctx, home2, tok2, HostAdvert(ctx, home2, HostOptions{}))
	if err != nil {
		t.Fatalf("join the second node: %v", err)
	}
	c2, err := NewClient(p2)
	if err != nil {
		t.Fatal(err)
	}
	keleustesTeleportRoundTrip(t, c, c2)
	c2.Close()
	c.Close()

	// Two belai processes on one host: one owns the link, the other watches
	// the published status and takes over when the owner stops. (flock is
	// per open file, so two Nodes in one test process contend like two
	// processes would.)
	takeoverInterval = 100 * time.Millisecond
	adv := func(ctx context.Context) *nodev1.HostAdvert { return HostAdvert(ctx, home, HostOptions{}) }
	n1 := NewNode(active, adv, nil)
	n1.Start(ctx)
	waitNode(t, n1, func(s NodeStatus) bool { return s.Owner && s.State == StateOnline })
	n2 := NewNode(active, adv, nil)
	n2.Start(ctx)
	defer n2.Stop(time.Second)
	waitNode(t, n2, func(s NodeStatus) bool { return !s.Owner && s.State == StateOnline && s.OwnerPID == os.Getpid() })
	n1.Stop(time.Second)
	waitNode(t, n2, func(s NodeStatus) bool { return s.Owner && s.State == StateOnline })
	if list := run("nodes", "list"); !strings.Contains(list, "active") {
		t.Fatalf("node not active after takeover: %q", list)
	}
	n2.Stop(time.Second)

	run("nodes", "revoke", p.NodeID)
	// The headless server holds the live link; the CLI revoke only marks the
	// row, so the link learns on its next reconnect. Force one.
	link.Stop(time.Second)
	link2 := NewLink(active, nil, nil)
	link2.Start(ctx)
	defer link2.Stop(time.Second)
	waitState(t, link2, StateRevoked)
	again, _ := Active(home)
	if again.Revoked == "" {
		t.Fatal("revocation not recorded in profile")
	}
}

func waitNode(t *testing.T, n *Node, ok func(NodeStatus) bool) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for !ok(n.Status()) {
		select {
		case <-n.Changed():
		case <-time.After(100 * time.Millisecond):
		case <-deadline:
			t.Fatalf("node status %+v never matched", n.Status())
		}
	}
}

func waitState(t *testing.T, l *Link, want State) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		if s := l.Status(); s.State == want {
			return
		}
		select {
		case <-l.Changed():
		case <-time.After(200 * time.Millisecond):
		case <-deadline:
			t.Fatalf("state %s, want %s (last error %q)", l.Status().State, want, l.Status().LastError)
		}
	}
}

// keleustesTeleportRoundTrip moves a bundle from one node to another through
// a real server: the origin uploads it for the target (no teleport id, so the
// server mints one), the target downloads exactly those bytes, and the origin,
// which the teleport is not addressed to, is refused. A server without the
// Teleport service is only logged.
func keleustesTeleportRoundTrip(t *testing.T, from, to *Client) {
	t.Helper()
	ctx := context.Background()
	data := bytes.Repeat([]byte("belai teleport bundle "), 40_000) // ~880 KiB, several parts
	id, err := from.UploadTeleport(ctx, TeleportUpload{SessionID: "e2e00000-0000-4000-8000-000000000002", ToNode: to.NodeID(), Title: "e2e"}, data)
	if status.Code(err) == codes.Unimplemented {
		t.Logf("keleustes does not implement Teleport yet: %v", err)
		return
	}
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	b, err := to.DownloadTeleport(ctx, id)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if !bytes.Equal(b.Data, data) || b.FromNode != from.NodeID() || b.ToNode != to.NodeID() || b.SessionID != "e2e00000-0000-4000-8000-000000000002" {
		t.Fatalf("downloaded %d bytes from %q to %q for %q", len(b.Data), b.FromNode, b.ToNode, b.SessionID)
	}
	if _, err := from.DownloadTeleport(ctx, id); status.Code(err) != codes.PermissionDenied {
		t.Errorf("the origin downloaded a teleport addressed to another node: %v", err)
	}
	if _, err := from.UploadTeleport(ctx, TeleportUpload{TeleportID: id, ToNode: to.NodeID()}, data); err == nil {
		t.Error("a delivered teleport took a second upload")
	}
	if _, err := from.UploadTeleport(ctx, TeleportUpload{ToNode: "no-such-node"}, data); err == nil {
		t.Error("a teleport for an unknown node was taken")
	}
}

// keleustesSessionsRoundTrip mirrors a short session to a real server. A
// server that does not implement Sessions yet answers Unimplemented, and the
// round trip is then only logged.
func keleustesSessionsRoundTrip(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	be := NewSyncBackend(c, "headless")
	const sid = "e2e00000-0000-4000-8000-000000000001"
	last, _, err := be.PutSessionControls(ctx, sid, sessionsync.SessionMeta{Name: "e2e", Cwd: "/tmp"})
	if status.Code(err) == codes.Unimplemented {
		t.Logf("keleustes does not implement Sessions yet: %v", err)
		return
	}
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if last != -1 {
		t.Errorf("new session holds %d lines", last+1)
	}
	entries := []sessionsync.Entry{{Seq: 0, ID: "a", Type: "user", Content: "hi"}, {Seq: 1, ID: "b", Type: "assistant", Content: "hello"}}
	if last, err = be.PostEntries(ctx, sid, entries); err != nil || last != 1 {
		t.Fatalf("append: %d %v", last, err)
	}
	// Idempotent by index.
	if last, err = be.PostEntries(ctx, sid, entries); err != nil || last != 1 {
		t.Fatalf("re-append: %d %v", last, err)
	}
	if err := be.EndWith(ctx, sid, sessionsync.EndInfo{Reason: sessionsync.EndCompleted}); err != nil {
		t.Fatalf("end: %v", err)
	}
}

// keleustesBoardRoundTrip syncs the board, the memory and A2A with a real
// server through the same adapters the TUI and rc use. Keleustes has no
// command line for the board or the factory control yet, so a console edit
// and a stop are not exercised here (the fake server covers them).
func keleustesBoardRoundTrip(t *testing.T, c *Client, home string) {
	t.Helper()
	ctx := context.Background()
	if _, err := c.State(ctx); status.Code(err) == codes.Unimplemented {
		t.Logf("keleustes does not implement Board yet: %v", err)
		return
	} else if err != nil {
		t.Fatalf("state: %v", err)
	}
	if ctl, err := RefreshControl(ctx, c); err != nil || ctl.Stopped || ctl.A2ABlackout {
		t.Fatalf("control = %+v, %v", ctl, err)
	}

	// The board: a card made here gets the server's key on the next pull, and
	// an edit is accepted at the server's version.
	store := kanban.Open(filepath.Join(t.TempDir(), "board.bkan"))
	it, _, err := store.Add(kanban.ItemInput{Title: "e2e card", List: kanban.Blocked, Labels: []string{"e2e"}},
		kanban.Provenance{Project: "e2e", Remote: "acme/api"})
	if err != nil {
		t.Fatal(err)
	}
	kr := NewKanbanRemote(c)
	s := kanban.NewSyncer(store, kr, kanban.SyncOptions{})
	s.Sync(ctx)
	if st := s.Status(); st.LastError != "" {
		t.Fatalf("board sync: %s", st.LastError)
	}
	got, _ := store.Get(it.ID)
	if got.Key == "" || got.ServerVersion != 1 || got.Dirty || got.List != kanban.Blocked {
		t.Fatalf("after the first sync: key %q version %d dirty %v list %s", got.Key, got.ServerVersion, got.Dirty, got.List)
	}
	if _, err := store.Move(it.ID, kanban.InProgress, "started", ""); err != nil {
		t.Fatal(err)
	}
	s.Sync(ctx)
	got, _ = store.Get(it.ID)
	if got.ServerVersion != 2 || got.Dirty || got.List != kanban.InProgress {
		t.Fatalf("after the edit: version %d dirty %v list %s (%s)", got.ServerVersion, got.Dirty, got.List, s.Status().LastError)
	}
	page, err := c.KanbanPull(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var card *nodev1.KanbanItem
	for _, k := range page.GetItems() {
		if k.GetId() == it.ID {
			card = k
		}
	}
	if card == nil || card.GetStatus() != "doing" || card.GetKey() != got.Key || !strings.Contains(card.GetMetaJson(), `"belai"`) {
		t.Fatalf("server card = %v", card)
	}
	// A stale push is a conflict, not an error.
	stale := proto.Clone(card).(*nodev1.KanbanItem)
	stale.Version = 1
	res, err := c.KanbanPush(ctx, []*nodev1.KanbanItem{stale})
	if err != nil || len(res.GetConflicts()) != 1 || res.GetConflicts()[0].GetVersion() != 2 {
		t.Fatalf("stale push = %v, %v", res, err)
	}

	// Repository memory, through the replicator.
	root := t.TempDir()
	st, _ := repomemory.OpenScope(root, repomemory.ScopeRepo, "acme/api")
	if _, err := st.Append("tests run with just check", []string{"build"}, repomemory.Stamp{}); err != nil {
		t.Fatal(err)
	}
	mem := NewMemoryRemote(c)
	r := sessionsync.NewMemoryReplicator(mem, "e2e00000-0000-4000-8000-0000000000aa", root)
	r.UseStateFile(mem.StateName())
	if err := r.Sync(ctx); err != nil {
		t.Fatalf("memory sync: %v", err)
	}
	mp, err := c.MemoryPull(ctx, "acme/api", 0)
	if err != nil || len(mp.GetNotes()) != 1 || mp.GetNotes()[0].GetText() != "tests run with just check" || mp.GetNotes()[0].GetAuthor() == "" {
		t.Fatalf("memory on the server = %v, %v", mp, err)
	}

	// A2A: a broadcast from one of this node's sessions reaches another.
	nodeID := c.Profile().NodeID
	s1, s2 := nodeID+":e2e00000-0000-4000-8000-0000000000b1", nodeID+":e2e00000-0000-4000-8000-0000000000b2"
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stream, err := c.A2AReceive(rctx, []string{s2}, 0)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	relay := NewA2ARelay(c)
	env := a2a.Envelope{MessageID: a2a.NewMessageID(time.Now()), Kind: a2a.KindBroadcast, TS: time.Now().UnixMilli(),
		Agent: a2a.AgentCard{HostID: "e2e00000-0000-4000-8000-0000000000aa", SessionID: "e2e00000-0000-4000-8000-0000000000b1"},
		Work:  a2a.Work{Repo: "acme/api", Branch: "main"}}
	raw, _ := json.Marshal(env)
	post, err := relay.PostA2A(ctx, "", []json.RawMessage{raw})
	if err != nil || post.Accepted != 1 || post.Blackout {
		t.Fatalf("send = %+v, %v", post, err)
	}
	e, err := stream.Recv()
	if err != nil || e.GetFrom() != s1 || e.GetId() != env.MessageID || !strings.Contains(e.GetMetaJson(), env.MessageID) {
		t.Fatalf("received = %v, %v", e, err)
	}
	// From this node: the relay hands it on to no one (the bus carried it).
	if _, ok := relay.inbound(e); ok {
		t.Error("an envelope from this node was relayed back")
	}
	if _, err := c.A2ASend(ctx, &nodev1.A2AEnvelope{From: "someone-else:x", Text: "spoof"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("spoofed sender = %v", err)
	}
	t.Logf("board, memory and A2A round trip ok (card %s)", got.Key)
	_ = home
}
