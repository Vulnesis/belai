package factorylink

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// teleState is the fake Keleustes's Teleport service, with the rules of
// kls-node/src/teleport.rs and kls-core's teleport functions: the header on
// the first part, the bytes capped at the header's size (or 256 MiB),
// checked against its SHA-256, a requested teleport filled only by its origin
// node, and a download only by the node a ready, unexpired teleport is
// addressed to. The fake's own node is "node-1".
type teleState struct {
	mu    sync.Mutex
	next  int
	byID  map[string]*fakeTeleport
	parts [][]*nodev1.TeleportPart // every upload's parts, as received
	// tamper, when set, rewrites the parts a download sends.
	tamper func([]*nodev1.TeleportPart) []*nodev1.TeleportPart
}

type fakeTeleport struct {
	id, session, from, to, title, status, sha string
	data                                      []byte
	expires                                   time.Time
}

func newTeleState() teleState { return teleState{byID: map[string]*fakeTeleport{}} }

// request records a teleport Keleustes asked node from to fill.
func (f *fakeKeleustes) requestTeleport(id, session, from, to string) {
	f.tele.mu.Lock()
	defer f.tele.mu.Unlock()
	f.tele.byID[id] = &fakeTeleport{id: id, session: session, from: from, to: to, status: "requested", expires: time.Now().Add(time.Hour)}
}

// readyTeleport stores a bundle addressed to node to.
func (f *fakeKeleustes) readyTeleport(id, session, from, to string, data []byte) *fakeTeleport {
	f.tele.mu.Lock()
	defer f.tele.mu.Unlock()
	sum := sha256.Sum256(data)
	t := &fakeTeleport{id: id, session: session, from: from, to: to, title: "a session", status: "ready",
		sha: hex.EncodeToString(sum[:]), data: data, expires: time.Now().Add(time.Hour)}
	f.tele.byID[id] = t
	return t
}

func (f *fakeKeleustes) teleport(id string) *fakeTeleport {
	f.tele.mu.Lock()
	defer f.tele.mu.Unlock()
	return f.tele.byID[id]
}

func (f *fakeKeleustes) Upload(st nodev1.Teleport_UploadServer) error {
	const node = "node-1"
	first, err := st.Recv()
	if err != nil {
		return status.Error(codes.InvalidArgument, "empty upload")
	}
	h := first.GetHeader()
	if h == nil {
		return status.Error(codes.InvalidArgument, "the first part carries the header")
	}
	if h.GetSize() < 0 || h.GetSize() > TeleportMaxBytes {
		return status.Error(codes.InvalidArgument, "bundle size out of range")
	}
	if s := h.GetSha256(); s != "" && len(s) != 64 {
		return status.Error(codes.InvalidArgument, "sha256 must be 64 hex digits")
	}
	if h.GetFromNode() != "" && h.GetFromNode() != node {
		return status.Error(codes.PermissionDenied, "teleport is not addressed to this node")
	}
	f.tele.mu.Lock()
	var t *fakeTeleport
	if first.GetTeleportId() == "" {
		if h.GetToNode() == "" || h.GetToNode() == node {
			f.tele.mu.Unlock()
			return status.Error(codes.InvalidArgument, "to_node is required and must be another node")
		}
		f.tele.next++
		t = &fakeTeleport{id: fmt.Sprintf("0190f0a2-0000-7000-8000-%012d", f.tele.next), session: h.GetSessionId(),
			from: node, to: h.GetToNode(), status: "requested", expires: time.Now().Add(time.Hour)}
		f.tele.byID[t.id] = t
	} else {
		t = f.tele.byID[first.GetTeleportId()]
		switch {
		case t == nil:
			f.tele.mu.Unlock()
			return status.Error(codes.NotFound, "unknown teleport")
		case t.from != node:
			f.tele.mu.Unlock()
			return status.Error(codes.PermissionDenied, "teleport is not addressed to this node")
		case h.GetToNode() != "" && h.GetToNode() != t.to:
			f.tele.mu.Unlock()
			return status.Error(codes.InvalidArgument, "to_node does not match the request")
		case t.status != "requested":
			f.tele.mu.Unlock()
			return status.Error(codes.FailedPrecondition, "teleport is "+t.status)
		}
	}
	f.tele.mu.Unlock()
	limit := int64(TeleportMaxBytes)
	if h.GetSize() > 0 {
		limit = h.GetSize()
	}
	var buf []byte
	var got []*nodev1.TeleportPart
	p, done := first, false
	for {
		got = append(got, p)
		if p.GetTeleportId() != "" && p.GetTeleportId() != t.id && first.GetTeleportId() != "" {
			return status.Error(codes.InvalidArgument, "parts name another teleport")
		}
		if int64(len(buf)+len(p.GetChunk())) > limit {
			return status.Error(codes.ResourceExhausted, "bundle too large")
		}
		buf = append(buf, p.GetChunk()...)
		if p.GetLast() {
			done = true
			break
		}
		if p, err = st.Recv(); err == io.EOF {
			break
		} else if err != nil {
			return err
		}
	}
	f.tele.mu.Lock()
	f.tele.parts = append(f.tele.parts, got)
	f.tele.mu.Unlock()
	if !done {
		return status.Error(codes.InvalidArgument, "upload ended before the last part")
	}
	if h.GetSize() > 0 && int64(len(buf)) != h.GetSize() {
		return status.Error(codes.InvalidArgument, "bundle size does not match the header")
	}
	sum := sha256.Sum256(buf)
	if s := strings.ToLower(h.GetSha256()); s != "" && s != hex.EncodeToString(sum[:]) {
		return status.Error(codes.DataLoss, "sha256 mismatch")
	}
	f.tele.mu.Lock()
	t.status, t.data, t.sha, t.title = "ready", buf, hex.EncodeToString(sum[:]), h.GetTitle()
	f.tele.mu.Unlock()
	return st.SendAndClose(&nodev1.TeleportReceipt{TeleportId: t.id, Size: int64(len(buf))})
}

func (f *fakeKeleustes) Download(in *nodev1.TeleportRequest, st nodev1.Teleport_DownloadServer) error {
	const node = "node-1"
	f.tele.mu.Lock()
	t := f.tele.byID[in.GetTeleportId()]
	tamper := f.tele.tamper
	f.tele.mu.Unlock()
	switch {
	case t == nil:
		return status.Error(codes.NotFound, "unknown teleport")
	case t.to != node:
		return status.Error(codes.PermissionDenied, "teleport is not addressed to this node")
	case time.Now().After(t.expires):
		return status.Error(codes.FailedPrecondition, "teleport is expired")
	case t.status != "ready" && t.status != "delivered":
		return status.Error(codes.FailedPrecondition, "teleport is "+t.status)
	}
	var parts []*nodev1.TeleportPart
	header := &nodev1.TeleportHeader{SessionId: t.session, FromNode: t.from, ToNode: t.to, Title: t.title,
		Size: int64(len(t.data)), Sha256: t.sha}
	for off := 0; off < len(t.data); off += 64 << 10 {
		end := min(off+64<<10, len(t.data))
		p := &nodev1.TeleportPart{TeleportId: t.id, Chunk: t.data[off:end], Last: end == len(t.data)}
		if off == 0 {
			p.Header = header
		}
		parts = append(parts, p)
	}
	if tamper != nil {
		parts = tamper(parts)
	}
	for _, p := range parts {
		if err := st.Send(p); err != nil {
			return err
		}
	}
	f.tele.mu.Lock()
	t.status = "delivered"
	f.tele.mu.Unlock()
	return nil
}
