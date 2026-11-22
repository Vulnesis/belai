package factorylink

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

const testTeleport = "0190f0a2-6b7e-7c1d-8a52-0d9e4f1b7a33"

func teleClient(t *testing.T, f *fakeKeleustes) *Client {
	t.Helper()
	c, err := NewClient(f.p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// A bundle for a teleport Keleustes requested goes up in parts under its id,
// with the header (this node, the target, the size and the SHA-256) on the
// first part and last on the final one, so the server verifies what it stores.
func TestUploadTeleportFillsTheRequestedTeleport(t *testing.T) {
	f := newFakeKeleustes(t)
	c := teleClient(t, f)
	f.requestTeleport(testTeleport, "sess-1", "node-1", "node-2")
	data := randomBytes(t, 600<<10)

	id, err := c.UploadTeleport(context.Background(), TeleportUpload{TeleportID: testTeleport, SessionID: "sess-1", ToNode: "node-2", Title: "fix it"}, data)
	if err != nil {
		t.Fatal(err)
	}
	if id != testTeleport {
		t.Fatalf("id = %q", id)
	}
	tp := f.teleport(testTeleport)
	if tp.status != "ready" || !bytes.Equal(tp.data, data) || tp.title != "fix it" {
		t.Fatalf("stored = %s %d bytes %q", tp.status, len(tp.data), tp.title)
	}
	parts := f.tele.parts[0]
	if len(parts) != 3 || parts[0].GetHeader() == nil || parts[1].GetHeader() != nil {
		t.Fatalf("%d parts, header on the first only: %v", len(parts), parts[0].GetHeader())
	}
	h := parts[0].GetHeader()
	if h.GetFromNode() != "node-1" || h.GetToNode() != "node-2" || h.GetSize() != int64(len(data)) || h.GetSha256() != tp.sha {
		t.Errorf("header = %+v", h)
	}
	for i, p := range parts {
		if p.GetLast() != (i == len(parts)-1) || p.GetTeleportId() != testTeleport {
			t.Errorf("part %d: last=%v id=%q", i, p.GetLast(), p.GetTeleportId())
		}
	}
}

// A node that starts a teleport itself sends no id and names the target; the
// server mints the id. A teleport this node may not fill, an unknown one, and
// one addressed back to this node are refused.
func TestUploadTeleportStartedByTheNodeAndItsRefusals(t *testing.T) {
	f := newFakeKeleustes(t)
	c := teleClient(t, f)
	data := []byte("bundle")

	id, err := c.UploadTeleport(context.Background(), TeleportUpload{SessionID: "sess-1", ToNode: "node-2"}, data)
	if err != nil || !ValidTeleportID(id) {
		t.Fatalf("id = %q, err = %v", id, err)
	}
	if tp := f.teleport(id); tp == nil || tp.to != "node-2" || tp.status != "ready" {
		t.Fatalf("stored = %+v", tp)
	}

	f.requestTeleport(testTeleport, "sess-1", "node-3", "node-2")
	if _, err := c.UploadTeleport(context.Background(), TeleportUpload{TeleportID: testTeleport, ToNode: "node-2"}, data); status.Code(err) != codes.PermissionDenied {
		t.Errorf("another node's teleport: %v", err)
	}
	if _, err := c.UploadTeleport(context.Background(), TeleportUpload{TeleportID: "0190f0a2-0000-7000-8000-00000000ffff"}, data); status.Code(err) != codes.NotFound {
		t.Errorf("unknown teleport: %v", err)
	}
	for name, u := range map[string]TeleportUpload{
		"to itself":    {ToNode: "node-1"},
		"no target":    {},
		"a bad id":     {TeleportID: "../../x", ToNode: "node-2"},
		"a bad target": {ToNode: "node 2"},
		"empty":        {ToNode: "node-2"},
	} {
		d := data
		if name == "empty" {
			d = nil
		}
		if _, err := c.UploadTeleport(context.Background(), u, d); err == nil {
			t.Errorf("%s was uploaded", name)
		}
	}
}

// A download returns exactly the bytes the header names, and is refused whole
// when it is not addressed to this node, when a byte differs from the SHA-256,
// when it is shorter or longer than the header says, or when it ends before
// its last part.
func TestDownloadTeleportChecksTheBundleAgainstItsHeader(t *testing.T) {
	f := newFakeKeleustes(t)
	c := teleClient(t, f)
	data := randomBytes(t, 300<<10)
	f.readyTeleport(testTeleport, "sess-1", "node-2", "node-1", data)

	b, err := c.DownloadTeleport(context.Background(), testTeleport)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.Data, data) || b.SessionID != "sess-1" || b.FromNode != "node-2" || b.TeleportID != testTeleport {
		t.Fatalf("bundle = %+v (%d bytes)", b.TeleportID, len(b.Data))
	}

	other := "0190f0a2-6b7e-7c1d-8a52-0d9e4f1b7a34"
	f.readyTeleport(other, "sess-1", "node-1", "node-2", data)
	if _, err := c.DownloadTeleport(context.Background(), other); status.Code(err) != codes.PermissionDenied {
		t.Errorf("a teleport for another node: %v", err)
	}
	if _, err := c.DownloadTeleport(context.Background(), "x/../y"); err == nil {
		t.Error("a malformed id was requested")
	}

	cases := map[string]func([]*nodev1.TeleportPart) []*nodev1.TeleportPart{
		"a changed byte": func(p []*nodev1.TeleportPart) []*nodev1.TeleportPart {
			p[1].Chunk = append([]byte{p[1].Chunk[0] ^ 1}, p[1].Chunk[1:]...)
			return p
		},
		"no last part": func(p []*nodev1.TeleportPart) []*nodev1.TeleportPart { return p[:len(p)-1] },
		"an extra part": func(p []*nodev1.TeleportPart) []*nodev1.TeleportPart {
			p[len(p)-1].Last = false
			return append(p, &nodev1.TeleportPart{Chunk: []byte("more"), Last: true})
		},
		"a short bundle": func(p []*nodev1.TeleportPart) []*nodev1.TeleportPart {
			p[len(p)-2].Last = true
			return p[:len(p)-1]
		},
		"no header": func(p []*nodev1.TeleportPart) []*nodev1.TeleportPart {
			p[0].Header = nil
			return p
		},
		"another node's header": func(p []*nodev1.TeleportPart) []*nodev1.TeleportPart {
			p[0].Header.ToNode = "node-9"
			return p
		},
		"an oversized claim": func(p []*nodev1.TeleportPart) []*nodev1.TeleportPart {
			p[0].Header.Size = TeleportMaxBytes + 1
			return p
		},
		"parts of another teleport": func(p []*nodev1.TeleportPart) []*nodev1.TeleportPart {
			p[1].TeleportId = other
			return p
		},
	}
	for name, tamper := range cases {
		f.readyTeleport(testTeleport, "sess-1", "node-2", "node-1", data)
		f.tele.mu.Lock()
		f.tele.tamper = tamper
		f.tele.mu.Unlock()
		if _, err := c.DownloadTeleport(context.Background(), testTeleport); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
