package factorylink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// FetchAttachment serves the fake's blobs in 3-byte parts, the whole size on
// the first.
func (f *fakeKeleustes) FetchAttachment(in *nodev1.AttachmentRequest, st nodev1.Sessions_FetchAttachmentServer) error {
	f.mu.Lock()
	f.fetches = append(f.fetches, in)
	b, ok := f.blobs[in.GetSha256()]
	f.mu.Unlock()
	if !ok {
		return status.Error(codes.NotFound, "unknown attachment")
	}
	for i := 0; i < len(b); i += 3 {
		end := min(i+3, len(b))
		p := &nodev1.AttachmentPart{Chunk: b[i:end], Last: end == len(b)}
		if i == 0 {
			p.Size = int64(len(b))
		}
		if err := st.Send(p); err != nil {
			return err
		}
	}
	return nil
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Row 53: a prompt's attachments are read naming its item and checked
// against their hash before the session sees them; one that does not match
// refuses the prompt, saying why.
func TestInboxPromptAttachments(t *testing.T) {
	f := newFakeKeleustes(t)
	good, liar := []byte("notes for the turn"), []byte("something else")
	f.blobs = map[string][]byte{sum(good): good, sum([]byte("claimed")): liar}
	c, _ := NewClient(f.p)
	be := NewSyncBackend(c, "rc")
	defer be.Close()
	att := func(b []byte, name string) *nodev1.Attachment {
		return &nodev1.Attachment{Name: name, Mime: "text/plain", Sha256: sum(b), Size: int64(len(b))}
	}
	f.box("s1") <- &nodev1.InboxItem{Seq: 1, Id: "p1", SessionId: "s1", Body: &nodev1.InboxItem_Prompt{Prompt: &nodev1.Prompt{
		Text: "read this", Attachments: []*nodev1.Attachment{att(good, "notes.md")}}}}
	f.box("s1") <- &nodev1.InboxItem{Seq: 2, Id: "p2", SessionId: "s1", Body: &nodev1.InboxItem_Prompt{Prompt: &nodev1.Prompt{
		Text: "and this", Attachments: []*nodev1.Attachment{{Name: "x.md", Mime: "text/plain", Sha256: sum([]byte("claimed")), Size: int64(len(liar))}}}}}
	var in sessionsync.Inbox
	waitFor(t, "the inbox", func() bool {
		got, _ := be.InboxBatchA2A(context.Background(), "", "s1", 200*time.Millisecond, -1)
		in.Prompts = append(in.Prompts, got.Prompts...)
		return len(in.Prompts) > 0
	})
	if len(in.Prompts) != 1 || len(in.Prompts[0].Attachments) != 1 || string(in.Prompts[0].Attachments[0].Data) != string(good) ||
		in.Prompts[0].Attachments[0].Name != "notes.md" {
		t.Fatalf("prompts = %+v", in.Prompts)
	}
	// p2 may arrive in a later batch than p1 (a loaded machine), and it is
	// checked, and refused, only when a batch carries it: keep reading.
	deadline := time.Now().Add(10 * time.Second)
	for refused := false; !refused; {
		select {
		case a := <-f.acks:
			if a.GetItemId() != "p2" || a.GetStatus() != "refused" || !strings.Contains(a.GetDetail(), "SHA-256") {
				t.Fatalf("ack = %v", a)
			}
			refused = true
		default:
			if time.Now().After(deadline) {
				t.Fatal("the mismatched attachment was not refused")
			}
			got, _ := be.InboxBatchA2A(context.Background(), "", "s1", 200*time.Millisecond, -1)
			if len(got.Prompts) > 0 {
				t.Fatalf("a refused prompt reached the session: %+v", got.Prompts)
			}
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.fetches) < 1 || f.fetches[0].GetSessionId() != "s1" || f.fetches[0].GetItemId() != "p1" {
		t.Errorf("fetches = %v", f.fetches)
	}
}
