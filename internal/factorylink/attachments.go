package factorylink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// Attachments on Keleustes prompts and session dispatches
// (belai-counterparts #53, docs/keleustes.md#attachments). A prompt or a
// dispatch carries references only; the bytes are read here with
// Sessions.FetchAttachment, naming the item or the dispatch that lists them,
// and checked against the caps and the listed SHA-256 before anything else
// sees them. What comes back is still untrusted: rc.AdmitAttachments admits
// it as a local `@` attachment is admitted.

// Attachment caps, equal to Keleustes's (kls-core attachments.rs).
const (
	MaxAttachments          = 8
	MaxAttachmentImageBytes = 8 << 20
	MaxAttachmentTextBytes  = 64 << 10
	MaxAttachmentTotalBytes = 16 << 20
	maxAttachmentName       = 255
	attachmentTimeout       = 2 * time.Minute
)

// AttachmentMediaTypes are the media types Keleustes sends.
var AttachmentMediaTypes = map[string]int64{
	"image/png":  MaxAttachmentImageBytes,
	"image/jpeg": MaxAttachmentImageBytes,
	"text/plain": MaxAttachmentTextBytes,
}

// CheckAttachments says why a list of references is refused, or "": the
// count, each name, media type, size and hash, and the total.
func CheckAttachments(list []*nodev1.Attachment) string {
	if len(list) > MaxAttachments {
		return fmt.Sprintf("at most %d attachments", MaxAttachments)
	}
	var total int64
	seen := map[string]bool{}
	for _, a := range list {
		name := a.GetName()
		if name == "" || len(name) > maxAttachmentName || strings.ContainsAny(name, "/\\") || strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return "an attachment has no plain file name"
		}
		limit, ok := AttachmentMediaTypes[a.GetMime()]
		if !ok {
			return "only PNG and JPEG images and UTF-8 text files can be attached"
		}
		if a.GetSize() <= 0 || a.GetSize() > limit {
			return fmt.Sprintf("an attachment is larger than %d KiB", limit>>10)
		}
		sum := a.GetSha256()
		if len(sum) != 64 || strings.Trim(sum, "0123456789abcdef") != "" {
			return "an attachment carries no SHA-256"
		}
		if seen[sum] {
			return "an attachment is listed twice"
		}
		seen[sum] = true
		total += a.GetSize()
	}
	if total > MaxAttachmentTotalBytes {
		return fmt.Sprintf("attachments total at most %d MiB", MaxAttachmentTotalBytes>>20)
	}
	return ""
}

// FetchAttachment reads one attachment's bytes for req (a dispatch, or a
// session's inbox item). The stream must declare the listed size on its
// first part, end on its last part with exactly that many bytes, and hash to
// the listed SHA-256; anything else is refused whole.
func (c *Client) FetchAttachment(ctx context.Context, req *nodev1.AttachmentRequest, a *nodev1.Attachment) ([]byte, error) {
	if why := CheckAttachments([]*nodev1.Attachment{a}); why != "" {
		return nil, errors.New(why)
	}
	conn, err := c.cc()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, attachmentTimeout)
	defer cancel()
	r := &nodev1.AttachmentRequest{Sha256: a.GetSha256(), DispatchId: req.GetDispatchId(), SessionId: req.GetSessionId(), ItemId: req.GetItemId()}
	st, err := nodev1.NewSessionsClient(conn).FetchAttachment(ctx, r)
	if err != nil {
		c.failed(conn, err)
		return nil, mapErr(err)
	}
	want := a.GetSize()
	buf := make([]byte, 0, want)
	first := true
	for {
		p, err := st.Recv()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("the attachment ended before its last part")
		}
		if err != nil {
			return nil, mapErr(err)
		}
		if first {
			if p.GetSize() != want {
				return nil, errors.New("the attachment is not the size it was listed with")
			}
			first = false
		}
		if int64(len(buf))+int64(len(p.GetChunk())) > want {
			return nil, errors.New("the attachment is larger than it was listed")
		}
		buf = append(buf, p.GetChunk()...)
		if p.GetLast() {
			break
		}
	}
	if int64(len(buf)) != want {
		return nil, errors.New("the attachment is smaller than it was listed")
	}
	sum := sha256.Sum256(buf)
	if hex.EncodeToString(sum[:]) != a.GetSha256() {
		return nil, errors.New("the attachment does not match its SHA-256")
	}
	return buf, nil
}

// FetchAttachments reads every attachment of list for req, in order.
func (c *Client) FetchAttachments(ctx context.Context, req *nodev1.AttachmentRequest, list []*nodev1.Attachment) ([]sessionsync.RemoteAttachment, error) {
	if why := CheckAttachments(list); why != "" {
		return nil, errors.New(why)
	}
	out := make([]sessionsync.RemoteAttachment, 0, len(list))
	for _, a := range list {
		b, err := c.FetchAttachment(ctx, req, a)
		if err != nil {
			return nil, err
		}
		out = append(out, sessionsync.RemoteAttachment{Name: a.GetName(), MediaType: a.GetMime(), SHA256: a.GetSha256(), Data: b})
	}
	return out, nil
}

// FetchAttachments on the daemon's connection, for a session dispatch.
func (r *RC) FetchAttachments(ctx context.Context, dispatchID string, list []*nodev1.Attachment) ([]sessionsync.RemoteAttachment, error) {
	return r.c.FetchAttachments(ctx, &nodev1.AttachmentRequest{DispatchId: dispatchID}, list)
}

// attachmentReason is a fetch error as one short line for an ack.
func attachmentReason(err error) string {
	s := strings.Join(strings.Fields(err.Error()), " ")
	if r := []rune(s); len(r) > 200 {
		s = string(r[:199]) + "…"
	}
	return s
}
