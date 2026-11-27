package rc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/imageguard"
	"github.com/vulnetix/belai/internal/run"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// Keleustes attachments (belai-counterparts #53, docs/keleustes.md#attachments):
// files and images on a remote prompt or on a session dispatch's first
// prompt. factorylink reads the bytes and checks them against the listed
// size and SHA-256; AdmitAttachments then admits them exactly as the TUI
// admits a local `@` attachment (internal/tui/attach.go,
// docs/image-attachments.md): an image through imageguard alone, whatever
// the guardrails say, and a text file through the host's classifier. One
// refusal refuses the whole prompt or start; refused bytes are never echoed.

// AdmitFunc admits one piece of remote text a model will read (the daemon's
// Options.AdmitText bound to a directory).
type AdmitFunc func(ctx context.Context, subject, text string) (string, error)

// AdmitAttachments admits raw attachments, in order, as run attachments.
func AdmitAttachments(ctx context.Context, raw []sessionsync.RemoteAttachment, admit AdmitFunc) ([]run.Attachment, error) {
	if len(raw) > factorylink.MaxAttachments {
		return nil, fmt.Errorf("at most %d attachments", factorylink.MaxAttachments)
	}
	total := 0
	out := make([]run.Attachment, 0, len(raw))
	for _, a := range raw {
		name := sanitize.Line(a.Name, 64)
		if name == "" || strings.ContainsAny(a.Name, "/\\") {
			return nil, errors.New("an attachment has no plain file name")
		}
		sum := sha256.Sum256(a.Data)
		if hex.EncodeToString(sum[:]) != a.SHA256 {
			return nil, fmt.Errorf("%s does not match its SHA-256", name)
		}
		limit, ok := factorylink.AttachmentMediaTypes[a.MediaType]
		if !ok {
			return nil, fmt.Errorf("%s: only PNG and JPEG images and UTF-8 text files can be attached", name)
		}
		if len(a.Data) == 0 || int64(len(a.Data)) > limit {
			return nil, fmt.Errorf("%s is larger than %d KiB", name, limit>>10)
		}
		if total += len(a.Data); total > factorylink.MaxAttachmentTotalBytes {
			return nil, fmt.Errorf("attachments total at most %d MiB", factorylink.MaxAttachmentTotalBytes>>20)
		}
		switch a.MediaType {
		case "image/png", "image/jpeg":
			// A decode-safety bound, not a posture gate: never the classifier.
			img, err := imageguard.Admit(a.Data, imageguard.Default)
			if err != nil {
				return nil, fmt.Errorf("%s: the image was not admitted: %s", name, clip(err.Error()))
			}
			out = append(out, run.Attachment{Kind: run.AttachmentImage, Label: "@" + name, MediaType: imageguard.MediaType, Data: img.PNG})
		default:
			if !utf8.Valid(a.Data) || bytes.IndexByte(a.Data, 0) >= 0 {
				return nil, fmt.Errorf("%s is not UTF-8 text", name)
			}
			if admit == nil {
				return nil, errors.New("this host cannot check attached text")
			}
			body, err := admit(ctx, "attachment "+name, string(a.Data))
			if err != nil {
				return nil, fmt.Errorf("%s was withheld: %s", name, clip(err.Error()))
			}
			out = append(out, run.Attachment{Kind: "file", Label: "@" + name, Body: body})
		}
	}
	return out, nil
}

// attachmentsDigest names a list of attachments for an audit line: each one's
// media type, size and hash prefix, never a byte of it.
func attachmentsDigest(raw []sessionsync.RemoteAttachment) string {
	parts := make([]string, 0, len(raw))
	for _, a := range raw {
		h := a.SHA256
		if len(h) > 16 {
			h = h[:16]
		}
		parts = append(parts, fmt.Sprintf("%s:%d:%s", a.MediaType, len(a.Data), h))
	}
	return strings.Join(parts, ",")
}

// auditAttachments records the attachments a prompt or a start took or refused.
func auditAttachments(sid, outcome string, raw []sessionsync.RemoteAttachment, why string) {
	data := map[string]string{"dispatch": "session", "status": outcome, "attachments": attachmentsDigest(raw)}
	if why != "" {
		data["reason"] = clip(why)
	}
	audit.Emit(audit.Fact{Kind: audit.HostDispatch, ActorKind: audit.ActorWeb, SessionID: sid, Outcome: outcome, Data: data})
}

// AttachmentFetcher is the part of a Factory that reads a dispatch's
// attachments (*factorylink.RC). A Factory without it takes none.
type AttachmentFetcher interface {
	FetchAttachments(ctx context.Context, dispatchID string, list []*nodev1.Attachment) ([]sessionsync.RemoteAttachment, error)
}

// factoryAttachments reads a session dispatch's attachments from Keleustes.
func (d *Daemon) factoryAttachments(ctx context.Context, fd *nodev1.Dispatch) ([]sessionsync.RemoteAttachment, string) {
	list := fd.GetAttachments()
	if len(list) == 0 {
		return nil, ""
	}
	f, ok := d.o.Factory.(AttachmentFetcher)
	if !ok {
		return nil, "this host cannot read attachments"
	}
	raw, err := f.FetchAttachments(ctx, fd.GetId(), list)
	if err != nil {
		return nil, "an attachment could not be read: " + clip(err.Error())
	}
	return raw, ""
}

// attachmentsPath is the 0600 file a session's admitted attachments go to.
func (d *Daemon) attachmentsPath(sid string) string {
	p := d.answersPath(sid)
	if p == "" {
		return ""
	}
	return strings.TrimSuffix(p, ".answers.json") + ".attachments.json"
}

// maxAttachmentsFile bounds the file the child reads: admitted images are
// re-encoded PNGs within imageguard's cap, text within its own, as base64.
const maxAttachmentsFile = 64 << 20

// WriteAttachmentsFile writes admitted attachments for the child to read.
func WriteAttachmentsFile(path string, atts []run.Attachment) error {
	b, err := json.Marshal(atts)
	if err != nil {
		return err
	}
	return writeAnswers(path, b)
}

// ReadAttachmentsFile reads the attachments the daemon admitted for this
// session, and removes the file. "" reads none.
func ReadAttachmentsFile(path string) ([]run.Attachment, error) {
	if path == "" {
		return nil, nil
	}
	defer os.Remove(path)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxAttachmentsFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxAttachmentsFile {
		return nil, errors.New("the attachments file is too large")
	}
	var atts []run.Attachment
	if err := json.Unmarshal(b, &atts); err != nil {
		return nil, errors.New("the attachments file is not readable")
	}
	if len(atts) > factorylink.MaxAttachments {
		return nil, errors.New("the attachments file holds too many")
	}
	for _, a := range atts {
		if a.Kind != run.AttachmentImage && a.Kind != "file" {
			return nil, errors.New("the attachments file holds an unknown kind")
		}
	}
	return atts, nil
}

// admitIn is the daemon's text admission for cwd, or nil when it has none
// (every attached text file is then refused).
func (d *Daemon) admitIn(cwd string) AdmitFunc {
	if d.o.AdmitText == nil {
		return nil
	}
	return func(ctx context.Context, subject, text string) (string, error) {
		return d.o.AdmitText(ctx, cwd, subject, text)
	}
}

// auditPromptAttachments records the attachments a remote prompt carried and
// whether they were admitted.
func auditPromptAttachments(dispatch string, p sessionsync.RemotePrompt, err error) {
	outcome, why := "prompt_attachments", ""
	if err != nil {
		outcome, why = "prompt_attachments_refused", err.Error()
	}
	data := map[string]string{"dispatch": "prompt", "status": outcome, "attachments": attachmentsDigest(p.Attachments),
		"prompt": sanitize.Ident(p.ID, 64), "via": sanitize.Ident(dispatch, 64)}
	if why != "" {
		data["reason"] = clip(why)
	}
	audit.Emit(audit.Fact{Kind: audit.HostDispatch, ActorKind: audit.ActorWeb, SessionID: p.SessionID, Outcome: outcome, Data: data})
}

// attachmentMarkers are what the transcript records of admitted
// attachments: a marker per attachment, never its bytes (as the TUI's
// `images` marker).
func attachmentMarkers(atts []run.Attachment) []map[string]any {
	out := make([]map[string]any, 0, len(atts))
	for _, a := range atts {
		m := map[string]any{"name": strings.TrimPrefix(a.Label, "@"), "kind": a.Kind}
		if a.Kind == run.AttachmentImage {
			m["media_type"], m["bytes"] = a.MediaType, len(a.Data)
		} else {
			m["bytes"] = len(a.Body)
		}
		out = append(out, m)
	}
	return out
}
