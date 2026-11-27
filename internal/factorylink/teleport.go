package factorylink

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// Teleport through Keleustes (docs/teleport.md#keleustes): the origin node
// uploads a session bundle with Teleport.Upload, either for a teleport
// Keleustes requested (a `teleport` job naming its id) or for one it starts
// itself (no id, a target node in the header). Keleustes stores the bytes
// content-addressed, checked against the header's size and SHA-256, and
// Teleport.Download hands them to the addressed node only, until the
// teleport expires.
//
// The bytes this package downloads are another host's: the caller decodes
// and checks them as untrusted content (internal/teleport). This file only
// moves them and proves they are the bytes the header names.

// TeleportMaxBytes is the largest bundle Keleustes accepts (its
// TELEPORT_MAX_BYTES); a larger one is refused before anything is sent, and a
// download that claims more is refused before it is read.
const TeleportMaxBytes = 256 << 20

// teleportChunk is the size of each uploaded part.
const teleportChunk = 256 << 10

// teleportTimeout bounds one upload or download stream.
const teleportTimeout = 10 * time.Minute

// teleportIDShape is a teleport id Keleustes mints (a UUID), and idShape a
// node or session id. Anything else is refused before it is sent.
var (
	teleportIDShape = regexp.MustCompile(`^[0-9A-Fa-f-]{8,64}$`)
	nodeIDShape     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

// ValidTeleportID reports whether id has the shape of a Keleustes teleport id.
func ValidTeleportID(id string) bool { return teleportIDShape.MatchString(id) }

// ValidNodeID reports whether id has the shape of a Keleustes node id.
func ValidNodeID(id string) bool { return nodeIDShape.MatchString(id) }

// TeleportUpload names what a bundle is for.
type TeleportUpload struct {
	// TeleportID is the teleport Keleustes requested, or empty when this node
	// starts the teleport itself (ToNode is then required).
	TeleportID string
	SessionID  string
	ToNode     string
	Title      string
	// Needs are the agent profile the session ran under and the crews that
	// list it (names only, never a built-in), so Keleustes can back them up
	// and the target can install what it lacks.
	Needs []TeleportNeed
}

// TeleportNeed is one profile or crew a teleported session needs.
type TeleportNeed struct {
	// Kind is "profile" or "crew".
	Kind, Name string
	// ID, Version and SHA256 are the library's copy, on a download only.
	ID      string
	Version int64
	SHA256  string
}

// MaxTeleportNeeds bounds the needs one header carries (Keleustes caps them
// the same).
const MaxTeleportNeeds = 24

// needName is a profile or crew name a header may carry; built-ins
// ("belai:…") have a colon and never match.
var needName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}$`)

// libraryIDShape is a library item id Keleustes mints (a UUID).
var libraryIDShape = regexp.MustCompile(`^[0-9A-Fa-f-]{8,64}$`)

// CleanTeleportNeeds keeps the well-formed profile and crew needs, built-ins
// dropped, de-duplicated and capped at MaxTeleportNeeds. On a download the
// library's id, version and hash are kept when well formed; they are
// Keleustes's and still untrusted.
func CleanTeleportNeeds(in []TeleportNeed) []TeleportNeed {
	var out []TeleportNeed
	seen := map[string]bool{}
	for _, n := range in {
		if (n.Kind != "profile" && n.Kind != "crew") || !needName.MatchString(n.Name) {
			continue
		}
		k := n.Kind + "/" + n.Name
		if seen[k] || len(out) >= MaxTeleportNeeds {
			continue
		}
		seen[k] = true
		if !libraryIDShape.MatchString(n.ID) {
			n.ID = ""
		}
		if n.SHA256 = strings.ToLower(n.SHA256); len(n.SHA256) != 64 {
			n.SHA256 = ""
		}
		if n.Version < 0 {
			n.Version = 0
		}
		out = append(out, n)
	}
	return out
}

// needsPB is the upload header's needs: kinds and names only.
func needsPB(in []TeleportNeed) []*nodev1.LibraryRef {
	var out []*nodev1.LibraryRef
	for _, n := range CleanTeleportNeeds(in) {
		out = append(out, &nodev1.LibraryRef{Kind: n.Kind, Name: n.Name})
	}
	return out
}

// needsOf is a download header's needs, cleaned.
func needsOf(in []*nodev1.LibraryRef) []TeleportNeed {
	var out []TeleportNeed
	for _, r := range in {
		out = append(out, TeleportNeed{Kind: r.GetKind(), Name: r.GetName(), ID: r.GetId(), Version: r.GetVersion(), SHA256: r.GetSha256()})
	}
	return CleanTeleportNeeds(out)
}

// TeleportBundle is a downloaded bundle and its header. Every string is
// Keleustes's (and the origin node's) and untrusted.
type TeleportBundle struct {
	TeleportID string
	SessionID  string
	FromNode   string
	ToNode     string
	Title      string
	// Needs are the profiles and crews the session needs, as Keleustes's
	// library holds them.
	Needs []TeleportNeed
	// Data is the bundle, already checked against the header's size and
	// SHA-256.
	Data []byte
}

// UploadTeleport streams data to Keleustes as the bundle u describes and
// returns the teleport id it was stored under. The header carries this
// node's id, the size and the SHA-256, so Keleustes verifies what it
// received before it stores it.
func (c *Client) UploadTeleport(ctx context.Context, u TeleportUpload, data []byte) (string, error) {
	if u.TeleportID != "" && !teleportIDShape.MatchString(u.TeleportID) {
		return "", errors.New("teleport id is not an id")
	}
	if u.TeleportID == "" && !nodeIDShape.MatchString(u.ToNode) {
		return "", errors.New("a teleport this node starts names the node it goes to")
	}
	if u.ToNode != "" && !nodeIDShape.MatchString(u.ToNode) {
		return "", errors.New("target node id is not an id")
	}
	if u.ToNode != "" && u.ToNode == c.p.NodeID {
		return "", errors.New("a teleport moves a session to another node")
	}
	if len(data) == 0 {
		return "", errors.New("the teleport bundle is empty")
	}
	if len(data) > TeleportMaxBytes {
		return "", fmt.Errorf("the teleport bundle is %d bytes, more than the %d Keleustes takes", len(data), TeleportMaxBytes)
	}
	sum := sha256.Sum256(data)
	header := &nodev1.TeleportHeader{
		SessionId: u.SessionID, FromNode: c.p.NodeID, ToNode: u.ToNode,
		Title: u.Title, Size: int64(len(data)), Sha256: hex.EncodeToString(sum[:]),
		Needs: needsPB(u.Needs),
	}
	conn, err := c.cc()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, teleportTimeout)
	defer cancel()
	st, err := nodev1.NewTeleportClient(conn).Upload(ctx)
	if err != nil {
		c.failed(conn, err)
		return "", err
	}
	for off := 0; off < len(data); off += teleportChunk {
		end := min(off+teleportChunk, len(data))
		part := &nodev1.TeleportPart{TeleportId: u.TeleportID, Chunk: data[off:end], Last: end == len(data)}
		if off == 0 {
			part.Header = header
		}
		if err := st.Send(part); err != nil {
			if errors.Is(err, io.EOF) {
				// The server ended the stream early: its status says why.
				_, err = st.CloseAndRecv()
			}
			c.failed(conn, err)
			return "", err
		}
	}
	rec, err := st.CloseAndRecv()
	if err != nil {
		c.failed(conn, err)
		return "", err
	}
	if rec.GetSize() != int64(len(data)) {
		return "", fmt.Errorf("keleustes stored %d bytes of a %d-byte bundle", rec.GetSize(), len(data))
	}
	id := rec.GetTeleportId()
	if !teleportIDShape.MatchString(id) || (u.TeleportID != "" && id != u.TeleportID) {
		return "", errors.New("keleustes answered the upload with another teleport id")
	}
	return id, nil
}

// DownloadTeleport fetches the bundle of teleport id, which Keleustes hands
// only to the node it is addressed to. The request says this node fetches
// the header's needs itself (LibraryFetchTeleport), so Keleustes sends no
// library_install dispatch for them. The bytes are checked against the
// header the first part carries: it must be addressed to this node, the
// declared size must be within TeleportMaxBytes, every part must name this
// teleport, the stream must end on the last part with exactly the declared
// size, and the SHA-256 must match. Anything else is refused whole.
func (c *Client) DownloadTeleport(ctx context.Context, id string) (TeleportBundle, error) {
	if !teleportIDShape.MatchString(id) {
		return TeleportBundle{}, errors.New("that is not a Keleustes teleport id")
	}
	conn, err := c.cc()
	if err != nil {
		return TeleportBundle{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, teleportTimeout)
	defer cancel()
	st, err := nodev1.NewTeleportClient(conn).Download(ctx, &nodev1.TeleportRequest{TeleportId: id, FetchNeeds: true})
	if err != nil {
		c.failed(conn, err)
		return TeleportBundle{}, err
	}
	var (
		out  TeleportBundle
		want int64 = -1
		sum  string
		h    = sha256.New()
		buf  []byte
		last bool
	)
	for !last {
		p, err := st.Recv()
		if errors.Is(err, io.EOF) {
			return TeleportBundle{}, errors.New("the teleport download ended before its last part")
		}
		if err != nil {
			c.failed(conn, err)
			return TeleportBundle{}, err
		}
		if p.GetTeleportId() != "" && p.GetTeleportId() != id {
			return TeleportBundle{}, errors.New("the download sent parts of another teleport")
		}
		if want < 0 {
			hd := p.GetHeader()
			if hd == nil {
				return TeleportBundle{}, errors.New("the download's first part carries no header")
			}
			if hd.GetSize() <= 0 || hd.GetSize() > TeleportMaxBytes {
				return TeleportBundle{}, fmt.Errorf("the bundle claims %d bytes, outside 1..%d", hd.GetSize(), TeleportMaxBytes)
			}
			if hd.GetToNode() != "" && hd.GetToNode() != c.p.NodeID {
				return TeleportBundle{}, errors.New("that teleport is not addressed to this node")
			}
			sum = strings.ToLower(hd.GetSha256())
			if len(sum) != 64 {
				return TeleportBundle{}, errors.New("the bundle's header carries no SHA-256")
			}
			want = hd.GetSize()
			buf = make([]byte, 0, want)
			out = TeleportBundle{TeleportID: id, SessionID: hd.GetSessionId(), FromNode: hd.GetFromNode(),
				ToNode: hd.GetToNode(), Title: hd.GetTitle(), Needs: needsOf(hd.GetNeeds())}
		}
		if int64(len(buf))+int64(len(p.GetChunk())) > want {
			return TeleportBundle{}, errors.New("the bundle is larger than its header says")
		}
		buf = append(buf, p.GetChunk()...)
		h.Write(p.GetChunk())
		last = p.GetLast()
	}
	if int64(len(buf)) != want {
		return TeleportBundle{}, fmt.Errorf("the bundle is %d bytes, its header said %d", len(buf), want)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sum {
		return TeleportBundle{}, errors.New("the bundle does not match its SHA-256")
	}
	out.Data = buf
	return out, nil
}

// NodeID is the id Keleustes gave this node.
func (c *Client) NodeID() string { return c.p.NodeID }

// UploadTeleport uploads a bundle for the daemon (see Client.UploadTeleport).
func (r *RC) UploadTeleport(ctx context.Context, u TeleportUpload, data []byte) (string, error) {
	return r.c.UploadTeleport(ctx, u, data)
}
