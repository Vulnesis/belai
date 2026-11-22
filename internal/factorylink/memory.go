package factorylink

import (
	"context"
	"crypto/sha256"
	"strings"
	"sync"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/repomemory"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// MemoryRemote replicates the shared repository memory (internal/repomemory)
// through the Board service: it is the sessionsync.MemoryClient the
// MemoryReplicator uses, so uploads, pulls, tombstones and newest-wins are
// the website's code, with only the server changed.
//
// Scopes map onto Keleustes's single scope string: a repository note's key
// ("acme/api") is its scope, and a profile lesson is "profile:<name>". A
// Keleustes note in any other scope ("global") has no belai home and is not
// pulled. A note written in the Keleustes console has a uuid id, which is not
// a belai note id; it is stored under a stable "web-" id derived from it, and
// a change this host makes to it is sent back under the original.
//
// Pulled notes are remote content: repomemory.Apply cleans them and a model
// reads them only through RepoMemoryRead (KindRepoMemory, classified).
type MemoryRemote struct {
	c *Client

	mu      sync.Mutex
	foreign map[string]string // derived belai id -> Keleustes id
}

var _ sessionsync.MemoryClient = (*MemoryRemote)(nil)

// NewMemoryRemote builds the memory backend on c.
func NewMemoryRemote(c *Client) *MemoryRemote {
	return &MemoryRemote{c: c, foreign: map[string]string{}}
}

// ActiveMemory returns the memory backend for this host's active, unrevoked
// profile, or ErrNoProfile.
func ActiveMemory(home string) (*MemoryRemote, error) {
	c, err := activeClient(home)
	if err != nil {
		return nil, err
	}
	return NewMemoryRemote(c), nil
}

// StateName is the replicator's marks file for this server, so the marks a
// host keeps for the website and for each Keleustes server never mix.
func (m *MemoryRemote) StateName() string {
	return "replica-keleustes-" + m.c.Profile().ServerID + ".json"
}

// Close drops the connection.
func (m *MemoryRemote) Close() error { return m.c.Close() }

const profileScopePrefix = "profile:"

// PostMemory pushes each note; the server keeps the newest change per id.
func (m *MemoryRemote) PostMemory(ctx context.Context, _ string, notes []repomemory.Note) (sessionsync.MemoryPostResult, error) {
	var res sessionsync.MemoryPostResult
	for _, n := range notes {
		pb, ok := m.toNote(n)
		if !ok {
			continue
		}
		if _, err := m.c.MemoryPush(ctx, pb); err != nil {
			return res, mapErr(err)
		}
		res.Accepted++
	}
	return res, nil
}

// GetMemory pulls the notes changed after the cursor (milliseconds). scope
// and scopeKey are always empty from the replicator: everything is pulled.
func (m *MemoryRemote) GetMemory(ctx context.Context, _, _ string, after int64, _ int) (sessionsync.MemoryPage, error) {
	page, err := m.c.MemoryPull(ctx, "", after)
	if err != nil {
		return sessionsync.MemoryPage{}, mapErr(err)
	}
	out := sessionsync.MemoryPage{LastSeq: max(page.GetNextSinceMs(), after)}
	for _, n := range page.GetNotes() {
		if note, ok := m.fromNote(n); ok {
			out.Notes = append(out.Notes, note)
		}
	}
	return out, nil
}

func (m *MemoryRemote) toNote(n repomemory.Note) (*nodev1.MemoryNote, bool) {
	var scope string
	switch n.Scope {
	case repomemory.ScopeRepo:
		scope = n.ScopeKey
	case repomemory.ScopeProfile:
		scope = profileScopePrefix + n.ScopeKey
	default:
		return nil, false
	}
	id := n.NoteID
	m.mu.Lock()
	if orig, ok := m.foreign[id]; ok {
		id = orig
	}
	m.mu.Unlock()
	out := &nodev1.MemoryNote{Id: id, Scope: scope, Text: n.Text, Tags: n.Tags, Author: n.AgentID,
		CreatedAtMs: n.CreatedAt, UpdatedAtMs: max(n.UpdatedAt, n.CreatedAt)}
	if n.DeletedAt != 0 {
		out.Deleted = true
		out.UpdatedAtMs = max(out.UpdatedAtMs, n.DeletedAt)
	}
	return out, true
}

func (m *MemoryRemote) fromNote(n *nodev1.MemoryNote) (repomemory.Note, bool) {
	scope, key := repomemory.ScopeRepo, strings.ToLower(n.GetScope())
	if rest, ok := strings.CutPrefix(n.GetScope(), profileScopePrefix); ok {
		scope, key = repomemory.ScopeProfile, rest
	}
	if !repomemory.ValidScopeKey(scope, key) {
		return repomemory.Note{}, false
	}
	id := n.GetId()
	out := repomemory.Note{NoteID: id, Scope: scope, ScopeKey: key, Text: n.GetText(), Tags: n.GetTags(),
		CreatedAt: n.GetCreatedAtMs(), UpdatedAt: n.GetUpdatedAtMs()}
	probe := out
	probe.Text = "x"
	if _, ok := probe.Clean(); !ok || id == "" {
		// Not a belai id (a console note): a stable stand-in.
		out.NoteID = foreignNoteID(id)
		m.mu.Lock()
		m.foreign[out.NoteID] = id
		m.mu.Unlock()
	}
	if author := n.GetAuthor(); author != "" {
		out.AgentID = author // kept only when it has an agent id's shape
	}
	if n.GetDeleted() {
		out.DeletedAt = max(n.GetUpdatedAtMs(), n.GetCreatedAtMs(), 1)
	}
	return out, true
}

// foreignNoteID is "web-" and 26 lower-case Crockford characters derived from
// a Keleustes note id.
func foreignNoteID(id string) string {
	const crockford = "0123456789abcdefghjkmnpqrstvwxyz"
	sum := sha256.Sum256([]byte("keleustes-note:" + id))
	var b strings.Builder
	b.WriteString("web-")
	var acc uint64
	bits := 0
	for _, c := range sum {
		acc = acc<<8 | uint64(c)
		bits += 8
		for bits >= 5 && b.Len() < 30 {
			bits -= 5
			b.WriteByte(crockford[(acc>>uint(bits))&31])
		}
	}
	return b.String()
}
