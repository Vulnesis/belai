package factorylink

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// KanbanRemote is the board sync's backend over the Board service: it
// satisfies kanban.Remote exactly as the website client does, so the same
// kanban.Syncer, the same local file and the same merge rules serve both.
//
// Keleustes keeps a version per card and refuses an edit based on a stale
// one, returning its own copy. That copy is handed back on the next pull,
// where the ordinary last-writer-wins merge settles it: a newer local edit
// survives with the server's version and is pushed again, an older one gives
// way. The server's card key is authoritative: it is taken from every pull
// and never minted here.
//
// Pulled cards are remote content. They are cleaned by kanban.Merge like any
// pulled item, and reach a model only through KanbanSearch (KindKanban,
// classified).
type KanbanRemote struct {
	c *Client

	mu        sync.Mutex
	conflicts map[string]sessionsync.KanbanItem
}

// NewKanbanRemote builds the board backend on c.
func NewKanbanRemote(c *Client) *KanbanRemote {
	return &KanbanRemote{c: c, conflicts: map[string]sessionsync.KanbanItem{}}
}

// ActiveKanban returns the board backend for this host's active, unrevoked
// profile, or ErrNoProfile.
func ActiveKanban(home string) (*KanbanRemote, error) {
	c, err := activeClient(home)
	if err != nil {
		return nil, err
	}
	return NewKanbanRemote(c), nil
}

// Close drops the connection.
func (k *KanbanRemote) Close() error { return k.c.Close() }

// kanbanPullMax is the largest page the server serves.
const kanbanPullMax = 1000

// KanbanList pulls the cards changed after since (Keleustes's change cursor,
// in milliseconds). Server copies returned by a refused push since the last
// call ride at the front of the page.
func (k *KanbanRemote) KanbanList(ctx context.Context, since int64, limit int) ([]sessionsync.KanbanItem, int64, bool, error) {
	if limit <= 0 || limit > kanbanPullMax {
		limit = kanbanPullMax
	}
	page, err := k.c.KanbanPull(ctx, since, uint32(limit))
	if err != nil {
		return nil, 0, false, mapErr(err)
	}
	k.mu.Lock()
	out := make([]sessionsync.KanbanItem, 0, len(k.conflicts)+len(page.GetItems()))
	for id, c := range k.conflicts {
		out = append(out, c)
		delete(k.conflicts, id)
	}
	k.mu.Unlock()
	for _, it := range page.GetItems() {
		out = append(out, FromKanbanItem(it))
	}
	next := page.GetNextSinceMs()
	if next < since {
		next = since
	}
	return out, next, page.GetMore(), nil
}

// KanbanBatch pushes edits. An accepted card is acknowledged with the
// version the server stored; a conflict is acknowledged as not applied (the
// item stays dirty) and its server copy is kept for the next pull.
func (k *KanbanRemote) KanbanBatch(ctx context.Context, items []sessionsync.KanbanItem) ([]sessionsync.KanbanAck, error) {
	if len(items) == 0 {
		return nil, nil
	}
	pushed := make(map[string]int64, len(items))
	pb := make([]*nodev1.KanbanItem, 0, len(items))
	for _, it := range items {
		pushed[it.ID] = it.UpdatedAt
		pb = append(pb, ToKanbanItem(it))
	}
	res, err := k.c.KanbanPush(ctx, pb)
	if err != nil {
		return nil, mapErr(err)
	}
	acks := make([]sessionsync.KanbanAck, 0, len(items))
	for _, a := range res.GetAccepted() {
		upd, ok := pushed[a.GetId()]
		if !ok {
			continue
		}
		acks = append(acks, sessionsync.KanbanAck{ID: a.GetId(), UpdatedAt: upd, Version: a.GetVersion(), Applied: true})
	}
	k.mu.Lock()
	for _, c := range res.GetConflicts() {
		if _, ok := pushed[c.GetId()]; !ok {
			continue
		}
		k.conflicts[c.GetId()] = FromKanbanItem(c)
		acks = append(acks, sessionsync.KanbanAck{ID: c.GetId(), Applied: false})
	}
	k.mu.Unlock()
	return acks, nil
}

// belaiCard is the host's part of a card's meta_json, under the "belai" key:
// the fields Keleustes has no column for, so another belai host (and this one
// after a reinstall) gets the card back whole.
type belaiCard struct {
	List       string                   `json:"list,omitempty"`
	Project    string                   `json:"project,omitempty"`
	ProjectKey string                   `json:"projectKey,omitempty"`
	Cwd        string                   `json:"cwd,omitempty"`
	HostID     string                   `json:"hostId,omitempty"`
	SessionID  string                   `json:"sessionId,omitempty"`
	History    []sessionsync.KanbanMove `json:"history,omitempty"`
	Agent      *sessionsync.KanbanAgent `json:"agent,omitempty"`
}

// metaBelai is the host's key in a card's meta_json; metaPulledStatus is a
// host-local note of the status last pulled, kept in the item's server meta
// and stripped before a push.
const (
	metaBelai        = "belai"
	metaPulledStatus = "belai.pulledStatus"
)

// Keleustes's card statuses.
const (
	statusTriage  = "triage"
	statusBacklog = "backlog"
	statusTodo    = "todo"
	statusDoing   = "doing"
	statusReview  = "review"
	statusDone    = "done"
)

// statusFor is the Keleustes status a belai list is pushed as. Keleustes has
// no "blocked": a blocked item is a "todo" card whose belai part says blocked.
func statusFor(list string) string {
	switch list {
	case "backlog":
		return statusBacklog
	case "in_progress":
		return statusDoing
	case "review":
		return statusReview
	case "done":
		return statusDone
	case "blocked":
		return statusTodo
	}
	return statusTriage
}

// listFor is the belai list a Keleustes status reads as. hint is the list the
// card's belai part names; it wins when it pushes as this status, so a
// blocked item comes back blocked and a moved card follows the server.
func listFor(status, hint string) string {
	if hint != "" && statusFor(hint) == status {
		return hint
	}
	switch status {
	case statusBacklog, statusTodo:
		return "backlog"
	case statusDoing:
		return "in_progress"
	case statusDone:
		return "done"
	}
	return "review" // triage, review and anything unknown
}

// clampPriority keeps a priority within Keleustes's -2..3.
func clampPriority(p int) int32 { return int32(min(max(p, -2), 3)) }

// ToKanbanItem maps a board item onto a Keleustes card. The columns
// Keleustes shows (status, priority, labels, assignee, repository, branch,
// pull request) carry the routing fields; everything else rides in
// meta_json under "belai", beside the server's own keys, which are sent back
// as they were pulled.
func ToKanbanItem(w sessionsync.KanbanItem) *nodev1.KanbanItem {
	meta := map[string]json.RawMessage{}
	if len(w.Meta) > 0 {
		_ = json.Unmarshal(w.Meta, &meta)
	}
	var pulled string
	if raw, ok := meta[metaPulledStatus]; ok {
		_ = json.Unmarshal(raw, &pulled)
		delete(meta, metaPulledStatus)
	}
	status := statusFor(w.List)
	// A card in a status belai folds into another list (triage) keeps it
	// while the item stays in that list.
	if pulled != "" && pulled != status && listFor(pulled, "") == w.List && w.List != "blocked" {
		status = pulled
	}
	card := belaiCard{List: w.List, Project: w.Project, ProjectKey: w.ProjectKey, Cwd: w.Cwd,
		HostID: w.HostID, SessionID: w.SessionID, History: w.History, Agent: w.Agent}
	if b, err := json.Marshal(card); err == nil {
		meta[metaBelai] = b
	}
	mj, _ := json.Marshal(meta)
	out := &nodev1.KanbanItem{
		Id: w.ID, Key: w.Key, Title: w.Title, Body: w.Body, Status: status,
		Repo: w.Remote, CreatedAtMs: w.CreatedAt, UpdatedAtMs: w.UpdatedAt,
		Version: w.Version, Deleted: w.Deleted, MetaJson: string(mj),
	}
	if a := w.Agent; a != nil {
		out.Priority = clampPriority(a.Priority)
		out.Labels = append([]string(nil), a.Labels...)
		out.Assignee = a.Assignee
		out.Branch = a.Branch
		out.PrUrl = a.PR
	}
	return out
}

// FromKanbanItem maps a Keleustes card onto a board item. The server's
// columns win over the belai part's copies of them (the console edits the
// columns). Every value is cleaned by kanban.Merge before it is stored.
func FromKanbanItem(k *nodev1.KanbanItem) sessionsync.KanbanItem {
	meta := map[string]json.RawMessage{}
	if k.GetMetaJson() != "" {
		_ = json.Unmarshal([]byte(k.GetMetaJson()), &meta)
	}
	var card belaiCard
	if raw, ok := meta[metaBelai]; ok {
		_ = json.Unmarshal(raw, &card)
		delete(meta, metaBelai)
	}
	if b, err := json.Marshal(k.GetStatus()); err == nil {
		meta[metaPulledStatus] = b
	}
	var mj json.RawMessage
	if b, err := json.Marshal(meta); err == nil {
		mj = b
	}
	a := card.Agent
	if a == nil {
		a = &sessionsync.KanbanAgent{}
	}
	a.Labels = append([]string(nil), k.GetLabels()...)
	a.Priority = int(k.GetPriority())
	a.Assignee = k.GetAssignee()
	a.Branch = k.GetBranch()
	a.PR = k.GetPrUrl()
	return sessionsync.KanbanItem{
		ID: k.GetId(), Key: k.GetKey(), Title: k.GetTitle(), Body: k.GetBody(),
		List:    listFor(k.GetStatus(), card.List),
		Project: card.Project, ProjectKey: card.ProjectKey, Remote: k.GetRepo(), Cwd: card.Cwd,
		HostID: card.HostID, SessionID: card.SessionID,
		CreatedAt: k.GetCreatedAtMs(), UpdatedAt: k.GetUpdatedAtMs(), History: card.History,
		Version: k.GetVersion(), Deleted: k.GetDeleted(), Meta: mj, Agent: a,
	}
}
