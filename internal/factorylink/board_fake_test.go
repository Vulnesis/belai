package factorylink

import (
	"context"
	"sort"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// boardState is the fake Keleustes's Board: cards versioned per item with a
// change clock, notes kept newest-wins, the A2A log, and the control state,
// as the server's kls-node/src/board.rs keeps them.
type boardState struct {
	mu      sync.Mutex
	clock   int64
	cards   map[string]*nodev1.KanbanItem
	changed map[string]int64
	notes   map[string]*nodev1.MemoryNote
	noteAt  map[string]int64
	a2a     []*nodev1.A2AEnvelope
	a2aWake chan struct{}
	control *nodev1.FactoryControl
	pushes  [][]*nodev1.KanbanItem
	scheds  map[string]*nodev1.ScheduleItem
	schedAt map[string]int64
}

func newBoardState() boardState {
	return boardState{cards: map[string]*nodev1.KanbanItem{}, changed: map[string]int64{},
		notes: map[string]*nodev1.MemoryNote{}, noteAt: map[string]int64{},
		a2aWake: make(chan struct{}, 1), control: &nodev1.FactoryControl{}}
}

func (b *boardState) tick() int64 { b.clock++; return b.clock }

// editCard changes a card as the console would: a new version and change.
func (f *fakeKeleustes) editCard(id string, edit func(*nodev1.KanbanItem)) {
	b := &f.board
	b.mu.Lock()
	defer b.mu.Unlock()
	c := b.cards[id]
	edit(c)
	c.Version++
	b.changed[id] = b.tick()
}

func (f *fakeKeleustes) card(id string) *nodev1.KanbanItem {
	b := &f.board
	b.mu.Lock()
	defer b.mu.Unlock()
	if c := b.cards[id]; c != nil {
		return proto.Clone(c).(*nodev1.KanbanItem)
	}
	return nil
}

func (f *fakeKeleustes) KanbanPull(_ context.Context, in *nodev1.KanbanPullRequest) (*nodev1.KanbanPage, error) {
	b := &f.board
	b.mu.Lock()
	defer b.mu.Unlock()
	var ids []string
	for id, at := range b.changed {
		if at > in.GetSinceMs() {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return b.changed[ids[i]] < b.changed[ids[j]] })
	limit := int(in.GetLimit())
	if limit == 0 {
		limit = 200
	}
	more := len(ids) > limit
	if more {
		ids = ids[:limit]
	}
	page := &nodev1.KanbanPage{NextSinceMs: in.GetSinceMs(), More: more}
	for _, id := range ids {
		page.Items = append(page.Items, proto.Clone(b.cards[id]).(*nodev1.KanbanItem))
		page.NextSinceMs = b.changed[id]
	}
	return page, nil
}

func (f *fakeKeleustes) KanbanPush(_ context.Context, in *nodev1.KanbanBatch) (*nodev1.KanbanPushResult, error) {
	b := &f.board
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pushes = append(b.pushes, in.GetItems())
	out := &nodev1.KanbanPushResult{}
	for _, it := range in.GetItems() {
		it = proto.Clone(it).(*nodev1.KanbanItem)
		switch cur := b.cards[it.GetId()]; {
		case cur == nil:
			if it.Key == "" {
				it.Key = "K-" + strings.ReplaceAll(it.GetId(), "-", "")[:4]
			}
			if it.Status == "" {
				it.Status = "triage"
			}
			it.Version = 1
			b.cards[it.Id] = it
		case cur.GetVersion() != it.GetVersion() || cur.GetDeleted():
			out.Conflicts = append(out.Conflicts, proto.Clone(cur).(*nodev1.KanbanItem))
			continue
		default:
			it.Key = cur.Key
			it.Version = cur.Version + 1
			b.cards[it.Id] = it
		}
		b.changed[it.Id] = b.tick()
		out.Accepted = append(out.Accepted, proto.Clone(it).(*nodev1.KanbanItem))
	}
	return out, nil
}

func (f *fakeKeleustes) MemoryPull(_ context.Context, in *nodev1.MemoryPullRequest) (*nodev1.MemoryPage, error) {
	b := &f.board
	b.mu.Lock()
	defer b.mu.Unlock()
	var ids []string
	for id, at := range b.noteAt {
		if at > in.GetSinceMs() && (in.GetScope() == "" || b.notes[id].GetScope() == in.GetScope()) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return b.noteAt[ids[i]] < b.noteAt[ids[j]] })
	page := &nodev1.MemoryPage{NextSinceMs: in.GetSinceMs()}
	for _, id := range ids {
		page.Notes = append(page.Notes, proto.Clone(b.notes[id]).(*nodev1.MemoryNote))
		page.NextSinceMs = b.noteAt[id]
	}
	return page, nil
}

func (f *fakeKeleustes) MemoryPush(_ context.Context, n *nodev1.MemoryNote) (*nodev1.MemoryNote, error) {
	b := &f.board
	b.mu.Lock()
	defer b.mu.Unlock()
	n = proto.Clone(n).(*nodev1.MemoryNote)
	if n.Id == "" {
		n.Id = "0190aaaa-bbbb-7ccc-8ddd-eeeeffff0000"
	}
	if n.Author == "" {
		n.Author = "node-1"
	}
	if cur := b.notes[n.Id]; cur != nil && cur.GetUpdatedAtMs() > n.GetUpdatedAtMs() {
		return proto.Clone(cur).(*nodev1.MemoryNote), nil
	}
	b.notes[n.Id] = n
	b.noteAt[n.Id] = b.tick()
	return proto.Clone(n).(*nodev1.MemoryNote), nil
}

// addNote stores a note as the console would.
func (f *fakeKeleustes) addNote(n *nodev1.MemoryNote) {
	b := &f.board
	b.mu.Lock()
	defer b.mu.Unlock()
	b.notes[n.Id] = n
	b.noteAt[n.Id] = b.tick()
}

func (f *fakeKeleustes) A2ASend(_ context.Context, e *nodev1.A2AEnvelope) (*nodev1.A2ASendResult, error) {
	b := &f.board
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.control.GetA2ABlackout() {
		return &nodev1.A2ASendResult{Refused: "a2a blackout"}, nil
	}
	if !strings.HasPrefix(e.GetFrom(), "node-1:") {
		return nil, status.Error(codes.PermissionDenied, "from must be an agent on this node")
	}
	e = proto.Clone(e).(*nodev1.A2AEnvelope)
	e.Seq = uint64(len(b.a2a) + 1)
	b.a2a = append(b.a2a, e)
	select {
	case b.a2aWake <- struct{}{}:
	default:
	}
	return &nodev1.A2ASendResult{Id: e.GetId(), Delivered: true}, nil
}

// injectA2A stores an envelope from another node.
func (f *fakeKeleustes) injectA2A(e *nodev1.A2AEnvelope) {
	b := &f.board
	b.mu.Lock()
	e.Seq = uint64(len(b.a2a) + 1)
	b.a2a = append(b.a2a, e)
	b.mu.Unlock()
	select {
	case b.a2aWake <- struct{}{}:
	default:
	}
}

func (f *fakeKeleustes) sentA2A() []*nodev1.A2AEnvelope {
	b := &f.board
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]*nodev1.A2AEnvelope(nil), b.a2a...)
}

func (f *fakeKeleustes) A2AReceive(in *nodev1.A2AReceiveRequest, st nodev1.Board_A2AReceiveServer) error {
	after := in.GetAfter()
	for {
		b := &f.board
		b.mu.Lock()
		var send []*nodev1.A2AEnvelope
		if !b.control.GetA2ABlackout() {
			for _, e := range b.a2a {
				if e.GetSeq() <= after {
					continue
				}
				after = e.GetSeq()
				for _, to := range in.GetTo() {
					if e.GetTo() == "" && e.GetFrom() != to || e.GetTo() == to {
						send = append(send, proto.Clone(e).(*nodev1.A2AEnvelope))
						break
					}
				}
			}
		}
		b.mu.Unlock()
		for _, e := range send {
			if err := st.Send(e); err != nil {
				return err
			}
		}
		select {
		case <-st.Context().Done():
			return nil
		case <-b.a2aWake:
		}
	}
}

func (f *fakeKeleustes) State(context.Context, *nodev1.StateRequest) (*nodev1.FactoryControl, error) {
	b := &f.board
	b.mu.Lock()
	defer b.mu.Unlock()
	return proto.Clone(b.control).(*nodev1.FactoryControl), nil
}

// setControl changes the control state; push also sends it on the link.
func (f *fakeKeleustes) setControl(c *nodev1.FactoryControl, seq uint64) {
	b := &f.board
	b.mu.Lock()
	b.control = c
	b.mu.Unlock()
	select {
	case b.a2aWake <- struct{}{}:
	default:
	}
	if seq > 0 {
		f.frames <- &nodev1.ServerFrame{Seq: seq, Body: &nodev1.ServerFrame_Control{Control: c}}
	}
}

func (f *fakeKeleustes) SchedulePull(_ context.Context, in *nodev1.SchedulePullRequest) (*nodev1.SchedulePage, error) {
	b := &f.board
	b.mu.Lock()
	defer b.mu.Unlock()
	page := &nodev1.SchedulePage{NextSinceMs: in.GetSinceMs()}
	for id, s := range b.scheds {
		if at := b.schedAt[id]; at > in.GetSinceMs() {
			page.Items = append(page.Items, s)
			page.NextSinceMs = max(page.NextSinceMs, at)
		}
	}
	return page, nil
}

// SchedulePush is Keleustes's rule: a stale version is a conflict.
func (f *fakeKeleustes) SchedulePush(_ context.Context, in *nodev1.ScheduleBatch) (*nodev1.SchedulePushResult, error) {
	b := &f.board
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.scheds == nil {
		b.scheds, b.schedAt = map[string]*nodev1.ScheduleItem{}, map[string]int64{}
	}
	res := &nodev1.SchedulePushResult{}
	for _, s := range in.GetItems() {
		b.clock++
		if p := b.scheds[s.GetId()]; p != nil && p.GetVersion() > s.GetVersion() {
			p.LastFiredMs, p.LastStatus = s.GetLastFiredMs(), s.GetLastStatus()
			b.schedAt[s.GetId()] = b.clock
			res.Conflicts = append(res.Conflicts, p)
			continue
		}
		c := proto.Clone(s).(*nodev1.ScheduleItem)
		c.Version = max(c.GetVersion(), b.scheds[s.GetId()].GetVersion()) + 1
		b.scheds[s.GetId()], b.schedAt[s.GetId()] = c, b.clock
		res.Accepted = append(res.Accepted, c)
	}
	return res, nil
}
