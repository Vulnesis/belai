package harnessrun

import (
	"context"
	"time"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// ScreenStream is one Screen.Stream call (node to Keleustes).
type ScreenStream interface {
	Send(*nodev1.ScreenUp) error
	Recv() (*nodev1.ScreenDown, error)
	CloseSend() error
}

// ScreenOpener opens a Screen.Stream.
type ScreenOpener func(ctx context.Context) (ScreenStream, error)

// MaxScreenChunk caps one output frame.
const MaxScreenChunk = 32 << 10

// serveScreen streams the harness's terminal to Keleustes: an open frame with
// the replay, then output while a viewer is attached (Keleustes sends pause
// when none is). Output is already scrubbed of concealed values (Runner).
// The viewer sends no input on this stream: keys go through the inbox.
func (s *Session) serveScreen(ctx context.Context, open ScreenOpener) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := s.screenOnce(ctx, open)
		if ctx.Err() != nil {
			return
		}
		select {
		case <-s.r.Done():
			return
		default:
		}
		if err == nil {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 30*time.Second)
	}
}

func (s *Session) screenOnce(ctx context.Context, open ScreenOpener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	st, err := open(ctx)
	if err != nil {
		return err
	}
	defer st.CloseSend()
	out := make(chan []byte, 256)
	replay, off, detach := s.r.Attach(func(p []byte) {
		select {
		case out <- append([]byte(nil), p...):
		default: // a slow link drops frames; the next open resyncs
		}
	})
	defer detach()
	size := &nodev1.ScreenSize{Cols: 120, Rows: 40}
	sendOpen := func(replay []byte, off int64) error {
		if len(replay) > ScreenBytes {
			replay = replay[len(replay)-ScreenBytes:]
		}
		return st.Send(&nodev1.ScreenUp{SessionId: s.c.SessionID, Offset: uint64(off - int64(len(replay))),
			Body: &nodev1.ScreenUp_Open{Open: &nodev1.ScreenOpen{Size: size, Replay: replay}}})
	}
	if err := sendOpen(replay, off); err != nil {
		return err
	}
	type down struct {
		pause  *bool
		resize *nodev1.ScreenSize
	}
	downs := make(chan down, 8)
	go func() {
		defer close(downs)
		for {
			d, err := st.Recv()
			if err != nil {
				return
			}
			switch b := d.GetBody().(type) {
			case *nodev1.ScreenDown_Pause:
				p := b.Pause
				downs <- down{pause: &p}
			case *nodev1.ScreenDown_Resize:
				downs <- down{resize: b.Resize}
			}
		}
	}()
	paused := true
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.r.Done():
			ex := s.r.Exit()
			_ = st.Send(&nodev1.ScreenUp{SessionId: s.c.SessionID, Offset: uint64(off),
				Body: &nodev1.ScreenUp_Exit{Exit: &nodev1.ScreenExit{Code: int32(ex.Code), Signal: ex.Signal}}})
			return nil
		case d, ok := <-downs:
			if !ok {
				return nil
			}
			if d.resize != nil {
				_ = s.r.Resize(uint16(d.resize.GetCols()), uint16(d.resize.GetRows()))
				size = d.resize
				_ = st.Send(&nodev1.ScreenUp{SessionId: s.c.SessionID, Offset: uint64(off), Body: &nodev1.ScreenUp_Size{Size: size}})
			}
			if d.pause != nil {
				if paused && !*d.pause {
					// A viewer attached: resync it from the replay.
					rep, o := s.r.ring.Snapshot()
					off = o
					if err := sendOpen(rep, o); err != nil {
						return err
					}
				}
				paused = *d.pause
			}
		case p := <-out:
			start := off
			off += int64(len(p))
			if paused {
				continue
			}
			for len(p) > 0 {
				n := min(len(p), MaxScreenChunk)
				if err := st.Send(&nodev1.ScreenUp{SessionId: s.c.SessionID, Offset: uint64(start),
					Body: &nodev1.ScreenUp_Output{Output: p[:n]}}); err != nil {
					return err
				}
				start += int64(n)
				p = p[n:]
			}
		}
	}
}
