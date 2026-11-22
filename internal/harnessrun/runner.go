package harnessrun

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/vulnetix/belai/internal/harness"
	"github.com/vulnetix/belai/internal/vaultenv"
)

// Timings. Tests shrink them.
type Timings struct {
	// ReadyQuiet is how long the screen must be still after the first output
	// for a TUI without bracketed paste to count as ready; ReadyMax caps the
	// wait.
	ReadyQuiet, ReadyMax time.Duration
	// ChunkGap separates 4 KiB writes (some Node TUIs drop large writes).
	ChunkGap time.Duration
	// ExitWait and TermWait are the stop escalation's waits: after the exit
	// sequence, then after SIGTERM, before SIGKILL.
	ExitWait, TermWait time.Duration
}

// DefaultTimings are the production timings.
var DefaultTimings = Timings{ReadyQuiet: 800 * time.Millisecond, ReadyMax: 20 * time.Second,
	ChunkGap: 2 * time.Millisecond, ExitWait: 5 * time.Second, TermWait: 5 * time.Second}

// ScreenBytes is the replay a new viewer gets.
const ScreenBytes = 256 << 10

// Runner is one harness process on a terminal.
type Runner struct {
	term    Term
	profile *harness.Launch
	t       Timings

	modes  Modes
	ring   *Ring
	writeM sync.Mutex

	lastOut   atomic.Int64 // unix ms of the last output
	firstOut  atomic.Int64
	outBytes  atomic.Int64
	done      chan struct{}
	exit      Exit
	stopping  atomic.Bool
	viewersMu sync.Mutex
	viewers   map[int]func([]byte)
	nextView  int
	scrub     *vaultenv.Writer
	// raw is the unscrubbed recent output, read in this process only (dialog
	// matching); it never leaves it.
	raw *Ring
	// screen is the emulated terminal (raw output; this process only).
	screen *grid
}

// StartRunner starts the harness and its output reader.
func StartRunner(start Starter, s Spawn, profile *harness.Launch, t Timings) (*Runner, error) {
	if start == nil {
		start = StartPTY
	}
	term, err := start(s)
	if err != nil {
		return nil, err
	}
	r := &Runner{term: term, profile: profile, t: t, ring: NewRing(ScreenBytes), raw: NewRing(16 << 10), screen: newGrid(int(max(s.Cols, 20)), int(max(s.Rows, 5))), done: make(chan struct{}),
		viewers: map[int]func([]byte){}}
	// Output leaves the process only scrubbed of every concealed value, a
	// value split across chunks included.
	r.scrub = vaultenv.NewWriter(writerFunc(r.fanout), vaultenv.Default)
	go r.read()
	return r, nil
}

type writerFunc func([]byte)

func (f writerFunc) Write(p []byte) (int, error) { f(p); return len(p), nil }

func (r *Runner) read() {
	buf := make([]byte, 32<<10)
	for {
		n, err := r.term.Read(buf)
		if n > 0 {
			now := time.Now().UnixMilli()
			r.firstOut.CompareAndSwap(0, now)
			r.lastOut.Store(now)
			r.outBytes.Add(int64(n))
			r.modes.Feed(buf[:n])
			_, _ = r.raw.Write(buf[:n])
			_, _ = r.screen.Write(buf[:n])
			_, _ = r.scrub.Write(append([]byte(nil), buf[:n]...))
		}
		if err != nil {
			break
		}
	}
	_ = r.scrub.Close()
	r.exit = r.term.Wait()
	close(r.done)
}

func (r *Runner) fanout(p []byte) {
	_, _ = r.ring.Write(p)
	r.viewersMu.Lock()
	vs := make([]func([]byte), 0, len(r.viewers))
	for _, v := range r.viewers {
		vs = append(vs, v)
	}
	r.viewersMu.Unlock()
	for _, v := range vs {
		v(p)
	}
}

// Attach adds a screen viewer: it gets the replay now, then every chunk
// (already scrubbed). The returned func detaches it.
func (r *Runner) Attach(view func([]byte)) (replay []byte, offset int64, detach func()) {
	r.viewersMu.Lock()
	id := r.nextView
	r.nextView++
	r.viewers[id] = view
	r.viewersMu.Unlock()
	replay, offset = r.ring.Snapshot()
	return replay, offset, func() {
		r.viewersMu.Lock()
		delete(r.viewers, id)
		r.viewersMu.Unlock()
	}
}

// Screen is the kept output.
func (r *Runner) Screen() []byte { b, _ := r.ring.Snapshot(); return b }

// Done is closed when the harness has exited.
func (r *Runner) Done() <-chan struct{} { return r.done }

// Exit is how it ended (valid after Done).
func (r *Runner) Exit() Exit { return r.exit }

// PID is the harness's process id.
func (r *Runner) PID() int { return r.term.PID() }

// Bracketed reports whether the TUI has bracketed paste on.
func (r *Runner) Bracketed() bool { return r.modes.Bracketed() }

// Quiet is how long the screen has been still (0 before any output).
func (r *Runner) Quiet() time.Duration {
	last := r.lastOut.Load()
	if last == 0 {
		return 0
	}
	return time.Since(time.UnixMilli(last))
}

// Ready waits until the TUI can take a prompt: bracketed paste is on, or the
// screen has been still for ReadyQuiet after its first output; ReadyMax at
// most.
func (r *Runner) Ready(ctx context.Context) error {
	deadline := time.Now().Add(r.t.ReadyMax)
	for {
		if r.Bracketed() || (r.firstOut.Load() != 0 && r.Quiet() >= r.t.ReadyQuiet) {
			return nil
		}
		if time.Now().After(deadline) {
			if r.firstOut.Load() != 0 {
				return nil
			}
			return errors.New("the harness drew nothing")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.done:
			return errors.New("the harness exited before it was ready")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// write sends bytes in 4 KiB chunks.
func (r *Runner) write(p []byte) error {
	r.writeM.Lock()
	defer r.writeM.Unlock()
	for len(p) > 0 {
		n := min(len(p), 4<<10)
		if _, err := r.term.Write(p[:n]); err != nil {
			return err
		}
		p = p[n:]
		if len(p) > 0 && r.t.ChunkGap > 0 {
			time.Sleep(r.t.ChunkGap)
		}
	}
	return nil
}

// Type types one prompt and submits it: bracketed paste when the TUI has it
// on, then the submit key after the profile's delay. text is neutralised
// here; a refused prompt types nothing.
func (r *Runner) Type(text string) error {
	b, err := PromptBytes(text, r.Bracketed(), r.profile.Input)
	if err != nil {
		return err
	}
	if err := r.write(b); err != nil {
		return err
	}
	time.Sleep(time.Duration(r.profile.Input.SubmitDelayMS) * time.Millisecond)
	submit := r.profile.Input.Submit
	if submit == "" {
		submit = "enter"
	}
	return r.write([]byte(harness.KeyBytes[submit]))
}

// Key sends one allowlisted key.
func (r *Runner) Key(name string) error {
	b, err := KeyBytes(name, r.profile.Keys.Allow)
	if err != nil {
		return err
	}
	return r.write(b)
}

// Interrupt sends the profile's interrupt key.
func (r *Runner) Interrupt() error {
	k := r.profile.Keys.Interrupt
	if k == "" {
		k = "esc"
	}
	return r.write([]byte(harness.KeyBytes[k]))
}

// Stop ends the harness: the profile's exit sequence, then SIGTERM to the
// process group, then SIGKILL, waiting between each. It returns the steps
// taken ("exit", "term", "kill").
func (r *Runner) Stop() []string {
	if !r.stopping.CompareAndSwap(false, true) {
		<-r.done
		return nil
	}
	var steps []string
	select {
	case <-r.done:
		return steps
	default:
	}
	if seq := ExitBytes(r.profile.Keys.Exit); len(seq) > 0 {
		steps = append(steps, "exit")
		for _, b := range seq {
			_ = r.write(b)
			time.Sleep(100 * time.Millisecond)
		}
		if r.wait(r.t.ExitWait) {
			return steps
		}
	}
	steps = append(steps, "term")
	_ = r.term.Signal(syscall.SIGTERM)
	if r.wait(r.t.TermWait) {
		return steps
	}
	steps = append(steps, "kill")
	_ = r.term.Signal(syscall.SIGKILL)
	<-r.done
	return steps
}

func (r *Runner) wait(d time.Duration) bool {
	select {
	case <-r.done:
		return true
	case <-time.After(d):
		return false
	}
}

// Resize sets the terminal size, clamped to 20..300 columns and 5..120 rows.
func (r *Runner) Resize(cols, rows uint16) error {
	c, w := min(max(cols, 20), 300), min(max(rows, 5), 120)
	r.screen.resize(int(c), int(w))
	return r.term.Resize(c, w)
}

var _ io.Writer = writerFunc(nil)
