// Package analytics records one row of facts per broker request and writes
// them to a database off the serving path. Record never blocks: it hands the
// row to a buffered channel and, when the buffer is full, drops it and counts
// the drop, so a slow or unreachable database can never add latency to a
// model call. A single writer goroutine batches rows into one transaction.
//
// A row holds numbers, enums and identifiers only (route, principal name,
// model id, status, timings, token counts, nonce counts). It never holds a
// prompt, a completion, a header value or a key.
package analytics

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Record is one request's facts.
type Record struct {
	Time       time.Time
	RequestID  string
	Principal  string
	Route      string
	Model      string
	Status     int
	Stream     bool
	LatencyMS  int64 // until the last response byte
	TTFBMS     int64 // until the first response byte from upstream
	QueueMS    int64 // waiting for vLLM to become ready
	ReqBytes   int64
	RespBytes  int64
	PromptTok  int64
	ComplTok   int64
	CachedTok  int64
	NonceMode  string
	Verified   int
	Unknown    int
	Tampered   int
	Stripped   int
	Canonical  int
	ErrorClass string
}

// Store persists batches of records.
type Store interface {
	Insert(ctx context.Context, batch []Record) error
	Close() error
}

// Options tune the recorder.
type Options struct {
	Buffer        int           // channel capacity; default 8192
	BatchSize     int           // rows per transaction; default 256
	FlushInterval time.Duration // default 1s
	Logger        *slog.Logger
}

// Recorder is the non-blocking front of a Store.
type Recorder struct {
	ch      chan Record
	store   Store
	opts    Options
	dropped atomic.Uint64
	failed  atomic.Uint64
	written atomic.Uint64
	once    sync.Once
	done    chan struct{}
}

// NewRecorder starts the writer goroutine. A nil store yields a recorder
// that discards everything.
func NewRecorder(store Store, opts Options) *Recorder {
	if opts.Buffer <= 0 {
		opts.Buffer = 8192
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 256
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = time.Second
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	r := &Recorder{ch: make(chan Record, opts.Buffer), store: store, opts: opts, done: make(chan struct{})}
	go r.run()
	return r
}

// Record queues rec without blocking.
func (r *Recorder) Record(rec Record) {
	if r == nil || r.store == nil {
		return
	}
	rec.Model = Clean(rec.Model, 128)
	rec.Principal = Clean(rec.Principal, 64)
	rec.RequestID = Clean(rec.RequestID, 64)
	select {
	case r.ch <- rec:
	default:
		r.dropped.Add(1)
	}
}

// Stats reports rows written, dropped at the buffer and lost to failed writes.
func (r *Recorder) Stats() (written, dropped, failed uint64) {
	return r.written.Load(), r.dropped.Load(), r.failed.Load()
}

// Close stops accepting rows, flushes what is queued within ctx and closes
// the store. Call it only after the HTTP server has stopped.
func (r *Recorder) Close(ctx context.Context) error {
	r.once.Do(func() { close(r.ch) })
	select {
	case <-r.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if r.store != nil {
		return r.store.Close()
	}
	return nil
}

func (r *Recorder) run() {
	defer close(r.done)
	t := time.NewTicker(r.opts.FlushInterval)
	defer t.Stop()
	buf := make([]Record, 0, r.opts.BatchSize)
	flush := func() {
		if len(buf) == 0 || r.store == nil {
			buf = buf[:0]
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := r.store.Insert(ctx, buf)
		cancel()
		if err != nil {
			r.failed.Add(uint64(len(buf)))
			r.opts.Logger.Warn("analytics write failed", "rows", len(buf), "err", err)
		} else {
			r.written.Add(uint64(len(buf)))
		}
		buf = buf[:0]
	}
	for {
		select {
		case rec, ok := <-r.ch:
			if !ok {
				flush()
				return
			}
			buf = append(buf, rec)
			if len(buf) >= r.opts.BatchSize {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

// Clean reduces s to identifier characters and caps it, so a client-supplied
// model name or request id cannot carry arbitrary text into the database.
func Clean(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case strings.ContainsRune("._:/@+-", r):
			b.WriteRune(r)
		}
	}
	return b.String()
}
