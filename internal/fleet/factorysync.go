package fleet

import (
	"context"
	"runtime"
	"time"

	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/headless"
	"github.com/vulnetix/belai/internal/repomemory"
	"github.com/vulnetix/belai/internal/sessionsync"
	"github.com/vulnetix/belai/internal/version"
)

// FactorySync is a Keleustes server's backends for a worker: its session
// mirror, its shared memory and its audit streams. Each is the same
// sessionsync driver the website uses, so the gates are the same.
type FactorySync struct {
	Backend sessionsync.Backend
	// Memory and MemoryState replicate the worker's lessons (nil: none).
	Memory      sessionsync.MemoryClient
	MemoryState string
	// Audit receives the host's audit streams (nil: none).
	Audit sessionsync.AuditBackend
}

// startFactorySync starts the audit upload and memory replication to the
// factory and returns what stops them (uploading the last lessons first).
func (w *Worker) startFactorySync() func() {
	f := w.Factory
	dir, err := config.GlobalDir()
	if err != nil {
		return func() {}
	}
	var stops []func()
	if f.Audit != nil {
		if aud := sessionsync.StartAuditOn(context.Background(), f.Audit, headless.HostID(),
			sessionsync.Host{Hostname: sessionsync.Hostname(), OS: runtime.GOOS, BelaiVersion: version.Version}, dir); aud != nil {
			stops = append(stops, func() { aud.Close(5 * time.Second) })
		}
	}
	if f.Memory != nil {
		mctx, mcancel := context.WithCancel(context.Background())
		repl := sessionsync.NewMemoryReplicator(f.Memory, headless.HostID(), repomemory.Root(dir))
		if f.MemoryState != "" {
			repl.UseStateFile(f.MemoryState)
		}
		repl.Start(mctx)
		stops = append(stops, func() {
			fctx, fcancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer fcancel()
			_ = repl.Upload(fctx)
			mcancel()
		})
	}
	return func() {
		for i := len(stops) - 1; i >= 0; i-- {
			stops[i]()
		}
	}
}
