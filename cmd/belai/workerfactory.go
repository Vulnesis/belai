package main

import (
	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/fleet"
)

// workerSync holds the Keleustes backends a fleet worker mirrors to.
type workerSync struct {
	fs     *fleet.FactorySync
	closes []func() error
}

// workerFactory returns the Keleustes backends for a worker when this host
// has an active Keleustes profile, else nil.
func workerFactory() *workerSync {
	dir, err := config.GlobalDir()
	if err != nil {
		return nil
	}
	be, err := factorylink.ActiveBackend(dir, "worker")
	if err != nil {
		return nil
	}
	w := &workerSync{fs: &fleet.FactorySync{Backend: be}, closes: []func() error{be.Close}}
	if m, err := factorylink.ActiveMemory(dir); err == nil {
		w.fs.Memory, w.fs.MemoryState = m, m.StateName()
		w.closes = append(w.closes, m.Close)
	}
	if a, err := factorylink.ActiveAudit(dir); err == nil {
		w.fs.Audit = a
		w.closes = append(w.closes, a.Close)
	}
	return w
}

func (w *workerSync) sync() *fleet.FactorySync {
	if w == nil {
		return nil
	}
	return w.fs
}

func (w *workerSync) close() {
	for _, c := range w.closes {
		_ = c()
	}
}
