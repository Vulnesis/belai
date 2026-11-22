package rc

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/harness"
	"github.com/vulnetix/belai/internal/harnessdetect"
	"github.com/vulnetix/belai/internal/harnessrun"
	"github.com/vulnetix/belai/internal/sanitize"
)

// harnessAdvert maps the detected harnesses onto the advert: identifiers,
// states and the registry's own lists, never a value.
func harnessAdvert() ([]*nodev1.Harness, bool) {
	var out []*nodev1.Harness
	for _, h := range harnessdetect.Default.All() {
		a := &nodev1.Harness{Id: h.ID, Name: h.Name, Version: h.Version, State: h.State, Detail: h.Detail,
			Resume: h.Resume, A2A: h.A2A, LoggedIn: h.LoggedIn, Modes: h.Modes, Transcript: h.Transcript,
			AllowKeys: h.AllowKeys, Path: h.Path, VersionHash: h.VersionHash, ProbedAtMs: h.ProbedAt, Conf: h.Conf,
			Kill: h.Kill, Asks: h.Asks, Named: h.Named, Continuity: h.Continuity, StartupP50Ms: h.StartupP50MS,
			StartupP95Ms: h.StartupP95MS, StartupSamples: uint32(max(h.Samples, 0)), StartupMeasuredAtMs: h.MeasuredAt}
		for _, c := range h.Caveats {
			a.Caveats = append(a.Caveats, &nodev1.HarnessCaveat{Code: sanitize.Ident(c.Code, 40), Note: sanitize.Line(c.Note, 200)})
		}
		if r, ok := harness.ByID(h.ID); ok && r.Launch != nil {
			a.GrantEnv = r.Launch.GrantEnv
		}
		out = append(out, a)
	}
	return out, harnessrun.Supported
}

// watchHarnesses keeps harnessdetect.Default current (every ten minutes and
// on SIGHUP) and calls changed after each change, so the advert follows.
func (d *Daemon) watchHarnesses(ctx context.Context, changed func()) {
	if !harnessrun.Supported {
		return
	}
	home, _ := os.UserHomeDir()
	kick := make(chan struct{}, 1)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP)
	defer signal.Stop(sig)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
				select {
				case kick <- struct{}{}:
				default:
				}
			}
		}
	}()
	timing := ""
	if g, err := config.GlobalDir(); err == nil {
		timing = filepath.Join(g, "harness", "timing.jsonl")
	}
	harnessdetect.Watch(ctx, harnessdetect.Options{Home: home, Path: os.Getenv("PATH"), TimingFile: timing}, 10*time.Minute, kick,
		func(h []harnessdetect.Harness) {
			harnessdetect.Default.Set(h)
			if changed != nil {
				changed()
			}
		})
}
