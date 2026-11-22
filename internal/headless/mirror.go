package headless

import (
	"context"
	"os"
	"runtime"
	"time"

	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/session"
	"github.com/vulnetix/belai/internal/sessionsync"
	"github.com/vulnetix/belai/internal/version"
)

// Mirror uploads a headless `belai -prompt` run's transcript to the Keleustes
// server this host joined (kind "headless"), the way the ACP mirror does
// (docs/keleustes.md#sessions). It uploads only the lines the transcript
// writer already wrote and takes nothing back: no remote prompt, answer or
// command reaches the run, so neither Keleustes nor its kill switch can drive
// it, and a stopped factory still receives the record of what ran. The
// website never gets a headless transcript; without a Keleustes profile, with
// sync.enabled off or with -no-transcript there is no mirror.
type Mirror struct {
	syncer *sessionsync.Syncer
	close  func() error
	info   sessionsync.SessionInfo
	active bool
}

// mirrorBackend is the session upload to Keleustes; a variable so a test can
// stand in for the server.
var mirrorBackend = func(dir string) (sessionsync.Backend, func() error, error) {
	be, err := factorylink.ActiveBackend(dir, "headless")
	if err != nil {
		return nil, nil, err
	}
	return be, be.Close, nil
}

// StartMirror starts the mirror for session id in workdir, or returns nil
// (every method is safe on nil).
func StartMirror(settings config.Settings, workdir, id, provider, model, mode string) *Mirror {
	if !settings.SyncEnabled() || id == "" {
		return nil
	}
	dir, err := config.GlobalDir()
	if err != nil {
		return nil
	}
	be, closeBe, err := mirrorBackend(dir)
	if err != nil {
		return nil
	}
	store, err := session.NewStore()
	if err != nil {
		_ = closeBe()
		return nil
	}
	key, err := session.KeyFor(workdir)
	if err != nil {
		_ = closeBe()
		return nil
	}
	hostID, _ := sessionsync.HostID(dir)
	if mode == "" {
		mode = "agent"
	}
	syncer := sessionsync.New(sessionsync.Options{
		Backend:       be,
		HostID:        hostID,
		Host:          sessionsync.Host{Hostname: sessionsync.Hostname(), OS: runtime.GOOS, BelaiVersion: version.Version},
		RemotePrompts: false,
		RemoteAnswers: false,
	})
	syncer.Start(context.Background())
	audit.Emit(audit.Fact{Kind: audit.HostDispatch, ActorKind: audit.ActorHuman, SessionID: id,
		Data: map[string]string{"dispatch": "headless", "status": "mirrored"}})
	return &Mirror{syncer: syncer, close: closeBe, info: sessionsync.SessionInfo{
		ID: id, Path: store.SessionPath(key, id), ProjectKey: string(key), ProjectName: key.Project(),
		Cwd: workdir, Model: model, Provider: provider, Mode: mode,
	}}
}

// Touch registers the session once its file exists and asks for the lines
// just written.
func (m *Mirror) Touch() {
	if m == nil {
		return
	}
	if !m.active {
		if _, err := os.Stat(m.info.Path); err != nil {
			return
		}
		m.syncer.Activate(m.info)
		m.active = true
	}
	m.syncer.Nudge()
}

// Close uploads what is left, ends the session on Keleustes and drops the
// connection.
func (m *Mirror) Close() {
	if m == nil {
		return
	}
	m.Touch()
	m.syncer.Close(3 * time.Second)
	_ = m.close()
}
