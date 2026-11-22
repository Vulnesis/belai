package hostmgmt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/vulnetix/belai/internal/sanitize"
)

// The version check after rc_restart, and the rollback to belai.prev
// (docs/gaps/host-management.md §5.5). Before the re-exec the old process
// writes a marker naming the action, the version it expects and the backup;
// the new process reads it when host management starts (recover):
//
//   - its own version matches, or none was expected: the restart is done;
//   - it does not match: belai.prev goes back over the binary, the action
//     fails saying why, and the daemon re-execs into the restored binary.
//
// The marker is removed before that re-exec and the action is settled, so a
// rollback happens once and cannot loop. A binary that crashes before host
// management starts cannot roll itself back; that needs a supervisor.

// restartMarker is what the old process leaves for the new one.
type restartMarker struct {
	ActionID string `json:"actionId"`
	Expect   string `json:"expect,omitempty"`
	Exe      string `json:"exe"`
	Prev     string `json:"prev,omitempty"`
}

func (m *Manager) markerPath() string {
	// Beside the queue, not in it: the queue reads every *.json there.
	return filepath.Join(filepath.Dir(m.q.dir), "hostrestart.json")
}

func (m *Manager) writeMarker(mk restartMarker) error {
	b, err := json.Marshal(mk)
	if err != nil {
		return err
	}
	tmp := m.markerPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.markerPath())
}

func (m *Manager) readMarker() (restartMarker, bool) {
	var mk restartMarker
	b, err := os.ReadFile(m.markerPath())
	if err != nil || json.Unmarshal(b, &mk) != nil || mk.ActionID == "" {
		return restartMarker{}, false
	}
	return mk, true
}

// sameVersion compares release versions with or without the leading "v".
func sameVersion(a, b string) bool {
	return strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v")
}

// checkRestart settles the running restart the marker names. It reports
// whether it did (recover settles any other restart done).
func (m *Manager) checkRestart(id string) bool {
	mk, ok := m.readMarker()
	if !ok || mk.ActionID != id {
		return false
	}
	_ = os.Remove(m.markerPath())
	if mk.Expect == "" || sameVersion(mk.Expect, m.o.Version) {
		m.settleOffline(id, stateDone, "")
		return true
	}
	why := "version mismatch after restart: belai " + sanitize.Ident(m.o.Version, 64) +
		" is running, " + sanitize.Ident(mk.Expect, 64) + " was expected"
	if mk.Prev == "" || mk.Exe == "" {
		m.settleOffline(id, stateFailed, why+"; no belai.prev to roll back to")
		return true
	}
	if err := backup(mk.Prev, mk.Exe); err != nil {
		m.settleOffline(id, stateFailed, why+"; the rollback to belai.prev failed")
		return true
	}
	m.settleOffline(id, stateFailed, why+"; rolled back to belai.prev")
	if m.o.Hooks.Reexec != nil {
		// Into the restored binary. On success this does not return.
		if err := m.o.Hooks.Reexec(); err != nil {
			m.o.Logf("host management: re-exec after rollback: %v", err)
		}
	}
	return true
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular()
}
