package rc

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/harness"
	"github.com/vulnetix/belai/internal/harnessdetect"
	"github.com/vulnetix/belai/internal/harnessrun"
	"github.com/vulnetix/belai/internal/proc"
	"github.com/vulnetix/belai/internal/session"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// HarnessStart is a Keleustes dispatch's third-party harness fields
// (Dispatch.harness, harness_mode, harness_resume, harness_keys).
type HarnessStart struct {
	ID, Mode, Resume, Keys string
}

// checkHarness validates a harness start against what this host advertises:
// the harness detected as launchable, a mode its profile maps, a resume id of
// the native shape, a known key mode. It returns the reason it refuses.
func checkHarness(h HarnessStart, model string, cat *harnessdetect.Catalog) string {
	if !harnessrun.Supported || runtime.GOOS == "windows" {
		return "this host cannot run harness sessions"
	}
	d, ok := cat.Get(h.ID)
	if !ok || !d.Launchable() {
		return "this host does not offer that harness"
	}
	if h.Mode != "" && h.Mode != "default" {
		found := false
		for _, m := range d.Modes {
			found = found || m == h.Mode
		}
		if !found {
			return fmt.Sprintf("%s has no mode %q", d.Name, h.Mode)
		}
	}
	if h.Resume != "" && (!d.Resume || !harness.NativeIDShape.MatchString(h.Resume)) {
		return "that native session cannot be resumed here"
	}
	if model != "" && !harness.ModelShape.MatchString(model) {
		return "the model is not a model id"
	}
	if !harnessrun.ValidKeyMode(h.Keys) {
		return "unknown key mode"
	}
	return ""
}

// harnessChildArgs is the fixed argv of one `belai rc-harness`. The prompt
// goes over stdin and a grant over its own pipe, never argv.
func harnessChildArgs(dispatch, sid string, h HarnessStart, model string, controls bool) []string {
	args := []string{"rc-harness", "-dispatch", dispatch, "-session-id", sid, "-harness", h.ID}
	for _, f := range [][2]string{{"-mode", h.Mode}, {"-model", model}, {"-resume", h.Resume}, {"-keys", h.Keys}} {
		if f[1] != "" {
			args = append(args, f[0], f[1])
		}
	}
	if controls {
		args = append(args, "-controls")
	}
	return args
}

// startHarness starts a harness session for a Keleustes dispatch, under the
// same directory, session-cap and workspace rules as a belai session. The
// caller has already checked the kill switch and the deadline.
func (d *Daemon) startHarness(r sessionsync.Dispatch, h HarnessStart, grant *factorylink.Grant) (string, string) {
	if why := checkHarness(h, r.Model, harnessdetect.Default); why != "" {
		return "", why
	}
	if h.Keys == "" || h.Keys == harnessrun.KeysOwnLogin {
		// Own login: the grant never leaves the daemon.
		if grant != nil {
			grant.Drop()
		}
		grant = nil
	}
	cwd, ok := Allowed(d.dirs(), r.Cwd)
	if !ok {
		return "", "this host does not offer that directory"
	}
	d.mu.Lock()
	if len(d.sessions) >= d.o.Max {
		n := len(d.sessions)
		d.mu.Unlock()
		return "", fmt.Sprintf("this host is already running %d of %d sessions", n, d.o.Max)
	}
	d.mu.Unlock()
	sid, err := session.NewID()
	if err != nil {
		return "", "could not mint a session id"
	}
	cmd := exec.Command(d.o.Exe, harnessChildArgs(r.ID, sid, h, r.Model, d.o.Controls)...)
	cmd.Dir = cwd
	cmd.Env = withoutGrantFD(os.Environ())
	cmd.Stdin = strings.NewReader(sessionsync.CleanPrompt(r.Prompt))
	var grantR, grantW *os.File
	if grant != nil {
		if grantR, grantW, err = os.Pipe(); err != nil {
			return "", "could not start Belai: " + err.Error()
		}
		cmd.ExtraFiles = []*os.File{grantR}
		cmd.Env = append(cmd.Env, factorylink.GrantFDEnv+"=3")
	}
	logPath := d.sessionLog(sid)
	var logFile *os.File
	if logPath != "" {
		if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err == nil {
			if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
				logFile = f
				cmd.Stdout, cmd.Stderr = f, f
			}
		}
	}
	proc.SetProcessGroup(cmd)
	// exec.Command, not CommandContext: a stop signals the group itself.
	cmd.Cancel = nil
	if err := cmd.Start(); err != nil {
		if logFile != nil {
			logFile.Close()
		}
		if grantR != nil {
			grantR.Close()
			grantW.Close()
		}
		return "", "could not start Belai: " + err.Error()
	}
	if grantR != nil {
		grantR.Close()
		go writeGrant(grantW, grant.Encode())
	}
	pid := cmd.Process.Pid
	d.mu.Lock()
	d.sessions[sid] = &child{RunningSession{ID: sid, Dispatch: r.ID, Cwd: cwd, PID: pid, Started: time.Now()}}
	d.mu.Unlock()
	d.writeRecord()
	d.logf("started %s harness session %s in %s (pid %d)", h.ID, short(sid), cwd, pid)
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		err := cmd.Wait()
		if logFile != nil {
			logFile.Close()
		}
		d.mu.Lock()
		delete(d.sessions, sid)
		d.mu.Unlock()
		d.writeRecord()
		if err != nil {
			d.logf("harness session %s ended: %v (log: %s)", short(sid), err, logPath)
		} else {
			d.logf("harness session %s ended", short(sid))
		}
	}()
	return sid, ""
}
