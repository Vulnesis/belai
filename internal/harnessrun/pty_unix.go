//go:build !windows

package harnessrun

import (
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"

	"github.com/creack/pty"
)

type ptyTerm struct {
	f    *os.File
	cmd  *exec.Cmd
	once sync.Once
	exit Exit
}

// StartPTY runs the harness on a new pseudo-terminal as the leader of its own
// session and process group, so a stop reaches every process it started.
func StartPTY(s Spawn) (Term, error) {
	if len(s.Argv) == 0 {
		return nil, errors.New("harnessrun: empty argv")
	}
	cmd := exec.Command(s.Argv[0], s.Argv[1:]...)
	cmd.Dir, cmd.Env = s.Dir, s.Env
	// pty.StartWithAttrs sets the controlling terminal; Setsid makes the
	// harness its own session and process group leader.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	f, err := pty.StartWithAttrs(cmd, &pty.Winsize{Cols: s.Cols, Rows: s.Rows}, cmd.SysProcAttr)
	if err != nil {
		return nil, err
	}
	return &ptyTerm{f: f, cmd: cmd}, nil
}

func (t *ptyTerm) Read(p []byte) (int, error)  { return t.f.Read(p) }
func (t *ptyTerm) Write(p []byte) (int, error) { return t.f.Write(p) }
func (t *ptyTerm) PID() int                    { return t.cmd.Process.Pid }

func (t *ptyTerm) Resize(cols, rows uint16) error {
	return pty.Setsize(t.f, &pty.Winsize{Cols: cols, Rows: rows})
}

func (t *ptyTerm) Signal(sig syscall.Signal) error {
	// The negative pid is the process group.
	return syscall.Kill(-t.cmd.Process.Pid, sig)
}

func (t *ptyTerm) Wait() Exit {
	t.once.Do(func() {
		err := t.cmd.Wait()
		_ = t.f.Close()
		ps := t.cmd.ProcessState
		if ps != nil {
			t.exit.Code = ps.ExitCode()
			if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
				t.exit.Signal = ws.Signal().String()
			}
		}
		if err != nil && ps == nil {
			t.exit.Err = err.Error()
		}
	})
	return t.exit
}

// Supported reports whether this platform runs harness sessions.
const Supported = true

// GroupGone reports whether the harness's process group has no process left
// (kill(-pgid, 0) fails with ESRCH).
func (t *ptyTerm) GroupGone() bool {
	return errors.Is(syscall.Kill(-t.cmd.Process.Pid, 0), syscall.ESRCH)
}
