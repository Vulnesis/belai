package hostmgmt

import (
	"context"
	"encoding/json"
	"path/filepath"
	"time"
)

// shell_exec (HM-15): off unless the host runs with --keleustes-shell and
// --keleustes-manage=provision. The person confirms the full argv in the
// preview; it runs with no shell, the scrubbed environment and its own
// process group, from the user's home, for at most 60 s, and its output
// (at most 64 KiB, scrubbed) is the action's lines. The audit line names the
// program and the params digest; the argv itself is in the preview
// Keleustes keeps, because the audit log never holds a command.

const shellTimeout = 60 * time.Second

func planShell(_ context.Context, c *call) (*Plan, string) {
	var argv []string
	_ = json.Unmarshal([]byte(c.p["argv_json"]), &argv)
	path, ok := c.m.look(argv[0])
	if !ok {
		return nil, "the program is not on this host's PATH"
	}
	argv[0] = path
	return &Plan{Params: map[string]string{"argv_json": c.p["argv_json"]},
		Steps: []Step{{Argv: argv, Dir: c.m.o.UserHome, Timeout: int(shellTimeout.Seconds())}}}, ""
}

func runShell(ctx context.Context, c *call, pl *Plan) result {
	if err := c.exec(ctx, pl.Steps[0]); err != nil {
		return failed(err.Error())
	}
	return done("")
}

// shellTool is the program's base name, for the audit.
func shellTool(argvJSON string) string {
	var argv []string
	if json.Unmarshal([]byte(argvJSON), &argv) != nil || len(argv) == 0 {
		return ""
	}
	return filepath.Base(argv[0])
}
