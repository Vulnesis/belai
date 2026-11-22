//go:build unix

package rc

import "syscall"

func execSelf(exe string, argv, env []string) error { return syscall.Exec(exe, argv, env) }
