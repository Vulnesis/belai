//go:build linux || darwin || freebsd

package hostmgmt

import "golang.org/x/sys/unix"

// freeBytes is the space available to this user on dir's filesystem.
func freeBytes(dir string) int64 {
	var st unix.Statfs_t
	if unix.Statfs(dir, &st) != nil {
		return 0
	}
	return int64(st.Bavail) * int64(st.Bsize)
}
