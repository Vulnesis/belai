//go:build !(linux || darwin || freebsd)

package hostmgmt

// freeBytes is not measured on this platform.
func freeBytes(string) int64 { return 0 }
