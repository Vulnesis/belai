//go:build !unix

package rc

func execSelf(string, []string, []string) error { return errNoReexec }
