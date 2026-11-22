//go:build windows

package harnessrun

import "errors"

// StartPTY is not available on Windows: belai has no ConPTY runner and no
// grant descriptor there, so the host advertises no harness sessions.
func StartPTY(Spawn) (Term, error) {
	return nil, errors.New("harness sessions are not supported on Windows")
}

// Supported reports whether this platform runs harness sessions.
const Supported = false
