package harnessrun

import (
	"io"
	"syscall"
)

// Term is a running harness on a terminal: its output, its input, its size
// and its process group.
type Term interface {
	io.ReadWriter
	// Resize sets the terminal size.
	Resize(cols, rows uint16) error
	// Signal signals the harness's whole process group.
	Signal(sig syscall.Signal) error
	// Wait waits for the harness to exit and closes the terminal.
	Wait() Exit
	PID() int
}

// Exit is how the harness ended.
type Exit struct {
	Code   int    `json:"code"`
	Signal string `json:"signal,omitempty"`
	Err    string `json:"err,omitempty"`
}

// Spawn is one harness to start: the absolute binary is Argv[0].
type Spawn struct {
	Argv       []string
	Dir        string
	Env        []string
	Cols, Rows uint16
}

// Starter starts a Spawn; StartPTY is the real one.
type Starter func(Spawn) (Term, error)
