package harnessrun

import (
	"io"
	"strings"
	"sync"

	"github.com/charmbracelet/x/vt"

	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/vaultenv"
)

// grid is the harness's screen as a terminal would show it: the PTY output
// run through a VT emulator (charmbracelet/x/vt) into a cell grid. Full-screen
// TUIs (Codex) redraw by cursor addressing, so only a grid reads their
// questions reliably. It holds raw output and stays in this process: what
// leaves is matched against it (dialogs) or scrubbed first (snapshots).
type grid struct {
	mu sync.Mutex
	e  *vt.Emulator
}

func newGrid(cols, rows int) *grid {
	g := &grid{e: vt.NewEmulator(cols, rows)}
	// The emulator answers terminal queries on its own pipe; nobody reads
	// them back into the harness, so drain them or the next write blocks.
	// The drain lives as long as the process (one harness per rc-harness):
	// the emulator's Close races its own Read.
	go func() { _, _ = io.Copy(io.Discard, g.e) }()
	return g
}

func (g *grid) Write(p []byte) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.e.Write(p)
}

func (g *grid) resize(cols, rows int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.e.Resize(cols, rows)
}

// text is the visible screen, one line per row, trailing blanks trimmed.
func (g *grid) text() string {
	g.mu.Lock()
	s := g.e.String()
	g.mu.Unlock()
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return strings.TrimRight(strings.Join(lines, "\n"), "\n")
}

// screenNow is the emulated screen as text for a snapshot line: scrubbed of
// every concealed value, then cleaned like any harness text.
func (s *Session) screenNow() string {
	return sanitize.Text(vaultenv.Default.Scrub(s.r.screen.text()))
}
