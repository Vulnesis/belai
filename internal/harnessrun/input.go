package harnessrun

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/vulnetix/belai/internal/harness"
)

// MaxPrompt caps one typed prompt.
const MaxPrompt = 64 << 10

// Bracketed paste markers (DECSET 2004).
const (
	PasteStart = "\x1b[200~"
	PasteEnd   = "\x1b[201~"
)

// ErrSlashPrompt refuses a prompt that would be a harness command: a remote
// prompt is never a slash command, a shell escape or a memory line, exactly
// as for a belai session (where a leading "/" or "!" is plain text).
var ErrSlashPrompt = errors.New("a prompt may not start with /, ! or # in a harness session; harness commands are not taken from a prompt")

// ErrMultiline refuses a multi-line prompt to a TUI without bracketed paste.
var ErrMultiline = errors.New("harness does not accept multi-line input")

// Neutralise makes text safe to type into a terminal: every C0 control but
// newline and tab, DEL and every C1 control are removed (so ESC, and with it
// a "\x1b[201~" that would end the paste early, cannot reach the TUI), line
// endings become "\n", invalid UTF-8 is dropped, and the result is capped at
// MaxPrompt.
func Neutralise(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	var b strings.Builder
	for i := 0; i < len(text); {
		r, n := utf8.DecodeRuneInString(text[i:])
		i += n
		switch {
		case r == utf8.RuneError && n <= 1:
			continue
		case r == '\n' || r == '\t':
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f):
			continue
		}
		if b.Len()+utf8.RuneLen(r) > MaxPrompt {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// PromptBytes is what to type for one prompt (without the submit key), after
// Neutralise. A leading command character is refused, and a multi-line
// prompt without bracketed paste follows the profile's multiline rule.
func PromptBytes(text string, bracketed bool, in harness.Input) ([]byte, error) {
	text = strings.TrimSpace(Neutralise(text))
	if text == "" {
		return nil, errors.New("the prompt was empty after cleaning")
	}
	if strings.ContainsAny(text[:1], "/!#") {
		return nil, ErrSlashPrompt
	}
	if bracketed {
		return []byte(PasteStart + text + PasteEnd), nil
	}
	if !strings.Contains(text, "\n") {
		return []byte(text), nil
	}
	switch in.Multiline {
	case "join":
		return []byte(strings.Join(strings.Fields(text), " ")), nil
	case "backslash":
		return []byte(strings.ReplaceAll(text, "\n", "\\\r")), nil
	}
	return nil, ErrMultiline
}

// KeyBytes maps an allowlisted key name to bytes. A name outside allow, or
// one the fixed table lacks, is refused.
func KeyBytes(name string, allow []string) ([]byte, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	ok := false
	for _, a := range allow {
		if a == name {
			ok = true
		}
	}
	b, known := harness.KeyBytes[name]
	if !ok || !known {
		return nil, fmt.Errorf("key %q is not one this harness session takes", name)
	}
	return []byte(b), nil
}

// ExitBytes turns the profile's exit sequence into writes: a key name is its
// bytes, anything else a literal line typed as-is (already a fixed profile
// value, never remote text).
func ExitBytes(seq []string) [][]byte {
	var out [][]byte
	for _, s := range seq {
		if b, ok := harness.KeyBytes[s]; ok {
			out = append(out, []byte(b))
		} else {
			out = append(out, []byte(s))
		}
	}
	return out
}

// Modes tracks the terminal modes the harness sets on its own output:
// bracketed paste (DECSET 2004) and the alternate screen (1049). Sequences
// split across chunks are caught.
type Modes struct {
	mu        sync.Mutex
	tail      []byte
	bracketed bool
	alt       bool
	seen      bool
}

var modeSeqs = []struct {
	seq string
	set func(m *Modes)
}{
	{"\x1b[?2004h", func(m *Modes) { m.bracketed = true }},
	{"\x1b[?2004l", func(m *Modes) { m.bracketed = false }},
	{"\x1b[?1049h", func(m *Modes) { m.alt = true }},
	{"\x1b[?1049l", func(m *Modes) { m.alt = false }},
}

// Feed scans one output chunk.
func (m *Modes) Feed(p []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seen = true
	buf := append(m.tail, p...)
	// Apply in stream order.
	for i := 0; i < len(buf); i++ {
		if buf[i] != 0x1b {
			continue
		}
		for _, s := range modeSeqs {
			if bytes.HasPrefix(buf[i:], []byte(s.seq)) {
				s.set(m)
			}
		}
	}
	keep := 8
	if len(buf) < keep {
		keep = len(buf)
	}
	m.tail = append([]byte(nil), buf[len(buf)-keep:]...)
}

// Bracketed reports whether bracketed paste is on.
func (m *Modes) Bracketed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bracketed
}

// Ring keeps the last N bytes of output for a new viewer's replay.
type Ring struct {
	mu   sync.Mutex
	buf  []byte
	max  int
	sent int64
}

// NewRing keeps max bytes.
func NewRing(max int) *Ring { return &Ring{max: max} }

// Write appends p.
func (r *Ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	if over := len(r.buf) - r.max; over > 0 {
		r.buf = append(r.buf[:0:0], r.buf[over:]...)
	}
	r.sent += int64(len(p))
	return len(p), nil
}

// Snapshot is the kept bytes and the stream offset just past them.
func (r *Ring) Snapshot() ([]byte, int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf...), r.sent
}

// NewUUID is a random RFC 4122 version 4 UUID.
func NewUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// matchPrompt reports whether a native user entry is the prompt typed: the
// first 200 characters agree once whitespace is collapsed.
func matchPrompt(typed, native string) bool {
	norm := func(s string) string {
		s = strings.Join(strings.Fields(s), " ")
		if r := []rune(s); len(r) > 200 {
			s = string(r[:200])
		}
		return s
	}
	a, b := norm(typed), norm(native)
	return a != "" && (strings.HasPrefix(b, a) || strings.HasPrefix(a, b) && len(b) >= min(len(a), 40))
}
