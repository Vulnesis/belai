package kanban

import (
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"

	"github.com/vulnetix/belai/internal/sessionsync"
)

// CleanTitle makes a title safe to store and render: ANSI sequences, delimiter markup,
// control and bidi runes removed, one line, at most MaxTitleRunes.
func CleanTitle(s string) string {
	s = strings.Join(strings.Fields(sessionsync.CleanPrompt(ansi.Strip(s))), " ")
	if utf8.RuneCountInString(s) > MaxTitleRunes {
		r := []rune(s)
		s = strings.TrimSpace(string(r[:MaxTitleRunes-1])) + "…"
	}
	return s
}

// CleanBody makes multi-line text safe to store and render, capped at max
// bytes on a rune boundary.
func CleanBody(s string, max int) string {
	s = sessionsync.CleanPrompt(ansi.Strip(s))
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strings.TrimSpace(s[:cut])
}

// MaxServerMetaBytes caps the backend's own metadata kept on an item.
const MaxServerMetaBytes = 16 << 10

// cleanKey keeps a backend display key only in its shape: a short identifier
// ("K-7f21"). Anything else is dropped rather than shown.
func cleanKey(s string) string {
	if s == "" || len(s) > 32 {
		return ""
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return ""
		}
	}
	return s
}

// cleanServerMeta keeps the backend's metadata only when it is a JSON object
// within MaxServerMetaBytes. It is carried, never read.
func cleanServerMeta(s string) string {
	if s == "" || len(s) > MaxServerMetaBytes {
		return ""
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal([]byte(s), &obj) != nil || obj == nil {
		return ""
	}
	return s
}
