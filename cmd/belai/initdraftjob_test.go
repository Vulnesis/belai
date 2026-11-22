package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnetix/belai/internal/rc"
	"github.com/vulnetix/belai/internal/repomap"
)

func TestInitDraftOfShapesTheReply(t *testing.T) {
	root := t.TempDir()
	d, why, err := initDraftOf(root, "```markdown\n# AGENTS\n\x1b[2Jrun `go test ./...`\n```")
	if err != nil || why != "" {
		t.Fatal(why, err)
	}
	if d.Path != "AGENTS.md" || d.BaseSHA256 != "" || len(d.SHA256) != 64 || strings.Contains(d.Markdown, "\x1b") || strings.Contains(d.Markdown, "```markdown") {
		t.Fatalf("draft = %+v", d)
	}
	// An existing CLAUDE.md is the file the draft replaces.
	if err := os.WriteFile(filepath.Join(root, "CLAUDE.md"), []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, _, _ = initDraftOf(root, strings.Repeat("x", rc.MaxInitDraftBytes+10))
	if d.Path != "CLAUDE.md" || len(d.BaseSHA256) != 64 || len(d.Markdown) > rc.MaxInitDraftBytes+1 {
		t.Fatalf("draft = %s %s %d", d.Path, d.BaseSHA256, len(d.Markdown))
	}
	if b, _ := os.ReadFile(filepath.Join(root, "CLAUDE.md")); string(b) != "old\n" {
		t.Fatal("the draft wrote the file")
	}
	if _, why, _ := initDraftOf(root, "  \n"); why == "" {
		t.Fatal("an empty reply was a draft")
	}
	if f := initDraftFacts(repomap.Map{}); f == "" {
		t.Fatal("no facts block")
	}
}
