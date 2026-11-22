package clijobs

import (
	"slices"
	"strings"
	"testing"
)

// The scout's stack facts come from manifest names through a closed table.
func TestDetectStack(t *testing.T) {
	pms, langs := DetectStack([]byte("go.mod\nweb/package.json\nweb/pnpm-lock.yaml\napi/App.csproj\nREADME.md\n<script>.json\n"))
	if !slices.Equal(pms, []string{"go", "npm", "nuget", "pnpm"}) || !slices.Equal(langs, []string{"csharp", "go", "javascript"}) {
		t.Errorf("pms %v langs %v", pms, langs)
	}
	// A result keeps only words of the table, even from a pulled document.
	doc, ok := Clean(`{"job":"scout","exitCode":0,"counts":{"critical":0,"high":0,"medium":0,"low":0},"findings":[],"signals":[],"artifacts":[],
		"packageManagers":["go","rm -rf"],"languages":["rust","<x>"]}`)
	if !ok || !strings.Contains(doc, `"packageManagers":["go"]`) || !strings.Contains(doc, `"languages":["rust"]`) {
		t.Errorf("clean = %s %v", doc, ok)
	}
}
