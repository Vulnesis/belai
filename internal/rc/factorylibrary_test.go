package rc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vulnetix/belai/internal/agentprofile"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/libinstall"
	"github.com/vulnetix/belai/internal/libitem"
	"github.com/vulnetix/belai/internal/libstore"
	"github.com/vulnetix/belai/internal/sessionsync"
)

// WP-E: a profile from Keleustes is validated as a profile before it is
// saved, an invalid one is refused, a host profile backs up with its
// markdown, and a library install obeys the kind's sync switch.
func TestKeleustesLibraryInstallAndBackup(t *testing.T) {
	t.Setenv("BELAI_HOME", t.TempDir())
	good, _ := json.Marshal(map[string]any{"name": "patch-helper", "description": "helps patch", "prompt": "Fix what the card says.",
		"tools": []string{"Read", "Grep"}})
	bad, _ := json.Marshal(map[string]any{"name": "Bad Name!", "prompt": "x"})
	ff := &fakeFactory{docs: map[string][]byte{"patch-helper": good, "bad": bad}}
	d := &Daemon{o: Options{Factory: ff, SyncItem: func(libitem.Kind) bool { return false }}}
	install := func(id, name string) (string, string) {
		_, report, why, _ := d.factoryStart(t.Context(), &nodev1.Dispatch{Id: id, Kind: "library_install",
			Library: []*nodev1.LibraryRef{{Kind: "profile", Name: name}}}, nil)
		return report, why
	}
	if _, why := install("d1", "bad"); why == "" || !strings.Contains(why, "not valid") {
		t.Fatalf("invalid profile: %q", why)
	}
	if rep, why := install("d2", "patch-helper"); why != "" || !strings.Contains(rep, "patch-helper") {
		t.Fatalf("install: %q %q", rep, why)
	}
	p, err := agentprofile.Load("patch-helper")
	if err != nil || p.SystemPrompt != "Fix what the card says." {
		t.Fatalf("saved profile: %+v %v", p, err)
	}
	// Back it up: the document carries the profile's markdown.
	_, report, why, _ := d.factoryStart(t.Context(), &nodev1.Dispatch{Id: "d3", Kind: "library_backup",
		Library: []*nodev1.LibraryRef{{Kind: "profile", Name: "patch-helper"}}}, nil)
	if why != "" || !strings.Contains(report, "version 1") || len(ff.backups) != 1 {
		t.Fatalf("backup: %q %q", report, why)
	}
	var a keleustesAgent
	if err := json.Unmarshal(ff.backups[0].GetDoc(), &a); err != nil || !strings.HasPrefix(a.Meta.BelaiMarkdown, "---") || a.Name != "patch-helper" {
		t.Errorf("backup doc = %s", ff.backups[0].GetDoc())
	}
	// The markdown round-trips to the same profile on another host.
	back, err := profileFromDoc(ff.backups[0].GetDoc())
	if err != nil || back.Name != "patch-helper" {
		t.Errorf("round trip: %+v %v", back, err)
	}
	// An item kind whose sync switch is off is refused before any fetch.
	_, _, why, _ = d.factoryStart(t.Context(), &nodev1.Dispatch{Id: "d4", Kind: "library_install",
		Library: []*nodev1.LibraryRef{{Kind: "hook", Name: "guard"}}}, nil)
	if why == "" {
		t.Error("a hook install with sync.hooks off went through")
	}
}

const crewWorkerMD = `---
name: crew-builder
description: Builds what a card asks
mode: worker
tools: [Read, Write]
kanban:
  labels: [build]
  on_success: {list: review}
workspace: {isolation: worktree}
---
Build it.
`

// P5 (#21, #22, #24): a crew backs up from one host as Keleustes's crew JSON
// with its canonical form inside, installs on another host after its member
// profile (sent in the same dispatch, after the crew), and keeps its id; a
// crew Keleustes wrote installs by agent names; the advert lists the crew's
// hash; a hook bundle installs with its files, and a file whose hash does not
// match is refused with nothing written.
func TestKeleustesCrewRoundTripAndHookBundle(t *testing.T) {
	hostA := t.TempDir()
	t.Setenv("BELAI_HOME", hostA)
	p, err := agentprofile.ParseMarkdown([]byte(crewWorkerMD))
	if err != nil {
		t.Fatal(err)
	}
	if p.ID, err = agentprofile.NewID(); err != nil {
		t.Fatal(err)
	}
	if _, err := agentprofile.SaveReplacing(p); err != nil {
		t.Fatal(err)
	}
	id, _ := agentprofile.NewID()
	if _, err := agentprofile.SaveCrew(agentprofile.Crew{ID: id, Name: "builders", Description: "two builders",
		Members: []agentprofile.Member{{Profile: "crew-builder", Replicas: 2}}}); err != nil {
		t.Fatal(err)
	}
	ff := &fakeFactory{docs: map[string][]byte{}, docFiles: map[string][]*nodev1.LibraryFile{}}
	d := &Daemon{o: Options{Factory: ff, SyncItem: func(libitem.Kind) bool { return true }}}
	_, report, why, _ := d.factoryStart(t.Context(), &nodev1.Dispatch{Id: "b1", Kind: "library_backup",
		Library: []*nodev1.LibraryRef{{Kind: "profile", Name: "crew-builder"}, {Kind: "crew", Name: "builders"}}}, nil)
	if why != "" || len(ff.backups) != 2 {
		t.Fatalf("backup: %q %q", report, why)
	}
	crewDocBytes := ff.backups[1].GetDoc()
	var k keleustesCrew
	if err := json.Unmarshal(crewDocBytes, &k); err != nil || k.Name != "builders" || len(k.Members) != 1 || k.Members[0].Count != 2 || k.Meta.BelaiCrew == "" {
		t.Fatalf("crew doc = %s", crewDocBytes)
	}
	// The advert's crew hash is the hash of the canonical form inside.
	refs := libraryInventory(Inventory{Crews: []sessionsync.RCCrew{{ID: id, Name: "builders", SHA256: hashOf([]byte(k.Meta.BelaiCrew))}}})
	if len(refs) != 1 || refs[0].GetKind() != "crew" || refs[0].GetId() != id || len(refs[0].GetSha256()) != 64 {
		t.Fatalf("advert = %+v", refs)
	}

	// Host B: the crew is listed first, the profile still installs before it.
	t.Setenv("BELAI_HOME", t.TempDir())
	ff.docs["crew-builder"] = ff.backups[0].GetDoc()
	ff.docs["builders"] = crewDocBytes
	install := func(id string, overwrite bool, refs ...*nodev1.LibraryRef) (string, string) {
		_, report, why, _ := d.factoryStart(t.Context(), &nodev1.Dispatch{Id: id, Kind: "library_install", Overwrite: overwrite, Library: refs}, nil)
		return report, why
	}
	if rep, why := install("i1", false, &nodev1.LibraryRef{Kind: "crew", Name: "builders"}, &nodev1.LibraryRef{Kind: "profile", Name: "crew-builder"}); why != "" {
		t.Fatalf("install: %q %q", rep, why)
	}
	got, ok := libinstall.StoredCrew("builders")
	if !ok || got.ID != id || got.Members[0].Replicas != 2 {
		t.Fatalf("host B crew = %+v %v", got, ok)
	}
	// Again without overwrite: refused, not replaced.
	if _, why := install("i2", false, &nodev1.LibraryRef{Kind: "crew", Name: "builders"}); why == "" {
		t.Error("a second install replaced the crew without overwrite")
	}
	// A crew Keleustes wrote: agent names and counts, no host id.
	ff.docs["kcrew"], _ = json.Marshal(map[string]any{"name": "kcrew", "description": "", "process": "sequential",
		"members": []any{map[string]any{"agent": "crew-builder", "role": "", "count": 1}}})
	if rep, why := install("i3", false, &nodev1.LibraryRef{Kind: "crew", Name: "kcrew"}); why != "" {
		t.Fatalf("keleustes crew: %q %q", rep, why)
	}
	if c, ok := libinstall.StoredCrew("kcrew"); !ok || !agentprofile.ValidID(c.ID) {
		t.Fatalf("kcrew = %+v", c)
	}
	// A crew whose member is not here is refused, nothing written.
	ff.docs["lonely"], _ = json.Marshal(map[string]any{"name": "lonely", "members": []any{map[string]any{"agent": "nobody", "count": 1}}})
	if _, why := install("i4", false, &nodev1.LibraryRef{Kind: "crew", Name: "lonely"}); why == "" {
		t.Error("a crew without its member was installed")
	}
	if _, ok := libinstall.StoredCrew("lonely"); ok {
		t.Error("the refused crew was written")
	}

	// A hook bundle with its script.
	script := []byte("#!/bin/sh\necho '{}'\n")
	ff.docs["guard"], _ = json.Marshal(map[string]any{"name": "guard", "description": "Guards",
		"hooks": map[string]any{"PreToolUse": []any{map[string]any{"matcher": "Bash", "hooks": []any{map[string]any{"type": "command", "command": "guard.sh"}}}}}})
	ff.docFiles["guard"] = []*nodev1.LibraryFile{{Path: "guard.sh", Data: script, Sha256: "00"}}
	if _, why := install("h1", false, &nodev1.LibraryRef{Kind: "hook", Name: "guard"}); why == "" || !strings.Contains(why, "hash") {
		t.Fatalf("a file with the wrong hash: %q", why)
	}
	if _, err := libstore.Get(libitem.Hook, "guard"); err == nil {
		t.Fatal("the refused bundle was written")
	}
	ff.docFiles["guard"][0].Sha256 = hashOf(script)
	if rep, why := install("h2", false, &nodev1.LibraryRef{Kind: "hook", Name: "guard"}); why != "" {
		t.Fatalf("hook bundle: %q %q", rep, why)
	}
	if it, err := libstore.Get(libitem.Hook, "guard"); err != nil || len(it.Files) != 1 {
		t.Fatalf("installed hook = %+v %v", it, err)
	}
}

// The advert lists knowledge indexes and plugins as facts only.
func TestLibraryInventoryKnowledgeAndPlugins(t *testing.T) {
	refs := libraryInventory(Inventory{
		Knowledge: []sessionsync.RCKnowledge{{Scope: "project", Name: "demo", Root: "/src/demo",
			Docs: []sessionsync.RCKnowledgeDoc{{Address: "kb://a", SHA256: strings.Repeat("a", 64)}}}},
		Plugins: []InvPlugin{{Name: "fmt", Commit: "abc123", SHA256: strings.Repeat("b", 64), Enabled: 1}},
	})
	if len(refs) != 2 || refs[0].GetKind() != "knowledge" || refs[0].GetId() != "project:/src/demo" || refs[0].GetVersion() != 1 || len(refs[0].GetSha256()) != 64 {
		t.Fatalf("knowledge = %+v", refs)
	}
	if refs[1].GetKind() != "plugin" || refs[1].GetName() != "fmt" || refs[1].GetId() != "abc123" || refs[1].GetVersion() != 1 {
		t.Fatalf("plugin = %+v", refs[1])
	}
}
