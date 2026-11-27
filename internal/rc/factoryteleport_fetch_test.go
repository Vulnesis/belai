package rc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/vulnetix/belai/internal/agentprofile"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// The target of a Keleustes teleport fetches the profile and crews its
// session needs with Library.Fetch(teleport id) and validates each as a
// library install does: profiles before crews, a need already here left
// alone (no fetch), one the library lacks only named, an invalid profile or
// a document of another version refused with nothing written.
func TestInstallTeleportNeeds(t *testing.T) {
	t.Setenv("BELAI_HOME", t.TempDir())
	good, _ := json.Marshal(map[string]any{"name": "patch-helper", "description": "helps patch", "prompt": "Fix what the card says.",
		"tools": []string{"Read", "Grep"}})
	bad, _ := json.Marshal(map[string]any{"name": "Bad Name!", "prompt": "x"})
	crew, _ := json.Marshal(map[string]any{"name": "fixers", "description": "fix",
		"members": []map[string]any{{"agent": "crew-builder", "count": 2}}})
	docs := map[string][]byte{"patch-helper": good, "bad": bad, "fixers": crew, "drifted": good, "crew-builder": []byte(crewWorkerMD)}
	var fetched []string
	fetch := func(_ context.Context, tid string, ref *nodev1.LibraryRef) (*nodev1.LibraryDoc, error) {
		if tid != "0f0e0d0c-1111-2222-3333-444455556666" {
			t.Errorf("fetch for teleport %q", tid)
		}
		fetched = append(fetched, ref.GetKind()+"/"+ref.GetName())
		doc, ok := docs[ref.GetName()]
		if !ok {
			return nil, errors.New("permission denied: the teleport does not need that item")
		}
		sha := hashOf(doc)
		if ref.GetName() == "drifted" {
			sha = strings.Repeat("0", 64)
		}
		return &nodev1.LibraryDoc{Ref: &nodev1.LibraryRef{Kind: ref.GetKind(), Name: ref.GetName(), Sha256: sha}, Doc: doc}, nil
	}
	const id = "0a0b0c0d-0000-0000-0000-000000000001"
	needs := []factorylink.TeleportNeed{
		// The crew is listed first; its member profile still installs before it.
		{Kind: "crew", Name: "fixers", ID: id},
		{Kind: "profile", Name: "patch-helper", ID: id, SHA256: hashOf(good)},
		{Kind: "profile", Name: "bad", ID: id},
		{Kind: "profile", Name: "crew-builder", ID: id},
		{Kind: "profile", Name: "nolib"},
		{Kind: "profile", Name: "drifted", ID: id, SHA256: hashOf(good)},
		{Kind: "profile", Name: "belai:triage-vulns", ID: id},
	}
	notes := InstallTeleportNeeds(t.Context(), fetch, "0f0e0d0c-1111-2222-3333-444455556666", needs)
	if len(notes) != 6 {
		t.Fatalf("notes = %q", notes)
	}
	joined := strings.Join(notes, "\n")
	for _, want := range []string{"installed profile patch-helper", "profile bad was not installed: the profile is not valid here",
		"profile nolib is not in the Keleustes library", "profile drifted was not installed: it is not the version the teleport named"} {
		if !strings.Contains(joined, want) {
			t.Errorf("notes lack %q:\n%s", want, joined)
		}
	}
	if fetched[0] != "profile/patch-helper" {
		t.Errorf("fetch order = %v (profiles first)", fetched)
	}
	for _, f := range fetched {
		if strings.Contains(f, "nolib") || strings.Contains(f, "belai:") {
			t.Errorf("fetched %s", f)
		}
	}
	if p, err := agentprofile.Load("patch-helper"); err != nil || p.SystemPrompt != "Fix what the card says." {
		t.Fatalf("saved profile: %+v %v", p, err)
	}
	if _, err := agentprofile.Load("drifted"); err == nil {
		t.Error("a document of another version was saved")
	}
	if c, err := agentprofile.LoadCrew("fixers"); err != nil || len(c.Members) != 1 {
		t.Fatalf("saved crew: %+v %v\n%s", c, err, joined)
	}

	// Again: both are here now, so nothing is fetched or overwritten.
	fetched = nil
	notes = InstallTeleportNeeds(t.Context(), fetch, "0f0e0d0c-1111-2222-3333-444455556666", needs[:2])
	if len(fetched) != 0 || !strings.Contains(strings.Join(notes, "\n"), "already on this host") {
		t.Errorf("second pass fetched %v, notes %q", fetched, notes)
	}
}
