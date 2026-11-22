package factorylink

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// Needs travel in the upload header as kinds and names only; built-ins,
// bad names, other kinds and duplicates are dropped and the list is capped.
func TestTeleportNeedsTravelInTheHeader(t *testing.T) {
	f := newFakeKeleustes(t)
	c := teleClient(t, f)
	f.requestTeleport(testTeleport, "sess-1", "node-1", "node-2")
	needs := []TeleportNeed{
		{Kind: "profile", Name: "log", ID: "forged", SHA256: strings.Repeat("a", 64)},
		{Kind: "profile", Name: "belai:triage-vulns"},
		{Kind: "crew", Name: "ops"},
		{Kind: "crew", Name: "ops"},
		{Kind: "skill", Name: "s"},
		{Kind: "profile", Name: "a\nb"},
	}
	if _, err := c.UploadTeleport(context.Background(), TeleportUpload{TeleportID: testTeleport, SessionID: "sess-1", ToNode: "node-2", Needs: needs}, []byte("x")); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range f.tele.parts[0][0].GetHeader().GetNeeds() {
		got = append(got, r.GetKind()+":"+r.GetName()+":"+r.GetId()+r.GetSha256())
	}
	if want := []string{"profile:log:", "crew:ops:"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("header needs = %v", got)
	}
	var many []TeleportNeed
	for i := 0; i < 40; i++ {
		many = append(many, TeleportNeed{Kind: "profile", Name: "p" + strings.Repeat("x", i)})
	}
	if n := CleanTeleportNeeds(many); len(n) != MaxTeleportNeeds {
		t.Errorf("cap = %d", len(n))
	}
}

// A download keeps the library's id, version and hash when well formed.
func TestTeleportNeedsFromTheDownloadHeader(t *testing.T) {
	sha := strings.Repeat("B", 64)
	got := needsOf([]*nodev1.LibraryRef{
		{Kind: "profile", Name: "log", Id: "0190f0a2-6b7e-7c1d-8a52-0d9e4f1b7a34", Version: 3, Sha256: sha},
		{Kind: "crew", Name: "ops", Id: "../x", Version: -1, Sha256: "short"},
	})
	want := []TeleportNeed{
		{Kind: "profile", Name: "log", ID: "0190f0a2-6b7e-7c1d-8a52-0d9e4f1b7a34", Version: 3, SHA256: strings.ToLower(sha)},
		{Kind: "crew", Name: "ops"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("needs = %+v", got)
	}
}
