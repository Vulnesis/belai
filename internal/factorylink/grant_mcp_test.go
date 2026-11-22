package factorylink

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vulnetix/belai/internal/credentials"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// WP-F: MCP credentials ride the grant like provider keys: shown by name
// only, carried over the pipe, answered for the bound server key while the
// grant lives, and forgotten on Drop.
func TestGrantCarriesMCPSecrets(t *testing.T) {
	const val = "ghp_mcp_test_value_123"
	now := time.Now()
	g := GrantFrom(&nodev1.VaultGrant{GrantId: "g1", ExpiresAtMs: now.Add(time.Hour).UnixMilli(),
		Mcp: []*nodev1.McpSecret{{Server: "github", Key: "token", Value: val}, {Server: "bad name", Key: "k", Value: "x"}}}, now)
	if g == nil {
		t.Fatal("no grant from MCP secrets alone")
	}
	for _, s := range []string{g.String(), fmt.Sprintf("%#v", g)} {
		if strings.Contains(s, val) || !strings.Contains(s, "github:token") {
			t.Errorf("formatted grant = %q", s)
		}
	}
	if b, _ := json.Marshal(g); bytes.Contains(b, []byte(val)) {
		t.Errorf("json = %s", b)
	}
	back, err := ReadGrant(bytes.NewReader(g.Encode()), now)
	if err != nil || len(back.MCP(now)) != 1 {
		t.Fatalf("pipe round trip: %v %v", back, err)
	}
	r, err := credentials.NewResolver(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	names := back.Apply(r)
	if !strings.Contains(strings.Join(names, ","), "github:token") {
		t.Errorf("applied = %v", names)
	}
	if v, err := r.MCPSecret("github", "token"); err != nil || v != val {
		t.Errorf("MCPSecret = %q %v", v, err)
	}
	// A key the grant does not hold is the host's own (none here).
	if _, err := r.MCPSecret("github", "other"); err == nil {
		t.Error("an unbound key answered from the grant")
	}
	back.Drop()
	if _, err := r.MCPSecret("github", "token"); err == nil {
		t.Error("a dropped grant still answers")
	}
}
