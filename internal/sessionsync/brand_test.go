package sessionsync

import (
	"testing"

	"github.com/vulnetix/belai/internal/brand"
)

// TestBrandOriginAndAllowlist: the default console origin and the credential
// allowlist follow the brand; vulnes.is is refused under the default brand.
func TestBrandOriginAndAllowlist(t *testing.T) {
	t.Cleanup(brand.Reset)
	brand.Set(brand.Vulnetix)
	if got := BaseURL(""); got != "https://www.vulnetix.com"+apiPath {
		t.Fatalf("vulnetix BaseURL = %q", got)
	}
	if AllowedOrigin("https://www.vulnes.is") {
		t.Fatal("vulnes.is must not be allowed under the default brand")
	}
	brand.Set(brand.Vulnesis)
	if got := BaseURL(""); got != "https://www.vulnes.is"+apiPath {
		t.Fatalf("vulnesis BaseURL = %q", got)
	}
	if got := BaseURL("https://console.example"); got != "https://console.example"+apiPath {
		t.Fatalf("explicit origin must win: %q", got)
	}
	for _, u := range []string{"https://www.vulnes.is", "https://www.vulnetix.com"} {
		if !AllowedOrigin(u) {
			t.Fatalf("%s should be allowed under vulnesis", u)
		}
	}
	if AllowedOrigin("https://notvulnes.is") || AllowedOrigin("http://www.vulnes.is") {
		t.Fatal("look-alike or plain-http hosts must be refused")
	}
}
