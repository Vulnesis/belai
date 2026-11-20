package vulnid

import (
	"testing"

	"github.com/vulnetix/belai/internal/brand"
)

// TestURLFollowsBrand: the console link is vulnetix.com by default and moves
// to vulnes.is only when the Vulnesis brand is selected.
func TestURLFollowsBrand(t *testing.T) {
	t.Cleanup(brand.Reset)
	brand.Set(brand.Vulnetix)
	if got := URL("CVE-2021-44228"); got != "https://www.vulnetix.com/vuln/CVE-2021-44228" {
		t.Fatalf("vulnetix URL = %q", got)
	}
	brand.Set(brand.Vulnesis)
	if got := URL("CVE-2021-44228"); got != "https://www.vulnes.is/vuln/CVE-2021-44228" {
		t.Fatalf("vulnesis URL = %q", got)
	}
	if !IsRemediation(URL("CVE-2021-44228")) {
		t.Fatal("a vulnes.is console link should still name its identifier")
	}
}
