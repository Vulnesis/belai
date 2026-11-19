package version

import (
	"strings"
	"testing"
)

func TestUserAgent(t *testing.T) {
	ua := UserAgent()
	if !strings.Contains(ua, "belai/") {
		t.Fatalf("UserAgent = %q", ua)
	}
	if !strings.Contains(ua, "github.com/Vulnesis/belai") {
		t.Fatalf("UserAgent = %q", ua)
	}
}
