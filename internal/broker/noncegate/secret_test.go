package noncegate

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadSecretCreatesThenReuses(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "nonce.key")
	a, err := LoadSecret(p, "")
	if err != nil || len(a) != 32 {
		t.Fatalf("create: %v", err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	b, err := LoadSecret(p, "")
	if err != nil || !bytes.Equal(a, b) {
		t.Fatalf("reload: %v", err)
	}
	os.Chmod(p, 0o644)
	if _, err := LoadSecret(p, ""); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("world-readable accepted: %v", err)
	}
}

func TestLoadSecretFromEnv(t *testing.T) {
	t.Setenv("BROKER_TEST_SECRET", strings.Repeat("ab", 32))
	b, err := LoadSecret("", "BROKER_TEST_SECRET")
	if err != nil || len(b) != 32 {
		t.Fatal(err)
	}
	t.Setenv("BROKER_TEST_SECRET", "short")
	if _, err := LoadSecret("", "BROKER_TEST_SECRET"); err == nil {
		t.Fatal("short secret accepted")
	}
}
