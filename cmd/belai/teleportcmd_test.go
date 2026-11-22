package main

import (
	"context"
	"io"
	"strings"
	"testing"
)

// Sending a session through Keleustes needs a joined profile; without one the
// command says so and uploads nothing.
func TestTeleportToNeedsAKeleustesProfile(t *testing.T) {
	t.Setenv("BELAI_HOME", t.TempDir())
	_, err := runTeleportSend(context.Background(), t.TempDir(), "11111111", "node-2", io.Discard)
	if err == nil || !strings.Contains(err.Error(), "has not joined a Keleustes server") {
		t.Fatalf("err = %v", err)
	}
}
