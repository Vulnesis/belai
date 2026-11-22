package main

import (
	"testing"

	"github.com/vulnetix/belai/internal/broker/config"
)

// The shipped example must load, and its placeholder digest must match no key.
func TestExampleConfigLoads(t *testing.T) {
	c, err := config.Load("broker.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Keys[0].SHA256 != "0000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("example digest changed: %s", c.Keys[0].SHA256)
	}
}
