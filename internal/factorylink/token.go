// Package factorylink joins this host to a Keleustes server (the desktop
// Software Factory) and keeps its control link open.
//
// A Keleustes owner mints a single-use join token ("kls1.…"). `/connect
// <token>` (or `belai connect <token>`) decodes it, dials the server over TLS
// pinned to the SPKI hash the token carries, and redeems it with a CSR for a
// fresh Ed25519 key. The server returns a client certificate from its local
// CA; every later connection is mutual TLS against that CA. See
// docs/keleustes.md.
//
// Everything Keleustes sends is remote content: it is never trusted for
// tool or prompt promotion beyond what the cloud console's equivalent
// content gets.
package factorylink

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TokenPrefix marks a Keleustes join token.
const TokenPrefix = "kls1."

// Token is the decoded join token payload (JSON with short keys).
type Token struct {
	V          int      `json:"v"`
	ServerID   string   `json:"sid"`
	ServerName string   `json:"sn"`
	Addrs      []string `json:"a"`
	Pin        string   `json:"pin"`
	TokenID    string   `json:"t"`
	Secret     string   `json:"s"`
	Expires    int64    `json:"e"`
}

// ErrNotToken reports text that is not a Keleustes join token.
var ErrNotToken = errors.New("not a Keleustes join token (it starts with kls1.)")

// LooksLikeToken reports whether s has the join-token prefix.
func LooksLikeToken(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), TokenPrefix)
}

// ParseToken decodes and validates a join token. It checks shape and expiry
// only; the server decides whether the token is still unused.
func ParseToken(s string, now time.Time) (*Token, error) {
	s = strings.TrimSpace(s)
	body, ok := strings.CutPrefix(s, TokenPrefix)
	if !ok {
		return nil, ErrNotToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("join token: %w", err)
	}
	var t Token
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("join token: %w", err)
	}
	if t.V != 1 {
		return nil, fmt.Errorf("join token version %d is not supported by this belai", t.V)
	}
	if len(t.Addrs) == 0 || t.ServerID == "" || t.TokenID == "" {
		return nil, errors.New("join token is incomplete")
	}
	pin, err := base64.RawURLEncoding.DecodeString(t.Pin)
	if err != nil || len(pin) != 32 {
		return nil, errors.New("join token has no valid server pin")
	}
	sec, err := base64.RawURLEncoding.DecodeString(t.Secret)
	if err != nil || len(sec) != 32 {
		return nil, errors.New("join token has no valid secret")
	}
	if t.Expires > 0 && now.UnixMilli() >= t.Expires {
		return nil, errors.New("join token has expired; mint a new one in Keleustes (Fleet → Add node)")
	}
	return &t, nil
}

func (t *Token) pinBytes() []byte {
	b, _ := base64.RawURLEncoding.DecodeString(t.Pin)
	return b
}

func (t *Token) secretBytes() []byte {
	b, _ := base64.RawURLEncoding.DecodeString(t.Secret)
	return b
}
