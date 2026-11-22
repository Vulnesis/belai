// Package noncegate is the broker's side of Belai's nonce protocol
// (docs/nonce-endpoint-spec.md). The Issuer mints nonces that are signed, not
// stored: each is random bytes plus an expiry, authenticated with an HMAC
// keyed per principal, so any broker replica holding the same master secret
// verifies one and a nonce issued to one principal never verifies for
// another. Gate applies the gateway verification rules to an OpenAI-style
// request body before it is forwarded to the upstream model server.
package noncegate

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"
)

const (
	randLen = 16
	expLen  = 8
	macLen  = 16
	rawLen  = randLen + expLen + macLen

	// DefaultCount and MaxCount bound GET /v1/nonces?count=N.
	DefaultCount = 16
	MaxCount     = 64
	// DefaultTTL is how long an issued nonce verifies.
	DefaultTTL = 24 * time.Hour
)

// Modes is the list the nonce response advertises. canonical is listed so a
// Belai pool seeded here may ask for canonical forwarding.
var Modes = []string{"observe", "enforce", "canonical"}

// Issuer mints and verifies nonces.
type Issuer struct {
	master []byte
	ttl    time.Duration
	now    func() time.Time
}

// NewIssuer returns an issuer keyed by master, which must hold at least 32
// bytes. ttl <= 0 means DefaultTTL.
func NewIssuer(master []byte, ttl time.Duration) (*Issuer, error) {
	if len(master) < 32 {
		return nil, errors.New("nonce secret must be at least 32 bytes")
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Issuer{master: append([]byte(nil), master...), ttl: ttl, now: time.Now}, nil
}

func (is *Issuer) principalKey(principal string) []byte {
	m := hmac.New(sha256.New, is.master)
	m.Write([]byte("belai-broker/nonce/v1\x00"))
	m.Write([]byte(principal))
	return m.Sum(nil)
}

func mac(key, body []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(body)
	return m.Sum(nil)[:macLen]
}

// Issue returns n nonces for principal and the time they expire.
func (is *Issuer) Issue(principal string, n int) ([]string, time.Time, error) {
	if n <= 0 {
		n = DefaultCount
	}
	n = min(n, MaxCount)
	exp := is.now().Add(is.ttl).UTC().Truncate(time.Second)
	key := is.principalKey(principal)
	out := make([]string, 0, n)
	for range n {
		raw := make([]byte, rawLen)
		if _, err := rand.Read(raw[:randLen]); err != nil {
			return nil, time.Time{}, err
		}
		binary.BigEndian.PutUint64(raw[randLen:randLen+expLen], uint64(exp.Unix()))
		copy(raw[randLen+expLen:], mac(key, raw[:randLen+expLen]))
		out = append(out, hex.EncodeToString(raw))
	}
	return out, exp, nil
}

// Checker returns a delimiters.NonceChecker-compatible func that accepts only
// unexpired nonces issued to principal. The per-principal key is derived once.
func (is *Issuer) Checker(principal string) func(string) bool {
	key := is.principalKey(principal)
	now := is.now().Unix()
	return func(nonce string) bool {
		if len(nonce) != rawLen*2 {
			return false
		}
		raw, err := hex.DecodeString(nonce)
		if err != nil {
			return false
		}
		if !hmac.Equal(raw[randLen+expLen:], mac(key, raw[:randLen+expLen])) {
			return false
		}
		return int64(binary.BigEndian.Uint64(raw[randLen:randLen+expLen])) > now
	}
}
