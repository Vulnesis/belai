package factorylink

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/credentials"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/vaultenv"
)

// Grant holds the provider keys a Keleustes VaultGrant lends this host for
// one dispatch or one job (docs/keleustes.md#vault-grants). The rules:
//
//   - memory only: a grant is never written to a file, a log, a transcript,
//     an error or an argv. Its String, GoString and MarshalJSON show the grant
//     id, the providers and the variable names, never a value, and every value
//     is concealed (vaultenv.Default.Conceal) so the scrubber hides it from
//     whatever Belai records should it surface anyway;
//   - scoped: it feeds the provider resolution of its own session or job
//     only (credentials.Resolver.UseGrant), never the process environment and
//     never a tool's;
//   - dropped: past its expiry Secrets returns nothing, and Drop forgets the
//     values when the session or job ends.
//
// A dispatched session gets its grant through an inherited pipe (Encode,
// ReadGrant), never through the environment or argv.
type Grant struct {
	id      string
	expires time.Time

	mu      sync.Mutex
	secrets []credentials.GrantedSecret
	// mcp are MCP server credentials (WP-F): fed only to the named server'"'"'s
	// bound key, through credentials.UseMCPGrant.
	mcp []credentials.GrantedMCPSecret
}

// maxGrantSecrets bounds what one grant may carry; maxGrantValue one value.
const (
	maxGrantSecrets = 32
	maxGrantValue   = 16 << 10
	maxGrantBytes   = 1 << 20
)

// GrantFrom takes the secrets of a dispatch's or job's VaultGrant. It returns
// nil when there is none, it is already expired, or it carries nothing usable.
func GrantFrom(v *nodev1.VaultGrant, now time.Time) *Grant {
	if v == nil || (len(v.GetSecrets()) == 0 && len(v.GetMcp()) == 0) {
		return nil
	}
	g := &Grant{id: shortGrantID(v.GetGrantId())}
	if ms := v.GetExpiresAtMs(); ms > 0 {
		g.expires = time.UnixMilli(ms)
		if !now.Before(g.expires) {
			return nil
		}
	}
	for _, s := range v.GetSecrets() {
		g.add(s.GetProvider(), s.GetEnv(), s.GetValue())
	}
	for _, m := range v.GetMcp() {
		g.addMCP(m.GetServer(), m.GetKey(), m.GetValue())
	}
	if len(g.secrets) == 0 && len(g.mcp) == 0 {
		return nil
	}
	return g
}

func (g *Grant) add(provider, env, value string) {
	if len(g.secrets) >= maxGrantSecrets || !validProvider(provider) || !validEnvName(env) || value == "" || len(value) > maxGrantValue {
		return
	}
	g.secrets = append(g.secrets, credentials.GrantedSecret{Provider: provider, Env: env, Value: value})
	vaultenv.Default.Conceal(env, value)
}

// addMCP keeps one MCP credential, concealed like a provider key.
func (g *Grant) addMCP(server, key, value string) {
	if len(g.mcp) >= maxGrantSecrets || value == "" || len(value) > maxGrantValue || !validMCPName(server) || !validMCPName(key) {
		return
	}
	g.mcp = append(g.mcp, credentials.GrantedMCPSecret{Server: server, Key: key, Value: value})
	vaultenv.Default.Conceal("mcp:"+server+":"+key, value)
}

// MCP returns the MCP credentials while the grant is live, else nil.
func (g *Grant) MCP(now time.Time) []credentials.GrantedMCPSecret {
	if g == nil || !(g.expires.IsZero() || now.Before(g.expires)) {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.mcp)
}

// ID is the grant's id (shortened, an identifier only).
func (g *Grant) ID() string {
	if g == nil {
		return ""
	}
	return g.id
}

// Expires is when the grant lapses; zero is with its session or job.
func (g *Grant) Expires() time.Time {
	if g == nil {
		return time.Time{}
	}
	return g.expires
}

// Live reports whether the grant may still be used at now.
func (g *Grant) Live(now time.Time) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return (len(g.secrets) > 0 || len(g.mcp) > 0) && (g.expires.IsZero() || now.Before(g.expires))
}

// Secrets returns the granted secrets while the grant is live, else nil.
func (g *Grant) Secrets(now time.Time) []credentials.GrantedSecret {
	if !g.Live(now) {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.secrets)
}

// Providers lists the providers the grant carries keys for, sorted.
func (g *Grant) Providers() []string {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []string
	for _, s := range g.secrets {
		if !slices.Contains(out, s.Provider) {
			out = append(out, s.Provider)
		}
	}
	sort.Strings(out)
	return out
}

// Apply makes r resolve the granted keys for as long as the grant is live,
// and returns the variable names it answers (no value).
func (g *Grant) Apply(r *credentials.Resolver) []string {
	if g == nil || r == nil {
		return nil
	}
	live := func() bool { return g.Live(time.Now()) }
	names := r.UseGrant(g.Secrets(time.Now()), live)
	return append(names, credentials.UseMCPGrant(g.MCP(time.Now()), live)...)
}

// Drop forgets the values. The scrubber still knows them, so anything that
// echoes one later is still hidden.
func (g *Grant) Drop() {
	if g == nil {
		return
	}
	g.mu.Lock()
	g.secrets, g.mcp = nil, nil
	g.mu.Unlock()
}

// String names the grant without any value.
func (g *Grant) String() string {
	if g == nil {
		return "no grant"
	}
	g.mu.Lock()
	var mcp []string
	for _, m := range g.mcp {
		mcp = append(mcp, m.Server+":"+m.Key)
	}
	g.mu.Unlock()
	if len(mcp) > 0 {
		return fmt.Sprintf("keleustes grant %s (%v, mcp %v)", g.id, g.Providers(), mcp)
	}
	return fmt.Sprintf("keleustes grant %s (%v)", g.id, g.Providers())
}

// GoString is String: %#v must not print the values either.
func (g *Grant) GoString() string { return g.String() }

// MarshalJSON is String: a grant never serialises its values by accident.
func (g *Grant) MarshalJSON() ([]byte, error) { return json.Marshal(g.String()) }

// grantWire is the pipe form of a grant. It exists only on the pipe between
// the rc daemon and the session it starts.
type grantWire struct {
	ID      string `json:"id"`
	Expires int64  `json:"expires,omitempty"`
	Secrets []struct {
		Provider string `json:"provider"`
		Env      string `json:"env"`
		Value    string `json:"value"`
	} `json:"secrets"`
	MCP []credentials.GrantedMCPSecret `json:"mcp,omitempty"`
}

// Encode is the grant for the pipe to the session it belongs to. The caller
// writes it to that pipe and nowhere else, and clears the slice after.
func (g *Grant) Encode() []byte {
	if g == nil {
		return nil
	}
	w := grantWire{ID: g.id}
	if !g.expires.IsZero() {
		w.Expires = g.expires.UnixMilli()
	}
	for _, s := range g.Secrets(time.Now()) {
		w.Secrets = append(w.Secrets, struct {
			Provider string `json:"provider"`
			Env      string `json:"env"`
			Value    string `json:"value"`
		}{s.Provider, s.Env, s.Value})
	}
	w.MCP = g.MCP(time.Now())
	b, _ := json.Marshal(w)
	return b
}

// ReadGrant reads a grant a parent wrote with Encode. Nothing read is kept
// anywhere but the returned grant.
func ReadGrant(r io.Reader, now time.Time) (*Grant, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxGrantBytes+1))
	if err != nil {
		return nil, errors.New("read the vault grant")
	}
	if len(data) > maxGrantBytes {
		return nil, errors.New("the vault grant is too large")
	}
	var w grantWire
	err = json.Unmarshal(data, &w)
	clear(data)
	if err != nil {
		return nil, errors.New("the vault grant is not readable")
	}
	g := &Grant{id: shortGrantID(w.ID)}
	if w.Expires > 0 {
		g.expires = time.UnixMilli(w.Expires)
		if !now.Before(g.expires) {
			return nil, errors.New("the vault grant expired before the session started")
		}
	}
	for _, s := range w.Secrets {
		g.add(s.Provider, s.Env, s.Value)
	}
	for _, m := range w.MCP {
		g.addMCP(m.Server, m.Key, m.Value)
	}
	if len(g.secrets) == 0 && len(g.mcp) == 0 {
		return nil, errors.New("the vault grant carries no usable key")
	}
	return g, nil
}

// GrantFDEnv names the inherited descriptor a session reads its grant from.
// Its value is a descriptor number, never a secret.
const GrantFDEnv = "BELAI_KELEUSTES_GRANT_FD"

func shortGrantID(id string) string {
	out := make([]byte, 0, 64)
	for i := 0; i < len(id) && len(out) < 64; i++ {
		c := id[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' {
			out = append(out, c)
		}
	}
	return string(out)
}

func validProvider(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func validEnvName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i, c := range s {
		if !(c >= 'A' && c <= 'Z' || c == '_' || c >= '0' && c <= '9' && i > 0) {
			return false
		}
	}
	return true
}

// validMCPName is a server or key name an MCP entry may carry.
func validMCPName(s string) bool { return config.ValidMCPRefName(s) && len(s) <= 64 }
