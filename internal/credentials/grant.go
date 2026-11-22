package credentials

import (
	"slices"
	"sort"
	"sync"
)

// GrantedSecret is one provider credential a remote factory lent this
// process for a single dispatch or job (a Keleustes VaultGrant secret). It is
// held in memory only and never written.
type GrantedSecret struct {
	Provider string
	// Env is the environment variable the factory says the provider reads.
	Env   string
	Value string
}

// String never shows the value.
func (g GrantedSecret) String() string { return g.Provider + ":" + g.Env + "=[hidden]" }

// GoString never shows the value.
func (g GrantedSecret) GoString() string { return g.String() }

// UseGrant makes the resolver answer provider secrets from the granted
// ones before its own sources, while live reports true. It never touches the
// process environment: only this resolver reads them.
//
// A granted value only answers a secret field of the provider it was
// granted for: the field whose environment variables include Env, or, when
// the provider has exactly one secret field, that one (a factory may name
// its own variable). A grant can therefore never set a base URL, an account
// id, the provider choice or any other variable the harness reads. A
// resolver holding a grant never routes through the AI Firewall, so the key
// reaches only its provider. It returns the environment variable names now
// answered from the grant, sorted, for a log line that carries no value.
func (r *Resolver) UseGrant(secrets []GrantedSecret, live func() bool) []string {
	m := map[string]string{}
	// exact marks a variable a secret named itself, which a fallback never
	// replaces.
	exact := map[string]bool{}
	for _, s := range secrets {
		if s.Provider == "" || s.Value == "" {
			continue
		}
		var secretFields []Field
		for _, f := range r.spec(s.Provider) {
			if f.Secret && len(f.EnvVars) > 0 {
				secretFields = append(secretFields, f)
			}
		}
		var target string
		for _, f := range secretFields {
			if slices.Contains(f.EnvVars, s.Env) {
				target = s.Env
				break
			}
		}
		switch {
		case target != "":
			m[target], exact[target] = s.Value, true
		case len(secretFields) == 1:
			if t := secretFields[0].EnvVars[0]; !exact[t] {
				m[t] = s.Value
			}
		}
	}
	if len(m) == 0 {
		return nil
	}
	// A granted key goes to the provider and nowhere else: never to the AI
	// Firewall's gateway, which would store it (BYOK).
	off := false
	r.firewallEnabledOverride = &off
	prev := r.env
	r.env = func(name string) string {
		if v, ok := m[name]; ok && (live == nil || live()) {
			return v
		}
		return prev(name)
	}
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// GrantedMCPSecret is one MCP server credential a Keleustes vault grant
// lends: a server installed on this host, one key its entry binds, and the
// value. Memory only, like GrantedSecret.
type GrantedMCPSecret struct {
	Server, Key, Value string
}

// mcpGrant holds MCP credentials a Keleustes vault grant lent this process
// (UseMCPGrant). Process-wide: a worker or session process serves one
// dispatch, and every Resolver it makes (the MCP manager builds its own)
// must see them. Memory only.
var mcpGrant struct {
	sync.Mutex
	m    map[[2]string]string
	live func() bool
}

// UseMCPGrant answers MCPSecret for the granted (server, key) pairs while
// live reports true. A pair only answers what a server's entry asks for:
// MCPSecret is called for the keys an entry's `cred:` references bind and
// nothing else, so a granted key no entry binds is never used. It returns
// "server:key" names for a log line that carries no value.
func UseMCPGrant(secrets []GrantedMCPSecret, live func() bool) []string {
	m := map[[2]string]string{}
	for _, s := range secrets {
		if s.Value == "" || validMCPSecret(s.Server, s.Key) != nil {
			continue
		}
		m[[2]string{s.Server, s.Key}] = s.Value
	}
	if len(m) == 0 {
		return nil
	}
	mcpGrant.Lock()
	mcpGrant.m, mcpGrant.live = m, live
	mcpGrant.Unlock()
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k[0]+":"+k[1])
	}
	sort.Strings(names)
	return names
}

// grantedMCP is the granted value for (server, key), if a live grant holds one.
func grantedMCP(server, key string) (string, bool) {
	mcpGrant.Lock()
	defer mcpGrant.Unlock()
	v, ok := mcpGrant.m[[2]string{server, key}]
	if !ok || (mcpGrant.live != nil && !mcpGrant.live()) {
		return "", false
	}
	return v, true
}
