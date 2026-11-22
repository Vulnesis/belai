package harnessrun

import (
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/vulnetix/belai/internal/credentials"
	"github.com/vulnetix/belai/internal/harness"
)

// Key modes: how a Keleustes vault key may reach a third-party harness
// (docs/harness-sessions.md, "Keys"). The owner picks one in Keleustes,
// globally, per harness or per key; the dispatch carries the resolved mode.
const (
	// KeysOwnLogin: the harness uses its own login. No vault value reaches
	// the harness, whatever the dispatch carried; a grant is dropped unread.
	KeysOwnLogin = "own_login"
	// KeysHandoff: the owner chose a vault key for this one session.
	KeysHandoff = "handoff"
	// KeysAlways: the owner set the provider's vault key to go to every
	// session of this harness.
	KeysAlways = "always"
)

// ValidKeyMode reports whether m is a key mode ("" reads as own login).
func ValidKeyMode(m string) bool {
	return m == "" || m == KeysOwnLogin || m == KeysHandoff || m == KeysAlways
}

// Grant is the part of factorylink.Grant a harness session uses.
type Grant interface {
	ID() string
	Secrets(now time.Time) []credentials.GrantedSecret
	Expires() time.Time
	Drop()
}

// Handoff is what one session hands to its harness: environment entries for
// the harness child only, and the names (never values) for audit and display.
type Handoff struct {
	Env   []string
	Names []string
	// Dropped are granted names the profile does not allow.
	Dropped []string
	GrantID string
}

// ErrKeysStopped refuses a hand-off while the factory is stopped.
var ErrKeysStopped = errors.New("the factory is stopped; no vault key is handed to a harness")

// HandOff resolves the key hand-off for one launch. Own login (or no grant)
// hands nothing and drops the grant. Hand-off and always pass only the
// granted variables the profile lists in grant_env, as KEY=value entries for
// the harness child's environment: never belai's own environment, a file, an
// argv or a log. stopped refuses any hand-off.
func HandOff(mode string, g Grant, l *harness.Launch, stopped bool, now time.Time) (Handoff, error) {
	var h Handoff
	if g == nil {
		return h, nil
	}
	h.GrantID = g.ID()
	if mode == "" || mode == KeysOwnLogin {
		g.Drop()
		return h, nil
	}
	if !ValidKeyMode(mode) {
		g.Drop()
		return h, errors.New("unknown key mode")
	}
	if stopped {
		g.Drop()
		return h, ErrKeysStopped
	}
	for _, s := range g.Secrets(now) {
		if !slices.Contains(l.GrantEnv, s.Env) || !harness.GrantEnvName(s.Env) {
			h.Dropped = append(h.Dropped, s.Env)
			continue
		}
		if slices.Contains(h.Names, s.Env) {
			continue
		}
		h.Env = append(h.Env, s.Env+"="+s.Value)
		h.Names = append(h.Names, s.Env)
	}
	sort.Strings(h.Names)
	sort.Strings(h.Dropped)
	return h, nil
}
