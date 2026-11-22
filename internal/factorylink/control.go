package factorylink

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/vulnetix/belai/internal/a2a"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sanitize"
)

// Factory control (docs/keleustes.md#factory-control). Keleustes can stop the
// whole factory and black out A2A. The link owner learns the state from the
// Welcome frame and every Control frame, and records it for the host in
// <profile>/control.json, so every belai process on the host obeys it:
//
//   - stopped: no dispatch or job is taken, and no session takes a remote
//     prompt (it is refused, saying so);
//   - a2a_blackout: the host's A2A blackout file (a2a.SetBlackout) is set,
//     which stops every relay on the host in both directions.
//
// Processes that do not own the link also read Board.State when their relay
// starts, so a blackout reaches them even with no link owner running.

// Control is the factory's control state as the host last saw it.
type Control struct {
	Stopped     bool      `json:"stopped"`
	A2ABlackout bool      `json:"a2aBlackout"`
	Reason      string    `json:"reason,omitempty"`
	At          time.Time `json:"at"`
}

// controlFromPB cleans a FactoryControl from the server. The reason is
// remote text: one short line.
func controlFromPB(c *nodev1.FactoryControl) Control {
	return Control{Stopped: c.GetStopped(), A2ABlackout: c.GetA2ABlackout(),
		Reason: sanitize.Line(c.GetReason(), 200), At: time.Now().UTC()}
}

func (p *Profile) controlPath() string { return filepath.Join(p.dir, "control.json") }

// home is the belai home the profile lives under.
func (p *Profile) home() string { return filepath.Dir(filepath.Dir(p.dir)) }

// Control reads the last control state recorded for the host. None is
// running with no blackout.
func (p *Profile) Control() Control {
	data, err := os.ReadFile(p.controlPath())
	if err != nil {
		return Control{}
	}
	var c Control
	if json.Unmarshal(data, &c) != nil {
		return Control{}
	}
	return c
}

// ApplyControl records c for every process on the host and sets the host's
// A2A blackout to match.
func (p *Profile) ApplyControl(c Control) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := writeFile(p.controlPath(), data, 0o600); err != nil {
		return err
	}
	_, err = a2a.SetBlackout(a2a.Dir(p.home()), c.A2ABlackout, time.Now())
	return err
}

// FactoryStopped reports whether the active, unrevoked Keleustes profile
// under home says the factory is stopped, and why. A host with no profile is
// never stopped.
func FactoryStopped(home string) (bool, string) {
	p, err := Active(home)
	if err != nil || p.Revoked != "" {
		return false, ""
	}
	c := p.Control()
	return c.Stopped, c.Reason
}

// RefreshControl reads Board.State once and records it. A process that does
// not own the link calls it so a blackout reaches it without one.
func RefreshControl(ctx context.Context, c *Client) (Control, error) {
	st, err := c.State(ctx)
	if err != nil {
		return Control{}, err
	}
	ctl := controlFromPB(st)
	return ctl, c.Profile().ApplyControl(ctl)
}

// activeClient is a client for the active, unrevoked profile under home.
func activeClient(home string) (*Client, error) {
	p, err := Active(home)
	if err != nil {
		return nil, err
	}
	if p.Revoked != "" {
		return nil, ErrNoProfile
	}
	return NewClient(p)
}

// ActiveClient is activeClient for callers outside the package.
func ActiveClient(home string) (*Client, error) { return activeClient(home) }
