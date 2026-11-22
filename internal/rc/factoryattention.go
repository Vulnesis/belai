package rc

import (
	"context"
	"time"

	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sanitize"
)

// Attention requests to Keleustes (docs/keleustes.md#attention). In factory
// mode there is no Vulnetix login to renew, so the daemon asks for what it
// can name: a gh sign-in when a github job found gh signed out. A request is
// identifiers from closed lists; the owner's decision arrives on the link and
// settles the request once.

// factoryAskAgain spaces requests of one kind and subject.
const factoryAskAgain = time.Hour

type factoryAsk struct {
	kind, subject string
	at            time.Time
}

// factoryAttention files a request unless one of the same kind and subject
// is open or was filed within factoryAskAgain.
func (d *Daemon) factoryAttention(ctx context.Context, kind, reason, subject string) {
	d.mu.Lock()
	if d.factoryAsks == nil {
		d.factoryAsks = map[string]*factoryAsk{}
	}
	for _, a := range d.factoryAsks {
		if a.kind == kind && a.subject == subject && time.Since(a.at) < factoryAskAgain {
			d.mu.Unlock()
			return
		}
	}
	d.mu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	id, err := d.o.Factory.Attention(cctx, kind, reason, subject)
	if err != nil {
		d.logf("could not ask the Keleustes owner (%s): %v", kind, err)
		return
	}
	d.mu.Lock()
	d.factoryAsks[id] = &factoryAsk{kind: kind, subject: subject, at: time.Now()}
	d.mu.Unlock()
	audit.Emit(audit.Fact{Kind: audit.HostDispatch, ActorKind: audit.ActorHarness,
		Data: map[string]string{"dispatch": "attention", "status": kind, "via": "keleustes"}})
	d.logf("asked the Keleustes owner: %s (request %s)", kind, short(id))
}

// factoryDecided settles a request the owner decided. A repeat (a replayed
// frame) or an id this daemon did not file does nothing.
func (d *Daemon) factoryDecided(dec *nodev1.AttentionDecided) {
	d.mu.Lock()
	a := d.factoryAsks[dec.GetId()]
	delete(d.factoryAsks, dec.GetId())
	d.mu.Unlock()
	if a == nil {
		return
	}
	state := sanitize.Ident(dec.GetState(), 16)
	switch {
	case state == "approved" && a.kind == "gh_login":
		d.logf("the Keleustes owner approved signing gh in: run `gh auth login` on this host")
	default:
		d.logf("the Keleustes owner answered %s: %s", a.kind, state)
	}
}
