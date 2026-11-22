package products

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sanitize"
)

// aifwDoc is the part of `vulnetix ai-firewall status -o json` read here.
// The gateway, provider and guardrail blocks are the org's policy, which
// stays in the Vulnetix console.
type aifwDoc struct {
	Clients []struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Scope string `json:"scope"`
		Path  string `json:"path"`
		State string `json:"state"`
	} `json:"clients"`
	Checks []struct {
		ID       string `json:"id"`
		Severity string `json:"severity"`
		Client   string `json:"client"`
	} `json:"checks"`
	Summary struct {
		Errors   int `json:"errors"`
		Warnings int `json:"warnings"`
	} `json:"summary"`
}

// aifwWired is the client state that means "points at this org's gateway".
const aifwWired = "wired"

// probeAIFW reports which AI clients are wired to the AI firewall gateway.
// Check hints are composed here from the check's identifiers; the CLI's
// message text is not carried.
func (p *Prober) probeAIFW(ctx context.Context) *nodev1.ProductStatus {
	st := &nodev1.ProductStatus{State: "absent"}
	path, ok := p.lookPath("vulnetix")
	if !ok {
		return st
	}
	out, err := p.run(ctx, path, "--disable-memory", "ai-firewall", "status", "-o", "json")
	var doc aifwDoc
	if err != nil || out.Exit != 0 || !looksJSONObject(out.Stdout) || json.Unmarshal(out.Stdout, &doc) != nil {
		st.State = "error"
		st.Degraded = append(st.Degraded, "status")
		st.Checks = append(st.Checks, check("status", "error", "ai-firewall status did not answer"))
		return st
	}
	wired := false
	for _, c := range doc.Clients {
		id := ident(c.ID)
		if id == "" {
			continue
		}
		on := c.State == aifwWired
		wired = wired || on
		st.Parts = append(st.Parts, &nodev1.Toggle{Id: id, Label: sanitize.Line(c.Name, 64), Scope: word(c.Scope), On: on,
			Path: HomeRel(p.Home, c.Path), State: word(c.State)})
	}
	for _, c := range doc.Checks {
		status := "warn"
		if c.Severity == "error" {
			status = "error"
		}
		hint := status
		if cl := ident(c.Client); cl != "" {
			hint = fmt.Sprintf("%s for client %s", status, cl)
		}
		if id := ident(c.ID); id != "" {
			st.Checks = append(st.Checks, check("aifw:"+id, status, hint))
		}
	}
	switch {
	case doc.Summary.Errors > 0:
		st.State = "degraded"
	case wired:
		st.State = "configured"
	default:
		st.State = "installed"
	}
	return st
}
