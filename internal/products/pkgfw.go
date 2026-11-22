package products

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/sanitize"
)

// pkgfwDoc is `vulnetix package-firewall status -o json`.
type pkgfwDoc struct {
	ProxyHost  string `json:"proxyHost"`
	Ecosystems []struct {
		ID         string `json:"id"`
		Label      string `json:"label"`
		Configured bool   `json:"configured"`
		Scope      string `json:"scope"`
		Path       string `json:"path"`
	} `json:"ecosystems"`
	Entitlement string `json:"entitlement"`
}

// pkgfwProxyHosts are the hosts a configured file points at, under either
// brand.
var pkgfwProxyHosts = []string{"packages.vulnetix.com", "packages.vulnes.is"}

// pkgfwFiles are the per-ecosystem files the fallback reads when the CLI has
// no JSON status: the same files cli/pkg/packagefirewall/detect.go reads.
var pkgfwFiles = []struct{ id, label, rel string }{
	{"npm", "npm", ".npmrc"},
	{"pypi", "PyPI", ".config/pip/pip.conf"},
	{"pypi", "PyPI", ".pip/pip.conf"},
	{"cargo", "Cargo", ".cargo/config.toml"},
	{"gem", "RubyGems", ".gemrc"},
	{"maven", "Maven", ".m2/settings.xml"},
	{"nuget", "NuGet", ".nuget/NuGet/NuGet.Config"},
}

// probePkgFW reports which ecosystems point at the package firewall, and the
// add-on entitlement as the CLI reports it.
func (p *Prober) probePkgFW(ctx context.Context) *nodev1.ProductStatus {
	st := &nodev1.ProductStatus{}
	path, haveCLI := p.lookPath("vulnetix")
	if haveCLI {
		if out, err := p.run(ctx, path, "--disable-memory", "package-firewall", "status", "-o", "json"); err == nil && out.Exit == 0 && looksJSONObject(out.Stdout) {
			var doc pkgfwDoc
			if json.Unmarshal(out.Stdout, &doc) == nil {
				for _, e := range doc.Ecosystems {
					id := ident(e.ID)
					if id == "" {
						continue
					}
					st.Parts = append(st.Parts, &nodev1.Toggle{Id: id, Label: sanitize.Line(e.Label, 64), Scope: word(e.Scope),
						On: e.Configured, Path: HomeRel(p.Home, e.Path)})
				}
				switch doc.Entitlement {
				case "entitled", "not_entitled":
					st.Entitlement = doc.Entitlement
				}
				st.State = pkgfwState(st.Parts, true)
				return st
			}
		}
		st.Degraded = append(st.Degraded, "status_json")
	}
	st.Parts = p.pkgfwFromFiles()
	st.State = pkgfwState(st.Parts, haveCLI)
	return st
}

// pkgfwFromFiles reads the known files for the proxy host. A file is read
// only to look for the host; nothing from it is reported.
func (p *Prober) pkgfwFromFiles() []*nodev1.Toggle {
	var out []*nodev1.Toggle
	seen := map[string]bool{}
	if p.Home == "" {
		return nil
	}
	for _, f := range pkgfwFiles {
		if seen[f.id] {
			continue
		}
		full := filepath.Join(p.Home, f.rel)
		info, err := os.Lstat(full)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
			continue
		}
		data, err := os.ReadFile(full)
		if err != nil {
			continue
		}
		on := false
		for _, h := range pkgfwProxyHosts {
			if strings.Contains(string(data), h) {
				on = true
			}
		}
		if on {
			seen[f.id] = true
			out = append(out, &nodev1.Toggle{Id: f.id, Label: f.label, Scope: "user", On: true, Path: HomeRel(p.Home, full)})
		}
	}
	if gp := p.getenv("GOPROXY"); gp != "" {
		for _, h := range pkgfwProxyHosts {
			if strings.Contains(gp, h) {
				out = append(out, &nodev1.Toggle{Id: "go", Label: "Go", Scope: "env", On: true})
				break
			}
		}
	}
	return out
}

func pkgfwState(parts []*nodev1.Toggle, haveCLI bool) string {
	for _, t := range parts {
		if t.On {
			return "configured"
		}
	}
	if haveCLI {
		return "installed"
	}
	return "absent"
}
