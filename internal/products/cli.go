package products

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/vulnetixcli"
)

// cliAuthDoc is `vulnetix auth status -o json`. Only these fields are read.
type cliAuthDoc struct {
	Authenticated bool   `json:"authenticated"`
	OrgID         string `json:"orgId"`
	Source        string `json:"source"`
	Method        string `json:"method"`
}

// probeCLI reports the Vulnetix CLI: installed or not, its version and
// install method, and whether it is signed in and with which source.
func (p *Prober) probeCLI(ctx context.Context) *nodev1.ProductStatus {
	st := &nodev1.ProductStatus{State: "absent"}
	path, ok := p.lookPath("vulnetix")
	if !ok {
		return st
	}
	st.State, st.Path = "installed", HomeRel(p.Home, path)
	if m, _ := vulnetixcli.DetectInstall(path, p.Getenv); m != "" && m != vulnetixcli.InstallUnknown {
		st.InstallMethod = string(m)
	}
	if out, err := p.run(ctx, path, "version", "--short"); err == nil && out.Exit == 0 {
		st.Version = version(firstLine(out.Stdout))
	}
	if st.Version == "" {
		st.Degraded = append(st.Degraded, "version")
	}
	auth, src, ok := p.cliAuth(ctx, path)
	if !ok {
		st.Degraded = append(st.Degraded, "auth")
		st.Checks = append(st.Checks, check("auth", "warn", "the CLI's sign-in state could not be read"))
		return st
	}
	st.Authenticated, st.AuthSource = auth.Authenticated, src
	if auth.Authenticated {
		st.State, st.OrgId = "active", ident(auth.OrgID)
		st.Checks = append(st.Checks, check("auth", "ok", "signed in"))
	} else {
		st.Checks = append(st.Checks, check("auth", "warn", "not signed in"))
	}
	return st
}

// cliAuth reads the sign-in state: the JSON form when the CLI has it, else
// the text form through vulnetixcli.ParseAuthStatus, which fails closed.
func (p *Prober) cliAuth(ctx context.Context, path string) (cliAuthDoc, string, bool) {
	if out, err := p.run(ctx, path, "--disable-memory", "auth", "status", "-o", "json"); err == nil && out.Exit == 0 {
		var doc cliAuthDoc
		if json.Unmarshal(out.Stdout, &doc) == nil && looksJSONObject(out.Stdout) {
			return doc, authSource(doc.Source + " " + doc.Method), true
		}
	}
	out, err := p.run(ctx, path, "--disable-memory", "auth", "status")
	if err != nil {
		return cliAuthDoc{}, "", false
	}
	a := vulnetixcli.ParseAuthStatus(string(out.Stdout))
	if !a.Parsed {
		return cliAuthDoc{}, "", false
	}
	src := ""
	switch a.Active {
	case vulnetixcli.SourceEnvAPIToken, vulnetixcli.SourceEnvAPIKey, vulnetixcli.SourceEnvVVD:
		src = "env"
	case vulnetixcli.SourceProjectCreds:
		src = "project"
	case vulnetixcli.SourceHomeCreds:
		src = "home"
	case vulnetixcli.SourceKeyring:
		src = "keyring"
	}
	return cliAuthDoc{Authenticated: a.Authenticated, OrgID: a.OrgID}, src, true
}

// authSource maps the CLI's source words onto the four ProductStatus knows.
func authSource(s string) string {
	s = strings.ToLower(s)
	switch {
	case strings.Contains(s, "env"):
		return "env"
	case strings.Contains(s, "project"):
		return "project"
	case strings.Contains(s, "keyring"), strings.Contains(s, "keychain"):
		return "keyring"
	case strings.Contains(s, "home"), strings.Contains(s, "file"):
		return "home"
	}
	return ""
}

func firstLine(b []byte) string {
	s, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(s)
}

func looksJSONObject(b []byte) bool {
	s := strings.TrimSpace(string(b))
	return strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")
}
