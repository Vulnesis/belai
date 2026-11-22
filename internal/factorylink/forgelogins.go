package factorylink

import (
	"bufio"
	"context"
	"encoding/json"
	"net/url"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/forge"
	"github.com/vulnetix/belai/internal/proc"
	"github.com/vulnetix/belai/internal/sanitize"
)

// Forge CLI logins (Capabilities.forges, keleustes docs/gaps/forges.md
// WP-9): every gh, glab and tea login on this host, signed in or not, so
// Keleustes routes a forge job only to a node that can run it. Only hosts,
// account names and a yes or no leave the host; a token never does (the
// status commands print a masked token at most, and nothing but the host
// and login is kept from their output).

// forgeRun runs one status command with the scrubbed environment and
// returns its combined output and whether it exited 0. Swapped in tests.
var forgeRun = func(ctx context.Context, prog string, args ...string) (string, bool) {
	path, err := exec.LookPath(prog)
	if err != nil {
		return "", false
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = proc.ScrubbedEnv()
	out, err := cmd.CombinedOutput()
	if len(out) > 64<<10 {
		out = out[:64<<10]
	}
	return string(out), err == nil
}

// forgeHave reports whether a CLI is installed. Swapped in tests.
var forgeHave = func(prog string) bool {
	_, err := exec.LookPath(prog)
	return err == nil
}

var (
	// gh: "✓ Logged in to <host> account <login> (keyring)" or
	// "X Failed to log in to <host> account <login> ...". glab prints
	// "Logged in to <host> as <login>".
	loggedIn  = regexp.MustCompile(`(?i)logged in to (\S+) (?:account|as) (\S+)`)
	failedIn  = regexp.MustCompile(`(?i)failed to log in to (\S+)(?: account (\S+))?`)
	activeYes = regexp.MustCompile(`(?i)active account:\s*true`)
	activeNo  = regexp.MustCompile(`(?i)active account:\s*false`)
)

// hostShape keeps a host[:port] of plain characters only.
func hostShape(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if h == "" || len(h) > 253 {
		return ""
	}
	for _, r := range h {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == ':') {
			return ""
		}
	}
	return h
}

// parseStatus reads gh's or glab's `auth status` text: per host, the
// active (or only) account and whether it is signed in. A host with a
// signed-in active account wins over a failed inactive one.
func parseStatus(cli, out string) []*nodev1.ForgeLogin {
	type acct struct {
		login       string
		ok, active  bool
		activeKnown bool
	}
	byHost := map[string][]*acct{}
	var order []string
	var cur *acct
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		var host, login string
		ok := false
		if m := loggedIn.FindStringSubmatch(line); m != nil {
			host, login, ok = m[1], m[2], true
		} else if m := failedIn.FindStringSubmatch(line); m != nil {
			host, login = m[1], m[2]
		} else {
			if cur != nil && activeYes.MatchString(line) {
				cur.active, cur.activeKnown = true, true
			} else if cur != nil && activeNo.MatchString(line) {
				cur.activeKnown = true
			}
			continue
		}
		host = hostShape(strings.TrimSuffix(host, ":"))
		if host == "" {
			cur = nil
			continue
		}
		if _, seen := byHost[host]; !seen {
			order = append(order, host)
		}
		cur = &acct{login: sanitize.Ident(strings.Trim(login, "()"), 64), ok: ok}
		byHost[host] = append(byHost[host], cur)
	}
	var out2 []*nodev1.ForgeLogin
	for _, h := range order {
		accts := byHost[h]
		pick := accts[0]
		for _, a := range accts {
			if a.active || (!a.activeKnown && a.ok) {
				pick = a
				break
			}
		}
		out2 = append(out2, &nodev1.ForgeLogin{Cli: cli, Host: h, Kind: forgeKind(cli, h), Login: pick.login, SignedIn: pick.ok})
	}
	return out2
}

// parseTeaLogins reads `tea login list -o json`: name, url and user per
// login, whatever the case of the keys.
func parseTeaLogins(out string) []teaLogin {
	var raw []map[string]any
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &raw) != nil {
		return nil
	}
	var logins []teaLogin
	for _, m := range raw {
		get := func(k string) string {
			for key, v := range m {
				if strings.EqualFold(key, k) {
					s, _ := v.(string)
					return s
				}
			}
			return ""
		}
		u, err := url.Parse(get("url"))
		if err != nil || u.Host == "" {
			continue
		}
		host := hostShape(u.Host)
		name := get("name")
		if host == "" || name == "" || sanitize.Ident(name, 64) != name {
			continue
		}
		logins = append(logins, teaLogin{name: name, host: host, user: sanitize.Ident(get("user"), 64)})
	}
	return logins
}

type teaLogin struct{ name, host, user string }

// forgeKind is the kind belai's forges setting gives host, else what the CLI implies.
func forgeKind(cli, host string) string {
	if k, ok := forge.HostKind(host); ok {
		return k
	}
	switch {
	case cli == "gh" && host == "github.com":
		return "github"
	case cli == "gh":
		return "ghes"
	case cli == "glab":
		return "gitlab"
	}
	return ""
}

// ForgeLogins lists every forge CLI login on this host.
func ForgeLogins(ctx context.Context) []*nodev1.ForgeLogin {
	var out []*nodev1.ForgeLogin
	if forgeHave("gh") {
		txt, _ := forgeRun(ctx, "gh", "auth", "status")
		out = append(out, parseStatus("gh", txt)...)
	}
	if forgeHave("glab") {
		txt, _ := forgeRun(ctx, "glab", "auth", "status", "--all")
		out = append(out, parseStatus("glab", txt)...)
	}
	if forgeHave("tea") {
		txt, ok := forgeRun(ctx, "tea", "login", "list", "-o", "json")
		if ok {
			for _, l := range parseTeaLogins(txt) {
				// A listed login is signed in only when the API answers.
				_, signed := forgeRun(ctx, "tea", "api", "-l", l.name, "/user")
				out = append(out, &nodev1.ForgeLogin{Cli: "tea", Host: l.host, Kind: forgeKind("tea", l.host), Login: l.user, SignedIn: signed})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].GetCli() != out[j].GetCli() {
			return out[i].GetCli() < out[j].GetCli()
		}
		return out[i].GetHost() < out[j].GetHost()
	})
	return out
}

var forgeCache struct {
	sync.Mutex
	list []*nodev1.ForgeLogin
	at   time.Time
}

// cachedForgeLogins is ForgeLogins reused for a minute (the advert is sent
// on every connection and heartbeat change).
func cachedForgeLogins(ctx context.Context) []*nodev1.ForgeLogin {
	forgeCache.Lock()
	defer forgeCache.Unlock()
	if !forgeCache.at.IsZero() && time.Since(forgeCache.at) < ghAuthTTL {
		return forgeCache.list
	}
	forgeCache.list, forgeCache.at = ForgeLogins(ctx), time.Now()
	return forgeCache.list
}

// ForgeSignedIn reports whether cli is signed in to host here (a forge job's check).
func ForgeSignedIn(ctx context.Context, cli, host string) bool {
	host = strings.ToLower(host)
	for _, f := range cachedForgeLogins(ctx) {
		if f.GetCli() == cli && f.GetHost() == host && f.GetSignedIn() {
			return true
		}
	}
	return false
}
