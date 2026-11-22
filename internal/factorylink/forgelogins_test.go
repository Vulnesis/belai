package factorylink

import (
	"context"
	"strings"
	"testing"
	"time"
)

const ghStatus = `github.com
  X Failed to log in to github.com account old-user (keyring)
  - Active account: false
  - The token in keyring is invalid.

  ✓ Logged in to github.com account new-user (keyring)
  - Active account: true
  - Git operations protocol: ssh
  - Token: gho_************************************

ghe.example.com
  X Failed to log in to ghe.example.com account dev (keyring)
  - Active account: true
`

const glabStatus = `gitlab.com
  ✓ Logged in to gitlab.com as gl-user (/home/u/.config/glab-cli/config.yml)
  ✓ Git operations for gitlab.com configured to use ssh protocol.
  ✓ Token: **************************
git.corp.example:8443
  x git.corp.example:8443: API call failed: GET https://git.corp.example:8443/api/v4/user: 401
`

const teaList = `[{"name":"codeberg.org","url":"https://codeberg.org","user":"tea-user","default":true},
 {"Name":"gitea","URL":"https://gitea.example.com/","User":"g"}]`

func TestForgeLoginsEveryCLIAndHost(t *testing.T) {
	prevRun, prevHave := forgeRun, forgeHave
	forgeCache.Lock()
	forgeCache.at = time.Time{}
	forgeCache.Unlock()
	t.Cleanup(func() { forgeRun, forgeHave = prevRun, prevHave })
	forgeHave = func(string) bool { return true }
	forgeRun = func(_ context.Context, prog string, args ...string) (string, bool) {
		switch {
		case prog == "gh":
			return ghStatus, false
		case prog == "glab":
			return glabStatus, false
		case prog == "tea" && args[0] == "login":
			return teaList, true
		case prog == "tea" && args[0] == "api":
			// Only codeberg answers.
			return "", args[2] == "codeberg.org"
		}
		return "", false
	}
	got := map[string]bool{}
	logins := map[string]string{}
	for _, f := range ForgeLogins(context.Background()) {
		key := f.GetCli() + " " + f.GetHost()
		got[key] = f.GetSignedIn()
		logins[key] = f.GetLogin()
		if strings.Contains(f.String(), "gho_") {
			t.Fatalf("a token reached the advert: %v", f)
		}
	}
	want := map[string]bool{
		"gh github.com": true, "gh ghe.example.com": false,
		"glab gitlab.com":  true,
		"tea codeberg.org": true, "tea gitea.example.com": false,
	}
	for k, v := range want {
		if s, ok := got[k]; !ok || s != v {
			t.Errorf("%s = %v (present %v), want %v; all %v", k, s, ok, v, got)
		}
	}
	if logins["gh github.com"] != "new-user" || logins["glab gitlab.com"] != "gl-user" {
		t.Errorf("logins = %v", logins)
	}
	forgeCache.Lock()
	forgeCache.at = time.Time{}
	forgeCache.Unlock()
	if !ForgeSignedIn(context.Background(), "tea", "codeberg.org") || ForgeSignedIn(context.Background(), "gh", "ghe.example.com") {
		t.Error("ForgeSignedIn disagrees with the advert")
	}
	forgeCache.Lock()
	forgeCache.at = time.Time{}
	forgeCache.Unlock()
}
