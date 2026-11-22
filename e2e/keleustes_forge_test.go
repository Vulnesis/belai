package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestKeleustesForgeJobOnANode: Keleustes reaches github.com through a
// belai node (the fallback when its own gh is signed out). The node
// advertises its gh login and the `forge` job kind, so Keleustes sends a
// `forge` job (kls-github select.rs node_reach), and belai runs the fake gh
// on its PATH with `--hostname github.com` forced. Real binaries throughout:
// a headless Keleustes, `belai connect` + `belai rc`, and the kls_e2e driver.
func TestKeleustesForgeJobOnANode(t *testing.T) {
	k := startKeleustes(t)
	d := driver(t, k)
	model := newKeleustesModel(t)

	bin := t.TempDir()
	argvLog := filepath.Join(t.TempDir(), "gh-argv.log")
	script := `#!/bin/sh
case "$1 $2" in
"auth status")
  echo "github.com"
  echo "  ✓ Logged in to github.com account octo (keyring)"
  echo "  - Active account: true"
  exit 0 ;;
"api "*|"api")
  echo "$*" >> '` + argvLog + `'
  echo '{"login":"octo"}'
  exit 0 ;;
esac
echo "fake gh: unexpected $*" >&2
exit 2
`
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	h := startRC(t, k, "forge-node", model.URL)

	// The node is online and its advert lists the gh login and the forge job.
	var node string
	eventually(t, 60*time.Second, "node online with its gh login", func() bool {
		for _, line := range strings.Split(k.kel("nodes", "list"), "\n") {
			if f := strings.Split(line, "\t"); len(f) > 1 && f[1] == h.label {
				node = f[0]
			}
		}
		if node == "" {
			return false
		}
		out, err := d.try("node", node)
		return err == nil && strings.Contains(out, `"forge"`) && strings.Contains(out, "gh@github.com:true")
	})

	var res struct {
		Job    string `json:"job"`
		Exit   int    `json:"exit"`
		Stdout string `json:"stdout"`
		Stderr string `json:"stderr"`
	}
	eventually(t, 90*time.Second, "a forge job answered by the node", func() bool {
		out, err := d.try("forge-api", node, "/user")
		if err != nil {
			t.Logf("forge-api: %v: %s", err, out)
			return false
		}
		lines := strings.Split(out, "\n")
		return json.Unmarshal([]byte(lines[len(lines)-1]), &res) == nil && res.Exit == 0
	})
	if res.Job != "forge" || !strings.Contains(res.Stdout, `"login":"octo"`) {
		t.Fatalf("forge-api = %+v", res)
	}
	b, err := os.ReadFile(argvLog)
	if err != nil {
		t.Fatalf("the fake gh never ran: %v", err)
	}
	if got := strings.TrimSpace(string(b)); !strings.Contains(got, "api --hostname github.com /user") {
		t.Errorf("gh ran %q, want --hostname forced", got)
	}
	// The node audited the job as a harness fact: kind, status, host and CLI.
	eventually(t, 20*time.Second, "the node's audit records the forge job", func() bool {
		found := false
		_ = filepath.WalkDir(h.home, func(p string, e os.DirEntry, err error) error {
			if err != nil || e.IsDir() || filepath.Base(filepath.Dir(p)) != "audit" || !strings.HasSuffix(p, ".jsonl") {
				return nil
			}
			b, _ := os.ReadFile(p)
			for _, line := range strings.Split(string(b), "\n") {
				if strings.Contains(line, `"kind":"forge"`) && strings.Contains(line, `"status":"ok"`) &&
					strings.Contains(line, `"tool":"gh"`) && strings.Contains(line, `"forge":"github.com"`) {
					found = true
				}
			}
			return nil
		})
		return found
	})
}
