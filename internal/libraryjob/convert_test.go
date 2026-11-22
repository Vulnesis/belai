package libraryjob

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vulnetix/belai/internal/libitem"
)

func payload(t *testing.T, format, name string, files map[string]string) string {
	t.Helper()
	enc := map[string]string{}
	for k, v := range files {
		enc[k] = base64.StdEncoding.EncodeToString([]byte(v))
	}
	b, err := json.Marshal(map[string]any{"task": "convert", "kind": "agent", "format": format, "name": name, "files": enc})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func hermes() map[string]string {
	return map[string]string{
		"SOUL.md":               "You are a careful research assistant.\n",
		"profile.yaml":          "description: Research helper\n",
		"config.yaml":           "model:\n  default: anthropic/claude-sonnet-4-5\n",
		"skills/notes/SKILL.md": "---\nname: notes\ndescription: Take notes in the house style\n---\n\nWrite short notes.\n",
	}
}

func TestConvertHermes(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	r, why := Parse(payload(t, "hermes", "research", hermes()))
	if why != "" {
		t.Fatal(why)
	}
	out, why, err := Convert(r)
	if err != nil || why != "" {
		t.Fatalf("convert: %v %q", err, why)
	}
	if left, _ := filepath.Glob(filepath.Join(os.TempDir(), "belai-library-job-*")); len(left) > 0 {
		t.Errorf("staging directory left behind: %v", left)
	}
	var res Result
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatal(err)
	}
	if res.Name != "research" || res.Format != "hermes" || !strings.Contains(res.Doc, "careful research assistant") {
		t.Errorf("result = %+v", res)
	}
	if res.SHA256 != libitem.Hash([]byte(res.Doc)) {
		t.Errorf("sha256 %s is not the libitem hash of the doc", res.SHA256)
	}
	if len(res.Skills) != 1 || res.Skills[0].Name != "notes" || res.Skills[0].SHA256 != libitem.Hash([]byte(res.Skills[0].Doc)) {
		t.Errorf("skills = %+v", res.Skills)
	}
	if len(res.Notes) == 0 {
		t.Error("no notes")
	}
}

func TestConvertRefusesBadDefinition(t *testing.T) {
	r, why := Parse(payload(t, "claws", "", map[string]string{"README.md": "nothing here"}))
	if why != "" {
		t.Fatal(why)
	}
	_, why, err := Convert(r)
	if err != nil || why == "" {
		t.Fatalf("want a refusal, got %v %q", err, why)
	}
}

func TestParseRefuses(t *testing.T) {
	big := strings.Repeat("a", 1<<20+1)
	cases := map[string]string{
		"not json":     "{",
		"task":         `{"task":"run","kind":"agent","format":"hermes","files":{"a":"YQ=="}}`,
		"kind":         `{"task":"convert","kind":"skill","format":"hermes","files":{"a":"YQ=="}}`,
		"format":       payload(t, "claude-code", "", map[string]string{"a": "b"}),
		"name":         payload(t, "hermes", "../x", map[string]string{"a": "b"}),
		"no files":     payload(t, "hermes", "", nil),
		"abs":          payload(t, "hermes", "", map[string]string{"/etc/passwd": "x"}),
		"dotdot":       payload(t, "hermes", "", map[string]string{"a/../../x": "x"}),
		"parent":       payload(t, "hermes", "", map[string]string{"../x": "x"}),
		"unclean":      payload(t, "hermes", "", map[string]string{"a//b": "x"}),
		"backslash":    payload(t, "hermes", "", map[string]string{`a\b`: "x"}),
		"git":          payload(t, "hermes", "", map[string]string{".git/config": "x"}),
		"deep":         payload(t, "hermes", "", map[string]string{"a/b/c/d/e/f/g": "x"}),
		"credential":   payload(t, "hermes", "", map[string]string{"auth.json": "{}"}),
		"env":          payload(t, "hermes", "", map[string]string{"x/.env": "A=1"}),
		"control":      payload(t, "hermes", "", map[string]string{"a\x1b.md": "x"}),
		"file and dir": payload(t, "hermes", "", map[string]string{"a": "x", "a/b": "y"}),
		"big file":     payload(t, "hermes", "", map[string]string{"SOUL.md": big}),
		"base64":       `{"task":"convert","kind":"agent","format":"hermes","files":{"a":"!!"}}`,
	}
	for name, p := range cases {
		if _, why := Parse(p); why == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	many := map[string]string{}
	for i := range 1001 {
		many[fmt.Sprintf("d/f%d", i)] = "x"
	}
	if _, why := Parse(payload(t, "hermes", "", many)); why == "" {
		t.Error("1001 files accepted")
	}
	total := map[string]string{}
	for i := range 9 {
		total[fmt.Sprintf("f%d", i)] = strings.Repeat("z", 1<<20)
	}
	if _, why := Parse(payload(t, "hermes", "", total)); why == "" {
		t.Error("9 MiB accepted")
	}
}
