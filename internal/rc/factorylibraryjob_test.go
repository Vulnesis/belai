package rc

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/vulnetix/belai/internal/audit"
	"github.com/vulnetix/belai/internal/factorylink"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

func libraryJobPayload(t *testing.T, files map[string]string) string {
	t.Helper()
	enc := map[string]string{}
	for k, v := range files {
		enc[k] = base64.StdEncoding.EncodeToString([]byte(v))
	}
	b, _ := json.Marshal(map[string]any{"task": "convert", "kind": "agent", "format": "hermes", "name": "research", "files": enc})
	return string(b)
}

// readStream reads one audit stream file back.
func readStream(t *testing.T, path string) []audit.Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var evs []audit.Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e audit.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		evs = append(evs, e)
	}
	return evs
}

func TestKeleustesLibraryConvertJob(t *testing.T) {
	t.Setenv("BELAI_HOME", t.TempDir())
	state := t.TempDir()
	rec, err := audit.Open(state, "host-a")
	if err != nil {
		t.Fatal(err)
	}
	audit.SetDefault(rec)
	t.Cleanup(func() { audit.SetDefault(nil); rec.Close() })

	ff := newFake()
	ff.jobs = []*nodev1.Job{
		{Id: "l1", Kind: "library", PayloadJson: libraryJobPayload(t, map[string]string{
			"SOUL.md": "You are a careful research assistant.\n", "profile.yaml": "description: Research helper\n"})},
		{Id: "l2", Kind: "library", PayloadJson: libraryJobPayload(t, map[string]string{"../escape": "x"})},
		{Id: "l3", Kind: "library", PayloadJson: libraryJobPayload(t, map[string]string{".env": "A=1"})},
		{Id: "l4", Kind: "library", PayloadJson: `{"task":"install"}`},
	}
	got, _ := runFactoryDaemon(t, ff, Options{})
	r := got["l1"]
	if r.GetStatus() != jobOK {
		t.Fatalf("l1 = %+v", r)
	}
	var out struct {
		Doc, SHA256, Name string
	}
	if err := json.Unmarshal([]byte(r.GetOutputJson()), &out); err != nil || out.Name != "research" || out.SHA256 == "" ||
		!strings.Contains(out.Doc, "careful research assistant") {
		t.Errorf("l1 output = %s (%v)", r.GetOutputJson(), err)
	}
	for _, id := range []string{"l2", "l3", "l4"} {
		if r := got[id]; r.GetStatus() != jobRefused || r.GetError() == "" {
			t.Errorf("%s = %+v, want refused", id, r)
		}
	}
	// Each finished job is a host.dispatch fact naming the kind, in a chain
	// that verifies.
	rec.Close()
	evs := readStream(t, rec.Path())
	if bad := audit.Verify(evs); bad != -1 {
		t.Fatalf("chain breaks at %d", bad)
	}
	found := false
	for _, e := range evs {
		if e.Kind == string(audit.HostDispatch) && e.Data["kind"] == "library" && e.Data["status"] == jobOK {
			found = true
		}
	}
	if !found {
		t.Errorf("no library job fact in %+v", evs)
	}
}

func TestKeleustesLibraryJobAdvertisedAndStopped(t *testing.T) {
	t.Setenv("BELAI_HOME", t.TempDir())
	ff := newFake()
	ff.control = &factorylink.Control{Stopped: true, Reason: "freeze"}
	ff.jobs = []*nodev1.Job{{Id: "l1", Kind: "library", PayloadJson: libraryJobPayload(t, map[string]string{"SOUL.md": "Hi.\n", "profile.yaml": "description: d\n"})}}
	got, _ := runFactoryDaemon(t, ff, Options{})
	if r := got["l1"]; r.GetStatus() != jobRefused || !strings.Contains(r.GetError(), "stopped: freeze") {
		t.Errorf("l1 = %+v", r)
	}
	d, err := New(Options{Factory: newFake(), HostID: testHost, Inventory: func() Inventory { return Inventory{} }})
	if err != nil {
		t.Fatal(err)
	}
	if kinds := d.factoryAdvert().JobKinds; !slices.Contains(kinds, "library") {
		t.Errorf("job kinds = %v", kinds)
	}
}
