package commands

import (
	"reflect"
	"testing"
)

func TestParseSnapshotsEveryCLIForm(t *testing.T) {
	out := `Snapshot: https://www.vulnes.is/snapshots/a
  ✓ Memory:   .vulnetix/memory.yaml
  ✓ Snapshot: https://www.vulnes.is/snapshots/b
  ✓ SAST Snapshot: https://www.vulnes.is/snapshots/c
Secrets snapshot: https://www.vulnes.is/snapshots/d
Malscan snapshot: https://www.vulnes.is/snapshots/e.
License snapshot: https://www.vulnes.is/snapshots/f
API: 3 binaries stored (0 flagged by the malware corpus)
     https://www.vulnes.is/snapshots/g
     https://www.vulnes.is/not-after-api
Snapshot: https://www.vulnes.is/snapshots/a
Snapshot: https://evil.example.com/phish
Snapshot: http://www.vulnes.is/plain
Snapshot: https://user@www.vulnes.is/x
Snapshot: https://www.vulnes.is.evil.io/x
    https://www.vulnes.is/resolve/register, then run 'vulnetix auth login'.
`
	got := ParseSnapshots(out)
	want := []Snapshot{
		{"", "https://www.vulnes.is/snapshots/a"},
		{"", "https://www.vulnes.is/snapshots/b"},
		{"SAST", "https://www.vulnes.is/snapshots/c"},
		{"Secrets", "https://www.vulnes.is/snapshots/d"},
		{"Malscan", "https://www.vulnes.is/snapshots/e"},
		{"License", "https://www.vulnes.is/snapshots/f"},
		{"Binary", "https://www.vulnes.is/snapshots/g"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}
