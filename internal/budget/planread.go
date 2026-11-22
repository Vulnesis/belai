package budget

import (
	"encoding/json"
	"os"
	"time"
)

// maxLedgerRead bounds the ledger a read-only reader loads.
const maxLedgerRead = 64 << 20

// ReadLimits reads the latest plan-limit reading per provider and window
// from the ledger at path, read only: no recorder, no flusher, and a file
// that does not decode gives nothing (Open, not this, moves a corrupt ledger
// aside). A reading that fails Valid at now, or whose window has reset, is
// left out. It is what `belai rc` reports to Keleustes in HostStatus.
func ReadLimits(path string, now time.Time) []PlanLimit {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxLedgerRead {
		return nil
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var data struct {
		Limits map[string]PlanLimit `json:"limits"`
	}
	if json.Unmarshal(buf, &data) != nil {
		return nil
	}
	out := make([]PlanLimit, 0, len(data.Limits))
	for _, l := range data.Limits {
		if !l.Valid(now) || l.Reset.Before(now) {
			continue
		}
		out = append(out, l)
	}
	sortLimits(out)
	return out
}
