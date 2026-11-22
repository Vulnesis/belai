package products

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// sensorDoc is `vulnetix-sensor status -o json` (exit 3 when the service is
// not active, with the document printed first).
type sensorDoc struct {
	Installed  bool   `json:"installed"`
	Version    string `json:"version"`
	Enrolled   bool   `json:"enrolled"`
	Profile    string `json:"profile"`
	Protection string `json:"protection"`
	Mode       string `json:"mode"`
	Service    struct {
		Active  bool `json:"active"`
		Enabled bool `json:"enabled"`
	} `json:"service"`
	Guard struct {
		Active  bool `json:"active"`
		Enabled bool `json:"enabled"`
	} `json:"guard"`
	Update *struct {
		Latest string `json:"latest"`
		Failed string `json:"failed"`
	} `json:"update"`
}

// Sensor units as the status reports them.
const (
	SensorUnit      = "vulnetix-sensor.service"
	SensorGuardUnit = "vulnetix-sensor-guard.timer"
)

// probeSensor reports the runtime sensor (Linux only): installed, enrolled,
// running, its mode and its units. Root is not needed to read any of it.
func (p *Prober) probeSensor(ctx context.Context) *nodev1.ProductStatus {
	if p.GOOS != "linux" {
		return &nodev1.ProductStatus{State: "unsupported"}
	}
	st := &nodev1.ProductStatus{State: "absent"}
	path, ok := p.lookPath("vulnetix-sensor")
	if !ok {
		return st
	}
	st.State, st.Path, st.InstallMethod = "installed", HomeRel(p.Home, path), "direct"
	var doc sensorDoc
	out, err := p.run(ctx, path, "status", "-o", "json")
	if err == nil && (out.Exit == 0 || out.Exit == 3) && looksJSONObject(out.Stdout) && json.Unmarshal(out.Stdout, &doc) == nil {
		st.Version = version(doc.Version)
		if doc.Update != nil {
			st.Latest = version(doc.Update.Latest)
		}
	} else {
		st.Degraded = append(st.Degraded, "status_json")
		doc = p.sensorText(ctx, path, st)
	}
	st.Running, st.Enabled = doc.Service.Active, doc.Service.Enabled
	st.Mode = word(doc.Mode)
	st.Units = []string{SensorUnit + ": " + unitWords(doc.Service.Active, doc.Service.Enabled)}
	if doc.Guard.Active || doc.Guard.Enabled {
		st.Units = append(st.Units, SensorGuardUnit+": "+unitWords(doc.Guard.Active, doc.Guard.Enabled))
	}
	switch {
	case doc.Service.Active:
		st.State = "active"
		st.Checks = append(st.Checks, check("service", "ok", "running"))
	case doc.Enrolled:
		st.State = "degraded"
		st.Checks = append(st.Checks, check("service", "error", "enrolled but the service is not active"))
	default:
		st.Checks = append(st.Checks, check("enroll", "warn", "not enrolled"))
	}
	return st
}

// sensorText reads the text status of a sensor without the JSON form, and
// its version.
func (p *Prober) sensorText(ctx context.Context, path string, st *nodev1.ProductStatus) sensorDoc {
	var doc sensorDoc
	if out, err := p.run(ctx, path, "--version"); err == nil && out.Exit == 0 {
		st.Version = version(firstLine(out.Stdout))
	}
	out, err := p.run(ctx, path, "status")
	if err != nil || (out.Exit != 0 && out.Exit != 3) {
		st.Degraded = append(st.Degraded, "status")
		return doc
	}
	for _, line := range strings.Split(string(out.Stdout), "\n") {
		key, val, _ := strings.Cut(strings.TrimSpace(line), " ")
		val = strings.TrimSpace(val)
		switch key {
		case "enrolled":
			doc.Enrolled = val == "true"
		case "mode":
			doc.Mode = val
		case "service":
			active, enabled, _ := strings.Cut(val, ",")
			doc.Service.Active = strings.TrimSpace(active) == "active"
			doc.Service.Enabled = strings.TrimSpace(enabled) == "enabled"
		}
	}
	return doc
}

func unitWords(active, enabled bool) string {
	a, e := "inactive", "disabled"
	if active {
		a = "active"
	}
	if enabled {
		e = "enabled"
	}
	return a + "/" + e
}
