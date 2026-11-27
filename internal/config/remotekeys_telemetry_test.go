package config

import (
	"strings"
	"testing"
)

// A Keleustes console sets OpenTelemetry export per node (docs/telemetry.md
// "Set from Keleustes"): the endpoint is a collector URL with nothing that
// could carry a credential, the signals are booleans, and a header names a
// host environment variable; a secret value never goes through a console,
// and a literal the host's owner wrote is never shown.
func TestRemoteTelemetryKeys(t *testing.T) {
	var s Settings
	set := func(k, v string) error { _, _, err := ApplyRemote(&s, k, v, false); return err }
	if err := set("telemetry.otlp_endpoint", "https://otel.example.com:4318/"); err != nil {
		t.Fatal(err)
	}
	if s.Telemetry == nil || s.Telemetry.OTLPEndpoint != "https://otel.example.com:4318" {
		t.Fatalf("endpoint = %+v", s.Telemetry)
	}
	for _, bad := range []string{"ftp://x", "https://u:p@x.example", "https://x.example/?k=v", "https://x.example/#f", "x.example"} {
		if err := set("telemetry.otlp_endpoint", bad); err == nil {
			t.Errorf("endpoint %q accepted", bad)
		}
	}
	if err := set("telemetry.traces", "false"); err != nil || *s.Telemetry.Traces {
		t.Fatalf("traces: %v", err)
	}
	if v, _ := RemoteValue(s, "telemetry.metrics"); v != "true" {
		t.Errorf("metrics default = %q", v)
	}
	if err := set("telemetry.headers.x-api-key", "env:OTEL_API_KEY"); err != nil || s.Telemetry.Headers["x-api-key"] != "env:OTEL_API_KEY" {
		t.Fatalf("header: %v %+v", err, s.Telemetry.Headers)
	}
	if err := set("telemetry.headers.x-api-key", "sk-live-123"); err == nil || !strings.Contains(err.Error(), "env:NAME") {
		t.Errorf("a literal header value: %v", err)
	}
	if err := set("telemetry.headers.bad name", "env:A"); err == nil {
		t.Error("a bad header name was accepted")
	}
	s.Telemetry.Headers["authorization"] = "Bearer secret"
	if v, _ := RemoteValue(s, "telemetry.headers.authorization"); strings.Contains(v, "secret") {
		t.Errorf("a host literal leaked: %q", v)
	}
	if err := set("telemetry.headers.x-api-key", ""); err != nil || s.Telemetry.Headers["x-api-key"] != "" {
		t.Fatalf("remove header: %v", err)
	}
	if err := set("telemetry.otlp_endpoint", ""); err != nil || s.Telemetry.OTLPEndpoint != "" {
		t.Fatalf("clear endpoint: %v", err)
	}
	if err := ValidateSettings(s); err != nil {
		t.Fatal(err)
	}
	if _, ok := LookupRemoteKey("telemetry.sampler"); ok {
		t.Error("an unknown telemetry key is in the table")
	}
}
