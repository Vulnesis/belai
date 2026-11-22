// Package config loads and validates the broker's YAML configuration. The
// file is the operator's: it names the model, the vLLM flags, the client keys
// (as SHA-256 digests, never the keys) and the analytics database. Validation
// is strict (unknown keys are refused) and fails closed: no keys and no
// explicit allow_anonymous is an error, and the flags that would move vLLM off
// loopback or change its credential are refused in extra_args.
package config

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/vulnetix/belai/internal/broker/analytics"
	"github.com/vulnetix/belai/internal/broker/noncegate"
)

// Key is one client credential.
type Key struct {
	Name   string `yaml:"name"`
	SHA256 string `yaml:"sha256"`
}

// TLS enables HTTPS on the listener.
type TLS struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// VLLM describes the managed server.
type VLLM struct {
	// ExternalURL, when set, proxies to a vLLM the broker does not start.
	ExternalURL string `yaml:"external_url"`
	// ExternalKeyEnv names an environment variable holding that server's key.
	ExternalKeyEnv string `yaml:"external_key_env"`

	Binary               string   `yaml:"binary"`
	Model                string   `yaml:"model"`
	ServedModelName      string   `yaml:"served_model_name"`
	Quantization         string   `yaml:"quantization"`
	DType                string   `yaml:"dtype"`
	GPUMemoryUtilization float64  `yaml:"gpu_memory_utilization"`
	MaxModelLen          int      `yaml:"max_model_len"`
	MaxNumSeqs           int      `yaml:"max_num_seqs"`
	EnablePrefixCaching  bool     `yaml:"enable_prefix_caching"`
	Port                 int      `yaml:"port"`
	ExtraArgs            []string `yaml:"extra_args"`
	PassEnv              []string `yaml:"pass_env"`

	// Start is "eager" (launch at boot) or "on_demand" (first request).
	Start          string        `yaml:"start"`
	IdleStop       time.Duration `yaml:"idle_stop"`
	StartupTimeout time.Duration `yaml:"startup_timeout"`
	StopGrace      time.Duration `yaml:"stop_grace"`
	RestartBackoff time.Duration `yaml:"restart_backoff"`
	MaxBackoff     time.Duration `yaml:"max_backoff"`
	HealthInterval time.Duration `yaml:"health_interval"`
}

// Nonce configures the nonce protocol.
type Nonce struct {
	SecretFile  string        `yaml:"secret_file"`
	SecretEnv   string        `yaml:"secret_env"`
	TTL         time.Duration `yaml:"ttl"`
	DefaultMode string        `yaml:"default_mode"`
}

// Analytics configures the request log.
type Analytics struct {
	Driver        string        `yaml:"driver"`
	DSN           string        `yaml:"dsn"`
	DSNEnv        string        `yaml:"dsn_env"`
	Buffer        int           `yaml:"buffer"`
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`
}

// Config is the whole file.
type Config struct {
	Listen         string        `yaml:"listen"`
	TLS            *TLS          `yaml:"tls"`
	Keys           []Key         `yaml:"keys"`
	AllowAnonymous bool          `yaml:"allow_anonymous"`
	MaxBodyBytes   int64         `yaml:"max_body_bytes"`
	ReadyWait      time.Duration `yaml:"ready_wait"`
	StreamUsage    *bool         `yaml:"stream_usage"`
	VLLM           VLLM          `yaml:"vllm"`
	Nonce          Nonce         `yaml:"nonce"`
	Analytics      Analytics     `yaml:"analytics"`
}

// Load reads, defaults and validates path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes b strictly, applies defaults and validates.
func Parse(b []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("broker config: %w", err)
	}
	c.defaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) defaults() {
	def := func(s *string, v string) {
		if *s == "" {
			*s = v
		}
	}
	defd := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&c.Listen, "0.0.0.0:8000")
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 16 << 20
	}
	defd(&c.ReadyWait, 10*time.Minute)
	if c.StreamUsage == nil {
		t := true
		c.StreamUsage = &t
	}
	v := &c.VLLM
	def(&v.Binary, "vllm")
	def(&v.Start, "eager")
	if v.Port == 0 {
		v.Port = 8001
	}
	defd(&v.StartupTimeout, 30*time.Minute)
	defd(&v.StopGrace, 30*time.Second)
	defd(&v.RestartBackoff, 5*time.Second)
	defd(&v.MaxBackoff, 2*time.Minute)
	defd(&v.HealthInterval, 5*time.Second)
	defd(&c.Nonce.TTL, noncegate.DefaultTTL)
	def(&c.Nonce.DefaultMode, noncegate.ModeAuto)
	def(&c.Analytics.Driver, analytics.DriverSQLite)
	if c.Analytics.Driver == analytics.DriverSQLite {
		def(&c.Analytics.DSN, "belai-broker.db")
	}
}

var (
	keyNameRe   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	modelRe     = regexp.MustCompile(`^[A-Za-z0-9._/:-]{1,200}$`)
	wordRe      = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	envNameRe   = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	reservedArg = []string{"--host", "--port", "--api-key", "--served-model-name", "--model"}
)

// Validate checks every field. It is called by Parse.
func (c *Config) Validate() error {
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }

	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		bad("listen: %v", err)
	}
	if c.TLS != nil && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		bad("tls: cert_file and key_file are both required")
	}
	if len(c.Keys) == 0 && !c.AllowAnonymous {
		bad("keys: at least one key is required (or set allow_anonymous: true)")
	}
	seen := map[string]bool{}
	for i, k := range c.Keys {
		if !keyNameRe.MatchString(k.Name) {
			bad("keys[%d].name: must match %s", i, keyNameRe)
		}
		if b, err := hex.DecodeString(k.SHA256); err != nil || len(b) != 32 {
			bad("keys[%d].sha256: must be 64 hex characters (run belai-broker hash-key)", i)
		}
		if seen[strings.ToLower(k.SHA256)] {
			bad("keys[%d]: duplicate digest", i)
		}
		seen[strings.ToLower(k.SHA256)] = true
	}

	v := c.VLLM
	if v.ExternalURL != "" {
		if !strings.HasPrefix(v.ExternalURL, "http://") && !strings.HasPrefix(v.ExternalURL, "https://") {
			bad("vllm.external_url: must be http or https")
		}
		if v.ExternalKeyEnv != "" && !envNameRe.MatchString(v.ExternalKeyEnv) {
			bad("vllm.external_key_env: not an environment variable name")
		}
	} else {
		if !modelRe.MatchString(v.Model) {
			bad("vllm.model: required, plain model id or path")
		}
		if v.ServedModelName != "" && !modelRe.MatchString(v.ServedModelName) {
			bad("vllm.served_model_name: plain identifier")
		}
		for name, s := range map[string]string{"quantization": v.Quantization, "dtype": v.DType} {
			if s != "" && !wordRe.MatchString(s) {
				bad("vllm.%s: plain word", name)
			}
		}
		if v.GPUMemoryUtilization < 0 || v.GPUMemoryUtilization > 1 {
			bad("vllm.gpu_memory_utilization: between 0 and 1")
		}
		if v.MaxModelLen < 0 || v.MaxNumSeqs < 0 {
			bad("vllm.max_model_len and max_num_seqs: not negative")
		}
		if v.Port < 1 || v.Port > 65535 {
			bad("vllm.port: 1-65535")
		}
		if v.Start != "eager" && v.Start != "on_demand" {
			bad("vllm.start: eager or on_demand")
		}
		if v.IdleStop > 0 && v.Start != "on_demand" {
			bad("vllm.idle_stop: only with start: on_demand")
		}
		for i, a := range v.ExtraArgs {
			if a == "" || strings.IndexFunc(a, unicode.IsControl) >= 0 {
				bad("vllm.extra_args[%d]: empty or holds a control character", i)
			}
			flag, _, _ := strings.Cut(a, "=")
			for _, r := range reservedArg {
				if flag == r {
					bad("vllm.extra_args[%d]: %s is set by the broker", i, r)
				}
			}
		}
		for i, e := range v.PassEnv {
			if !envNameRe.MatchString(e) || e == "VLLM_API_KEY" {
				bad("vllm.pass_env[%d]: %q is not allowed", i, e)
			}
		}
	}

	if !noncegate.ValidDefault(c.Nonce.DefaultMode) {
		bad("nonce.default_mode: observe, enforce, canonical or auto")
	}
	if c.Nonce.SecretFile == "" && c.Nonce.SecretEnv == "" {
		bad("nonce: secret_file or secret_env is required")
	}
	if c.Nonce.SecretEnv != "" && !envNameRe.MatchString(c.Nonce.SecretEnv) {
		bad("nonce.secret_env: not an environment variable name")
	}

	switch c.Analytics.Driver {
	case analytics.DriverSQLite, analytics.DriverPostgres:
		if c.Analytics.DSN == "" && c.Analytics.DSNEnv == "" {
			bad("analytics: dsn or dsn_env is required")
		}
	case analytics.DriverNone:
	default:
		bad("analytics.driver: sqlite, postgres or none")
	}
	if c.Analytics.DSNEnv != "" && !envNameRe.MatchString(c.Analytics.DSNEnv) {
		bad("analytics.dsn_env: not an environment variable name")
	}
	return errors.Join(errs...)
}

// AnalyticsDSN resolves the DSN, preferring the environment variable so a
// Postgres password need not sit in the file.
func (c *Config) AnalyticsDSN() string {
	if c.Analytics.DSNEnv != "" {
		if v := os.Getenv(c.Analytics.DSNEnv); v != "" {
			return v
		}
	}
	return c.Analytics.DSN
}

// ServedName is the model id clients see in /v1/models.
func (v VLLM) ServedName() string {
	if v.ServedModelName != "" {
		return v.ServedModelName
	}
	return v.Model
}
