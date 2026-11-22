package config

import (
	"strings"
	"testing"
	"time"
)

const digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func TestExampleParses(t *testing.T) {
	c, err := Parse([]byte(`
keys: [{name: belai, sha256: ` + digest + `}]
vllm:
  model: Qwen/Qwen3.8-27B-AWQ
  quantization: awq_marlin
  dtype: float16
  gpu_memory_utilization: 0.92
  max_model_len: 4096
  max_num_seqs: 16
  enable_prefix_caching: true
  startup_timeout: 45m
nonce: {secret_file: /tmp/x}
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "0.0.0.0:8000" || c.VLLM.Port != 8001 || c.VLLM.StartupTimeout != 45*time.Minute {
		t.Fatalf("defaults: %+v", c)
	}
	if c.Nonce.DefaultMode != "auto" || c.Analytics.Driver != "sqlite" || !*c.StreamUsage {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestValidationFailsClosed(t *testing.T) {
	cases := map[string]string{
		"no keys":       `vllm: {model: m}` + "\nnonce: {secret_file: x}",
		"unknown key":   `allow_anonymous: true` + "\nbogus: 1\nvllm: {model: m}\nnonce: {secret_file: x}",
		"reserved flag": `allow_anonymous: true` + "\nvllm: {model: m, extra_args: [\"--host=0.0.0.0\"]}\nnonce: {secret_file: x}",
		"api key env":   `allow_anonymous: true` + "\nvllm: {model: m, pass_env: [VLLM_API_KEY]}\nnonce: {secret_file: x}",
		"bad mode":      `allow_anonymous: true` + "\nvllm: {model: m}\nnonce: {secret_file: x, default_mode: off}",
		"no secret":     `allow_anonymous: true` + "\nvllm: {model: m}",
		"bad digest":    "keys: [{name: a, sha256: abc}]\nvllm: {model: m}\nnonce: {secret_file: x}",
		"idle eager":    `allow_anonymous: true` + "\nvllm: {model: m, idle_stop: 1m}\nnonce: {secret_file: x}",
	}
	for name, y := range cases {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if testing.Verbose() {
			t.Logf("%s: %v", name, strings.ReplaceAll(err.Error(), "\n", "; "))
		}
	}
}
