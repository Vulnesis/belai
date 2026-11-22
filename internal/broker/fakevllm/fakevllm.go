// Package fakevllm is a stand-in for vLLM's OpenAI-compatible server, for
// the broker's tests. It checks the bearer key the broker must send, echoes
// the system message it received so a test can see what reached upstream,
// and reports fixed usage numbers. MaybeRun turns a test binary into the
// fake so the supervisor can launch it as a real process.
package fakevllm

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
)

// EnvRun selects the fake in a test binary's TestMain.
const EnvRun = "BELAI_BROKER_FAKE_VLLM"

// Usage the fake reports on every completion.
const (
	PromptTokens     = 7
	CompletionTokens = 3
	CachedTokens     = 5
)

// Handler serves /health, /v1/models and /v1/chat/completions.
func Handler(apiKey string) http.Handler {
	m := http.NewServeMux()
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if apiKey != "" && r.Header.Get("Authorization") != "Bearer "+apiKey {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			h(w, r)
		}
	}
	m.HandleFunc("GET /health", authed(func(w http.ResponseWriter, _ *http.Request) {}))
	m.HandleFunc("GET /v1/models", authed(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"object": "list", "data": []any{map[string]any{"id": "fake", "object": "model"}}})
	}))
	m.HandleFunc("POST /v1/chat/completions", authed(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Stream        bool `json:"stream"`
			StreamOptions *struct {
				IncludeUsage bool `json:"include_usage"`
			} `json:"stream_options"`
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		echo := ""
		if len(req.Messages) > 0 {
			echo = req.Messages[0].Content
		}
		u := map[string]any{
			"prompt_tokens": PromptTokens, "completion_tokens": CompletionTokens,
			"total_tokens": PromptTokens + CompletionTokens, "prompt_tokens_details": map[string]any{"cached_tokens": CachedTokens},
		}
		if !req.Stream {
			json.NewEncoder(w).Encode(map[string]any{
				"id": "c1", "object": "chat.completion",
				"choices": []any{map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": echo}}},
				"usage":   u,
			})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		send := func(v any) {
			b, _ := json.Marshal(v)
			fmt.Fprintf(w, "data: %s\n\n", b)
			if fl != nil {
				fl.Flush()
			}
		}
		send(map[string]any{"id": "c1", "choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": echo}}}})
		if req.StreamOptions != nil && req.StreamOptions.IncludeUsage {
			send(map[string]any{"id": "c1", "choices": []any{}, "usage": u})
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	return m
}

// MaybeRun serves the fake on the --port in os.Args and never returns, when
// EnvRun is set. It reads the key from VLLM_API_KEY as vLLM does.
func MaybeRun() {
	if os.Getenv(EnvRun) != "1" {
		return
	}
	port := 0
	for i, a := range os.Args {
		if a == "--port" && i+1 < len(os.Args) {
			port, _ = strconv.Atoi(os.Args[i+1])
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("fake vllm listening")
	_ = http.Serve(ln, Handler(os.Getenv("VLLM_API_KEY")))
	os.Exit(0)
}
