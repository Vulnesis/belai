// Package server is the broker's HTTP front: an OpenAI-compatible API that
// authenticates clients, serves Belai's nonce endpoint, applies the nonce
// gate to request bodies and proxies to vLLM, streaming responses through as
// they arrive. Each request leaves one analytics row, handed to a
// non-blocking recorder after the response is written.
package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vulnetix/belai/internal/broker/analytics"
	"github.com/vulnetix/belai/internal/broker/config"
	"github.com/vulnetix/belai/internal/broker/noncegate"
	"github.com/vulnetix/belai/internal/broker/vllm"
)

// Upstream is what the server needs from the supervisor.
type Upstream interface {
	Ensure(ctx context.Context) error
	Upstream() string
	APIKey() string
	Touch()
	Status() vllm.Status
}

// Server is the HTTP handler.
type Server struct {
	cfg      *config.Config
	up       Upstream
	issuer   *noncegate.Issuer
	rec      *analytics.Recorder
	log      *slog.Logger
	keys     map[string]string // sha256 hex -> principal name
	client   *http.Client
	mux      *http.ServeMux
	started  time.Time
	modelTag string
}

// New wires the handler.
func New(cfg *config.Config, up Upstream, issuer *noncegate.Issuer, rec *analytics.Recorder, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{
		cfg: cfg, up: up, issuer: issuer, rec: rec, log: log,
		keys:    map[string]string{},
		started: time.Now(),
		client: &http.Client{
			// Loopback traffic must never go through HTTP(S)_PROXY, and a
			// redirect from the model server is never followed.
			Transport: &http.Transport{
				Proxy:               nil,
				MaxIdleConns:        256,
				MaxIdleConnsPerHost: 256,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		modelTag: cfg.VLLM.ServedName(),
	}
	for _, k := range cfg.Keys {
		s.keys[strings.ToLower(k.SHA256)] = k.Name
	}
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", s.healthz)
	m.HandleFunc("GET /readyz", s.readyz)
	m.HandleFunc("GET /v1/nonces", s.auth(s.nonces))
	m.HandleFunc("GET /v1/models", s.auth(s.proxy("models", false)))
	m.HandleFunc("POST /v1/chat/completions", s.auth(s.proxy("chat", true)))
	m.HandleFunc("POST /v1/completions", s.auth(s.proxy("completions", true)))
	m.HandleFunc("POST /v1/responses", s.auth(s.proxy("responses", true)))
	m.HandleFunc("POST /v1/embeddings", s.auth(s.proxy("embeddings", true)))
	m.HandleFunc("GET /broker/stats", s.auth(s.stats))
	s.mux = m
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

type principalKey struct{}

func principalOf(r *http.Request) string {
	p, _ := r.Context().Value(principalKey{}).(string)
	return p
}

// HashKey is the digest stored in the config for a client key.
func HashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func bearer(r *http.Request) string {
	if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return strings.TrimSpace(r.Header.Get("X-Api-Key"))
}

// auth resolves the principal. The presented key is hashed before lookup,
// so the map lookup's timing depends on the digest, not on the key.
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := bearer(r)
		var name string
		if key != "" {
			name = s.keys[HashKey(key)]
		}
		if name == "" {
			if !s.cfg.AllowAnonymous || key != "" {
				writeError(w, http.StatusUnauthorized, "invalid_api_key", "missing or unknown API key")
				return
			}
			name = "anonymous"
		}
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, name)))
	}
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok\n"))
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	st := s.up.Status()
	if st.State != vllm.StateReady {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	writeJSON(w, map[string]any{"state": st.State})
}

func (s *Server) nonces(w http.ResponseWriter, r *http.Request) {
	n := noncegate.DefaultCount
	if v := r.URL.Query().Get("count"); v != "" {
		if c, err := strconv.Atoi(v); err == nil && c >= 1 {
			n = min(c, noncegate.MaxCount)
		}
	}
	ns, exp, err := s.issuer.Issue(principalOf(r), n)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "nonce_error", "could not mint nonces")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{
		"nonces":     ns,
		"count":      len(ns),
		"expires_at": exp.Format(time.RFC3339),
		"modes":      noncegate.Modes,
	})
	s.rec.Record(analytics.Record{
		Time: time.Now(), RequestID: newID(), Principal: principalOf(r), Route: "nonces", Status: 200,
	})
}

func (s *Server) stats(w http.ResponseWriter, _ *http.Request) {
	written, dropped, failed := s.rec.Stats()
	writeJSON(w, map[string]any{
		"model":          s.modelTag,
		"model_server":   s.up.Status(),
		"uptime_seconds": int(time.Since(s.started).Seconds()),
		"analytics":      map[string]uint64{"written": written, "dropped": dropped, "failed": failed},
		"nonce_default":  s.cfg.Nonce.DefaultMode,
	})
}

func newID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "req_" + hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes an OpenAI-shaped error so SDKs surface it normally.
func writeError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"message": msg, "type": "broker_error", "code": code},
	})
}
