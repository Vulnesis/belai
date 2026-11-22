package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/vulnetix/belai/internal/broker/analytics"
	"github.com/vulnetix/belai/internal/broker/noncegate"
)

// captureLimit bounds how much of a non-streamed response is kept to read
// its usage block. The client still receives every byte.
const captureLimit = 1 << 20

// requestFacts is the little the broker reads from a request body.
type requestFacts struct {
	Model         string          `json:"model"`
	Stream        bool            `json:"stream"`
	StreamOptions json.RawMessage `json:"stream_options"`
}

type usage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	InputTokens      int64 `json:"input_tokens"`
	OutputTokens     int64 `json:"output_tokens"`
	PromptDetails    *struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
	InputDetails *struct {
		CachedTokens int64 `json:"cached_tokens"`
	} `json:"input_tokens_details"`
}

func (u usage) apply(rec *analytics.Record) {
	rec.PromptTok = u.PromptTokens + u.InputTokens
	rec.ComplTok = u.CompletionTokens + u.OutputTokens
	if u.PromptDetails != nil {
		rec.CachedTok = u.PromptDetails.CachedTokens
	}
	if u.InputDetails != nil {
		rec.CachedTok = u.InputDetails.CachedTokens
	}
}

// usageEnvelope matches both a chat/completions body or chunk ({"usage":…})
// and a Responses API event ({"response":{"usage":…}}).
type usageEnvelope struct {
	Usage    *usage          `json:"usage"`
	Choices  json.RawMessage `json:"choices"`
	Response *struct {
		Usage *usage `json:"usage"`
	} `json:"response"`
}

func (e usageEnvelope) get() *usage {
	if e.Usage != nil {
		return e.Usage
	}
	if e.Response != nil {
		return e.Response.Usage
	}
	return nil
}

// injectUsage adds "stream_options":{"include_usage":true} to a JSON object
// that has no stream_options key, by splicing after the opening brace. The
// caller has already decoded the body, so it is a valid object.
func injectUsage(body []byte) []byte {
	i := bytes.IndexByte(body, '{')
	if i < 0 {
		return body
	}
	rest := bytes.TrimLeft(body[i+1:], " \t\r\n")
	sep := ","
	if len(rest) > 0 && rest[0] == '}' {
		sep = ""
	}
	out := make([]byte, 0, len(body)+40)
	out = append(out, body[:i+1]...)
	out = append(out, `"stream_options":{"include_usage":true}`...)
	out = append(out, sep...)
	return append(out, body[i+1:]...)
}

// hopHeaders are never copied between the client and upstream connections.
var hopHeaders = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true, "Proxy-Authorization": true,
	"Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true, "Content-Length": true,
}

func (s *Server) proxy(route string, gated bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := newID()
		w.Header().Set("X-Request-Id", id)
		rec := analytics.Record{Time: start, RequestID: id, Principal: principalOf(r), Route: route, Model: s.modelTag}
		defer func() {
			rec.LatencyMS = time.Since(start).Milliseconds()
			s.rec.Record(rec)
		}()

		var body []byte
		injected := false
		if r.Method == http.MethodPost {
			b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes))
			if err != nil {
				rec.Status, rec.ErrorClass = http.StatusRequestEntityTooLarge, "body_too_large"
				writeError(w, rec.Status, "body_too_large", "request body is too large")
				return
			}
			rec.ReqBytes = int64(len(b))
			var facts requestFacts
			if err := json.Unmarshal(b, &facts); err != nil {
				rec.Status, rec.ErrorClass = http.StatusBadRequest, "bad_json"
				writeError(w, rec.Status, "invalid_request", "request body is not valid JSON")
				return
			}
			if facts.Model != "" {
				rec.Model = facts.Model
			}
			rec.Stream = facts.Stream
			if gated {
				res, err := noncegate.Gate(b, s.issuer.Checker(rec.Principal), r.Header.Get(noncegate.HeaderMode), s.cfg.Nonce.DefaultMode)
				if err != nil {
					rec.Status, rec.ErrorClass = http.StatusBadRequest, "bad_json"
					writeError(w, rec.Status, "invalid_request", "request body is not a JSON object")
					return
				}
				b = res.Body
				rec.NonceMode = res.Mode
				rec.Verified, rec.Unknown, rec.Tampered = res.Report.Verified, res.Report.Unknown, res.Report.Tampered
				rec.Stripped, rec.Canonical = res.Report.Stripped, res.Report.Canonical
				w.Header().Set(noncegate.HeaderReport, res.Header())
			}
			if facts.Stream && *s.cfg.StreamUsage && len(facts.StreamOptions) == 0 && (route == "chat" || route == "completions") {
				b = injectUsage(b)
				injected = true
			}
			body = b
		}

		qStart := time.Now()
		waitCtx, cancel := context.WithTimeout(r.Context(), s.cfg.ReadyWait)
		err := s.up.Ensure(waitCtx)
		cancel()
		rec.QueueMS = time.Since(qStart).Milliseconds()
		if err != nil {
			rec.Status, rec.ErrorClass = http.StatusServiceUnavailable, "not_ready"
			w.Header().Set("Retry-After", "30")
			writeError(w, rec.Status, "model_not_ready", "the model server is starting; retry shortly")
			return
		}

		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		up, err := http.NewRequestWithContext(r.Context(), r.Method, s.up.Upstream()+r.URL.Path, rd)
		if err != nil {
			rec.Status, rec.ErrorClass = http.StatusInternalServerError, "internal"
			writeError(w, rec.Status, "internal", "could not build upstream request")
			return
		}
		up.URL.RawQuery = r.URL.RawQuery
		if body != nil {
			up.Header.Set("Content-Type", "application/json")
		}
		if a := r.Header.Get("Accept"); a != "" {
			up.Header.Set("Accept", a)
		}
		if k := s.up.APIKey(); k != "" {
			up.Header.Set("Authorization", "Bearer "+k)
		}
		up.Header.Set("X-Request-Id", id)

		resp, err := s.client.Do(up)
		if err != nil {
			if errors.Is(r.Context().Err(), context.Canceled) {
				rec.Status, rec.ErrorClass = 499, "client_closed"
				return
			}
			rec.Status, rec.ErrorClass = http.StatusBadGateway, "upstream_error"
			writeError(w, rec.Status, "upstream_error", "the model server did not answer")
			return
		}
		defer resp.Body.Close()
		rec.TTFBMS = time.Since(start).Milliseconds()
		rec.Status = resp.StatusCode
		if resp.StatusCode >= 400 {
			rec.ErrorClass = "upstream_" + strconv.Itoa(resp.StatusCode)
		}
		s.up.Touch()
		for k, vs := range resp.Header {
			if hopHeaders[http.CanonicalHeaderKey(k)] || k == "X-Request-Id" {
				continue
			}
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		if rec.Stream && resp.StatusCode == http.StatusOK {
			n, u := streamSSE(w, resp.Body, injected)
			rec.RespBytes = n
			if u != nil {
				u.apply(&rec)
			}
			if r.Context().Err() != nil {
				rec.ErrorClass = "client_closed"
			}
			return
		}
		capture := &limitedBuffer{max: captureLimit}
		n, _ := io.Copy(w, io.TeeReader(resp.Body, capture))
		rec.RespBytes = n
		if !capture.overflow {
			var env usageEnvelope
			if json.Unmarshal(capture.buf.Bytes(), &env) == nil {
				if u := env.get(); u != nil {
					u.apply(&rec)
				}
			}
		}
	}
}

// streamSSE copies an event stream to w one event at a time, flushing after
// each, and returns the bytes written and the last usage block seen. When the
// broker injected include_usage, the usage-only chunk (empty choices) is not
// forwarded, so the client receives exactly the stream it asked for.
func streamSSE(w http.ResponseWriter, body io.Reader, injected bool) (int64, *usage) {
	rc := http.NewResponseController(w)
	br := bufio.NewReaderSize(body, 64*1024)
	var event bytes.Buffer
	var written int64
	var last *usage
	usageKey := []byte(`"usage"`)
	emit := func() bool {
		if event.Len() == 0 {
			return true
		}
		drop := false
		for _, line := range bytes.Split(event.Bytes(), []byte("\n")) {
			data, ok := bytes.CutPrefix(line, []byte("data:"))
			if !ok || !bytes.Contains(data, usageKey) {
				continue
			}
			var env usageEnvelope
			if json.Unmarshal(bytes.TrimSpace(data), &env) != nil {
				continue
			}
			if u := env.get(); u != nil {
				last = u
				if injected && env.Usage != nil && isEmptyArray(env.Choices) {
					drop = true
				}
			}
		}
		if !drop {
			n, err := w.Write(event.Bytes())
			written += int64(n)
			if err != nil {
				return false
			}
			_ = rc.Flush()
		}
		event.Reset()
		return true
	}
	for {
		line, err := br.ReadBytes('\n')
		event.Write(line)
		if len(bytes.TrimRight(line, "\r\n")) == 0 && len(line) > 0 {
			if !emit() {
				return written, last
			}
		}
		if err != nil {
			emit()
			return written, last
		}
	}
}

func isEmptyArray(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) >= 2 && t[0] == '[' && len(bytes.TrimSpace(t[1:len(t)-1])) == 0
}

type limitedBuffer struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if !l.overflow {
		if l.buf.Len()+len(p) > l.max {
			l.overflow = true
			l.buf.Reset()
		} else {
			l.buf.Write(p)
		}
	}
	return len(p), nil
}
