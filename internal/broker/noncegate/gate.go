package noncegate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vulnetix/belai/internal/delimiters"
)

// HeaderMode is the request header a client sends to choose a mode, and
// HeaderReport the response header that reports the result. They are the
// names Belai already sends to and reads from the Vulnetix AI Firewall
// (internal/firewall), so a Belai session shows the same card here.
const (
	HeaderMode   = "X-Vulnetix-Nonce-Mode"
	HeaderReport = "X-Vulnetix-Firewall-Nonce"
)

// Mode names. Auto is a broker default only, never a header value.
const (
	ModeObserve   = "observe"
	ModeEnforce   = "enforce"
	ModeCanonical = "canonical"
	ModeAuto      = "auto"
)

// ValidDefault reports whether m may be the broker's default mode.
func ValidDefault(m string) bool {
	switch m {
	case ModeObserve, ModeEnforce, ModeCanonical, ModeAuto:
		return true
	}
	return false
}

// Result is what Gate did to one request body.
type Result struct {
	Mode   string
	Report delimiters.GatewayReport
	// Body is the body to forward: the original bytes unless a block was
	// stripped or rewritten.
	Body []byte
	// Sealed reports whether the body held any known-kind tag at all.
	Sealed bool
}

// Header renders the X-Vulnetix-Firewall-Nonce value.
func (r Result) Header() string {
	h := fmt.Sprintf("mode=%s;verified=%d;unknown=%d;tampered=%d;stripped=%d",
		r.Mode, r.Report.Verified, r.Report.Unknown, r.Report.Tampered, r.Report.Stripped)
	if r.Mode == ModeCanonical {
		h += fmt.Sprintf(";canonical=%d", r.Report.Canonical)
	}
	return h
}

// escapedLT is "<" as a JSON escape; Go encoders write it that way by default.
var escapedLT = []byte{0x5c, 'u', '0', '0', '3', 'c'}

// promptKeys are the top-level request fields that carry conversation text.
// Everything else (tools, response_format, sampling knobs) passes unchanged.
var promptKeys = []string{"messages", "prompt", "input", "instructions"}

// Gate applies the gateway rules to an OpenAI-style JSON body. headerMode is
// the client's X-Vulnetix-Nonce-Mode (empty when absent); defaultMode is the
// broker's configured default. An unrecognised header value is observe, as
// the spec requires of a gateway that does not know a mode.
//
// Auto, the default, canonicalises a request only when every block in it
// verified and observes otherwise. That gives the prefix cache identical
// bytes for Belai sessions seeded here without ever stripping a block from a
// client that minted its own nonces.
func Gate(body []byte, checker func(string) bool, headerMode, defaultMode string) (Result, error) {
	mode := strings.ToLower(strings.TrimSpace(headerMode))
	switch mode {
	case ModeObserve, ModeEnforce, ModeCanonical:
	case "":
		mode = defaultMode
	default:
		mode = ModeObserve
	}
	res := Result{Mode: mode, Body: body}
	if !bytes.Contains(body, []byte("<")) && !bytes.Contains(body, escapedLT) {
		if mode == ModeAuto {
			res.Mode = ModeObserve
		}
		return res, nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return res, fmt.Errorf("request body is not a JSON object: %w", err)
	}
	chk := delimiters.CheckerFunc(checker)

	walk := func(gm delimiters.GatewayMode) (delimiters.GatewayReport, bool) {
		var rep delimiters.GatewayReport
		changed := false
		for _, k := range promptKeys {
			v, ok := doc[k]
			if !ok {
				continue
			}
			nv := rewrite(v, func(s string) string {
				if !strings.Contains(s, "<") {
					return s
				}
				out, r := delimiters.Gateway(s, chk, gm)
				rep.Add(r)
				if out != s {
					changed = true
				}
				return out
			})
			if gm != delimiters.Observe {
				doc[k] = nv
			}
		}
		return rep, changed
	}

	if mode == ModeAuto {
		rep, _ := walk(delimiters.Observe)
		if rep.Verified == 0 || rep.Unknown > 0 || rep.Tampered > 0 {
			res.Mode = ModeObserve
			res.Report = rep
			res.Sealed = rep.Verified+rep.Unknown+rep.Tampered > 0
			return res, nil
		}
		mode = ModeCanonical
		res.Mode = mode
	}
	gm := map[string]delimiters.GatewayMode{
		ModeObserve: delimiters.Observe, ModeEnforce: delimiters.Enforce, ModeCanonical: delimiters.Canonical,
	}[mode]
	rep, changed := walk(gm)
	res.Report = rep
	res.Sealed = rep.Verified+rep.Unknown+rep.Tampered+rep.Stripped > 0
	if !changed {
		return res, nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return res, err
	}
	res.Body = bytes.TrimRight(buf.Bytes(), "\n")
	return res, nil
}

// rewrite applies f to every string in v, recursively.
func rewrite(v any, f func(string) string) any {
	switch t := v.(type) {
	case string:
		return f(t)
	case []any:
		for i := range t {
			t[i] = rewrite(t[i], f)
		}
		return t
	case map[string]any:
		for k, x := range t {
			t[k] = rewrite(x, f)
		}
		return t
	}
	return v
}
