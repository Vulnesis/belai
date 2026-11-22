package delimiters

import "strings"

// Verdict is a gateway's classification of one sealed block.
type Verdict int

const (
	// Verified means the nonce was accepted and the integrity hash, when
	// present or required, matches the content.
	Verified Verdict = iota
	// Unknown means the block has no nonce or one the checker does not accept.
	Unknown
	// Tampered means the nonce was accepted but the integrity hash does not
	// match, or a kind that requires one carries none.
	Tampered
)

// GatewayMode selects what Gateway does with each block.
type GatewayMode int

const (
	// Observe counts blocks and changes nothing.
	Observe GatewayMode = iota
	// Enforce strips unknown and tampered blocks, unmatched opening tags and
	// stray closing tags of known kinds.
	Enforce
	// Canonical is Enforce plus forwarding each verified block as
	// <kind integrity="H">, its nonce and every other attribute removed.
	Canonical
)

// GatewayReport counts what Gateway saw and did.
type GatewayReport struct {
	Verified  int
	Unknown   int
	Tampered  int
	Stripped  int
	Canonical int
}

// Add accumulates other into r.
func (r *GatewayReport) Add(o GatewayReport) {
	r.Verified += o.Verified
	r.Unknown += o.Unknown
	r.Tampered += o.Tampered
	r.Stripped += o.Stripped
	r.Canonical += o.Canonical
}

// Gateway verifies every known-kind block in text the way an AI Firewall
// does (docs/nonce-endpoint-spec.md, "Gateway verification") and, under
// Enforce or Canonical, rewrites it. It shares Egress's tag grammar, so a
// block Egress would keep is Verified here with the same checker.
func Gateway(text string, checker NonceChecker, mode GatewayMode) (string, GatewayReport) {
	var rep GatewayReport
	strip := mode == Enforce || mode == Canonical
	var b strings.Builder
	pos := 0
	stray := func(s string) string {
		if !strip {
			return s
		}
		return closeTagRe.ReplaceAllStringFunc(s, func(m string) string {
			sub := closeTagRe.FindStringSubmatch(m)
			if len(sub) == 2 && KnownKinds[sub[1]] {
				rep.Stripped++
				return ""
			}
			return m
		})
	}
	for pos < len(text) {
		loc := openTagRe.FindStringSubmatchIndex(text[pos:])
		if loc == nil {
			b.WriteString(stray(text[pos:]))
			break
		}
		openStart := pos + loc[0]
		openEnd := pos + loc[1]
		kind := text[pos+loc[2] : pos+loc[3]]
		attrs := text[pos+loc[4] : pos+loc[5]]
		b.WriteString(stray(text[pos:openStart]))

		if !KnownKinds[kind] {
			b.WriteString(text[openStart:openEnd])
			pos = openEnd
			continue
		}
		closeLoc := closeTagRes[kind].FindStringIndex(text[openEnd:])
		if closeLoc == nil {
			rep.Unknown++
			if strip {
				rep.Stripped++
			} else {
				b.WriteString(text[openStart:openEnd])
			}
			pos = openEnd
			continue
		}
		closeStart := openEnd + closeLoc[0]
		closeEnd := openEnd + closeLoc[1]
		content := text[openEnd:closeStart]

		v, integ := classify(attrs, content, checker, kind)
		switch {
		case v == Verified:
			rep.Verified++
			if mode == Canonical {
				rep.Canonical++
				if integ != "" {
					b.WriteString(`<` + kind + ` integrity="` + integ + `">`)
				} else {
					b.WriteString(`<` + kind + `>`)
				}
				b.WriteString(content)
				b.WriteString(Close(kind))
			} else {
				b.WriteString(text[openStart:closeEnd])
			}
		default:
			if v == Unknown {
				rep.Unknown++
			} else {
				rep.Tampered++
			}
			if strip {
				rep.Stripped++
			} else {
				b.WriteString(text[openStart:closeEnd])
			}
		}
		pos = closeEnd
	}
	return b.String(), rep
}

// classify is valid() with the failure split into Unknown and Tampered. It
// returns the block's integrity hash when the block carries one.
func classify(attrs, content string, checker NonceChecker, kind string) (Verdict, string) {
	parsed := parseAttrs(attrs)
	n := parsed["nonce"]
	if n == "" || checker == nil || !checker.Valid(n) {
		return Unknown, ""
	}
	integ := parsed["integrity"]
	if integ == "" {
		if kind == KindAttachment || kind == KindDirective || kind == KindDiagnostics {
			return Tampered, ""
		}
		return Verified, ""
	}
	if integ != Integrity(content) {
		return Tampered, ""
	}
	return Verified, integ
}
