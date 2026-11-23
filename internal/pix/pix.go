// Package pix holds the mascot drawing that a generated agent avatar is a
// variant of. The drawing is the website's owl without its animation, so every
// element in it is one the SVG guard (internal/svgguard) admits, and a model is
// shown exactly the picture it may change.
//
// Vulnetix's owl is Pix; Vulnesis's is Strix (see Drawing, Name and
// TemplateVersionFor). The brand is chosen at run time like every other
// brand-dependent value (internal/brand), so a released binary draws Pix unless
// the user opts into Vulnesis.
package pix

import (
	_ "embed"

	"github.com/vulnetix/belai/internal/brand"
)

// SVG is the static Pix drawing, 320 by 320 units in the viewBox 96 26 320 320.
//
//go:embed pix.svg
var SVG []byte

// StrixSVG is the static Strix drawing, the same 320 by 320 viewBox and the
// same element ids as SVG.
//
//go:embed strix.svg
var StrixSVG []byte

// TemplateVersion names the Pix drawing. It is sent with an avatar request so
// the website can tell a variant of an older Pix from one of the current drawing.
const TemplateVersion = "1"

// StrixTemplateVersion names the Strix drawing.
const StrixTemplateVersion = "s1"

// Drawing is the owl the current brand draws.
func Drawing() []byte {
	if brand.Current() == brand.Vulnesis {
		return StrixSVG
	}
	return SVG
}

// Name is the owl's name under the current brand.
func Name() string {
	if brand.Current() == brand.Vulnesis {
		return "Strix"
	}
	return "Pix"
}

// MakerName is the name of the brand that owns the owl.
func MakerName() string {
	if brand.Current() == brand.Vulnesis {
		return "Vulnesis"
	}
	return "Vulnetix"
}

// TemplateVersionFor is the template version to send with an avatar request.
func TemplateVersionFor() string {
	if brand.Current() == brand.Vulnesis {
		return StrixTemplateVersion
	}
	return TemplateVersion
}
