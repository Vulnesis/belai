package pix

import (
	"bytes"
	"os"
	"testing"

	"github.com/vulnetix/belai/internal/brand"
	"github.com/vulnetix/belai/internal/svgguard"
)

// The drawing a model is shown must itself be admitted, or every variant of it
// would be refused.
func TestTemplateIsAdmitted(t *testing.T) {
	out, err := svgguard.Sanitize(SVG)
	if err != nil {
		t.Fatalf("the Pix template is not admitted: %v", err)
	}
	if len(out) == 0 || len(out) > svgguard.MaxBytes {
		t.Fatalf("admitted template is %d bytes", len(out))
	}
}

// The guard's own corpus holds a copy of the template; the two must not drift.
func TestTemplateMatchesTheGuardCorpus(t *testing.T) {
	want, err := os.ReadFile("../svgguard/testdata/pix.svg")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(SVG, want) {
		t.Fatal("internal/pix/pix.svg and internal/svgguard/testdata/pix.svg differ; copy one over the other")
	}
}

// Vulnesis draws Strix, which must pass the same guard and stay in step with
// the guard's corpus. Vulnetix keeps Pix.
func TestStrixTemplateIsAdmittedAndMatchesTheCorpus(t *testing.T) {
	out, err := svgguard.Sanitize(StrixSVG)
	if err != nil {
		t.Fatalf("the Strix template is not admitted: %v", err)
	}
	if len(out) == 0 || len(out) > svgguard.MaxBytes {
		t.Fatalf("admitted template is %d bytes", len(out))
	}
	want, err := os.ReadFile("../svgguard/testdata/strix.svg")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(StrixSVG, want) {
		t.Fatal("internal/pix/strix.svg and internal/svgguard/testdata/strix.svg differ; copy one over the other")
	}
}

func TestTheBrandChoosesTheOwl(t *testing.T) {
	prev := brand.Current()
	t.Cleanup(func() { brand.Set(prev) })

	brand.Set(brand.Vulnetix)
	if !bytes.Equal(Drawing(), SVG) || Name() != "Pix" || MakerName() != "Vulnetix" || TemplateVersionFor() != TemplateVersion {
		t.Fatal("Vulnetix must draw Pix")
	}
	brand.Set(brand.Vulnesis)
	if !bytes.Equal(Drawing(), StrixSVG) || Name() != "Strix" || MakerName() != "Vulnesis" || TemplateVersionFor() != StrixTemplateVersion {
		t.Fatal("Vulnesis must draw Strix")
	}
}
