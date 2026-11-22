// Package products probes the Vulnetix products on this host for Keleustes
// host management (docs/gaps/host-management.md §5.1): the Vulnetix CLI, the
// package firewall's per-ecosystem configuration, the AI firewall's client
// wiring and the runtime sensor.
//
// Every probe runs a fixed program with a fixed argv, no shell, the scrubbed
// environment and its own process group, and is capped at ProbeTimeout. The
// result is facts the harness composes: states and versions from closed sets
// or identifier shapes, home-relative paths, and check hints written here.
// Tool output never passes through as text, so a ProductStatus carries no
// secret and nothing a model reads. Entitlement is the host CLI's own answer
// (decision O4); nothing here asks the Vulnetix API.
package products

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/proc"
	"github.com/vulnetix/belai/internal/sanitize"
)

// The products, as ProductStatus.product names them.
const (
	CLI             = "cli"
	PackageFirewall = "package_firewall"
	AIFirewall      = "ai_firewall"
	Sensor          = "sensor"
)

// Names lists the products in report order.
func Names() []string { return []string{CLI, PackageFirewall, AIFirewall, Sensor} }

// Valid reports whether name is a product.
func Valid(name string) bool {
	switch name {
	case CLI, PackageFirewall, AIFirewall, Sensor:
		return true
	}
	return false
}

// ProbeTimeout caps one probe command; CacheFor is how long a result is
// reused.
const (
	ProbeTimeout = 10 * time.Second
	CacheFor     = 60 * time.Second
	maxOutput    = 1 << 20
)

// Output is what a probe command produced. Stdout is read by a parser and
// never forwarded.
type Output struct {
	Stdout []byte
	Exit   int
}

// Runner runs one fixed program. err is set when it could not start or ran
// out of time; a non-zero exit is Output.Exit, not an error.
type Runner func(ctx context.Context, name string, args ...string) (Output, error)

// ExecRunner is the real Runner: the scrubbed environment, its own process
// group, no stdin, stdout capped and stderr dropped.
func ExecRunner(ctx context.Context, name string, args ...string) (Output, error) {
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = proc.ScrubbedEnv()
	proc.SetProcessGroup(cmd)
	var out capped
	out.max = maxOutput
	cmd.Stdout, cmd.Stderr, cmd.Stdin = &out, io.Discard, nil
	err := cmd.Run()
	if ctx.Err() != nil {
		return Output{}, ctx.Err()
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return Output{Stdout: out.Bytes(), Exit: ee.ExitCode()}, nil
	}
	if err != nil {
		return Output{}, err
	}
	return Output{Stdout: out.Bytes()}, nil
}

type capped struct {
	bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.Len(); room > 0 {
		if len(p) > room {
			c.Buffer.Write(p[:room])
		} else {
			c.Buffer.Write(p)
		}
	}
	return len(p), nil
}

// Prober probes the products, caching each result for CacheFor.
type Prober struct {
	Run      Runner
	LookPath func(string) (string, error)
	// Home is the user's home directory; paths under it are reported
	// home-relative.
	Home   string
	GOOS   string
	Getenv func(string) string
	Now    func() time.Time

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	st *nodev1.ProductStatus
	at time.Time
}

// NewProber is a Prober on this host.
func NewProber() *Prober {
	home, _ := os.UserHomeDir()
	return &Prober{Run: ExecRunner, LookPath: exec.LookPath, Home: home, GOOS: runtime.GOOS, Getenv: os.Getenv, Now: time.Now}
}

func (p *Prober) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Prober) getenv(k string) string {
	if p.Getenv != nil {
		return p.Getenv(k)
	}
	return ""
}

// Probe returns one product's status, from the cache unless fresh or the
// cached result is older than CacheFor. An unknown product is nil.
func (p *Prober) Probe(ctx context.Context, product string, fresh bool) *nodev1.ProductStatus {
	if !Valid(product) {
		return nil
	}
	p.mu.Lock()
	if c, ok := p.cache[product]; ok && !fresh && p.now().Sub(c.at) < CacheFor {
		p.mu.Unlock()
		return c.st
	}
	p.mu.Unlock()
	var st *nodev1.ProductStatus
	switch product {
	case CLI:
		st = p.probeCLI(ctx)
	case PackageFirewall:
		st = p.probePkgFW(ctx)
	case AIFirewall:
		st = p.probeAIFW(ctx)
	case Sensor:
		st = p.probeSensor(ctx)
	}
	st.Product = product
	st.ProbedAtMs = p.now().UnixMilli()
	p.mu.Lock()
	if p.cache == nil {
		p.cache = map[string]cached{}
	}
	p.cache[product] = cached{st: st, at: p.now()}
	p.mu.Unlock()
	return st
}

// All probes every product.
func (p *Prober) All(ctx context.Context, fresh bool) []*nodev1.ProductStatus {
	out := make([]*nodev1.ProductStatus, 0, 4)
	for _, n := range Names() {
		out = append(out, p.Probe(ctx, n, fresh))
	}
	return out
}

// run is p.Run with the probe cap applied.
func (p *Prober) run(ctx context.Context, name string, args ...string) (Output, error) {
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	run := p.Run
	if run == nil {
		run = ExecRunner
	}
	return run(ctx, name, args...)
}

func (p *Prober) lookPath(name string) (string, bool) {
	look := p.LookPath
	if look == nil {
		look = exec.LookPath
	}
	path, err := look(name)
	return path, err == nil && path != ""
}

// HomeRel makes path home-relative ("~/...") when it is under home, and
// cleans it to one short line.
func HomeRel(home, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if home != "" && filepath.IsAbs(path) {
		if rel, err := filepath.Rel(home, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			if rel == "." {
				path = "~"
			} else {
				path = "~/" + filepath.ToSlash(rel)
			}
		}
	}
	return sanitize.Line(path, 256)
}

var (
	versionRE = regexp.MustCompile(`^v?[0-9]+(\.[0-9]+){0,3}([-+][0-9A-Za-z.+-]{1,40})?$`)
	identRE   = regexp.MustCompile(`^[A-Za-z0-9._:@-]{1,64}$`)
	wordRE    = regexp.MustCompile(`^[a-z][a-z0-9_ -]{0,31}$`)
)

// version keeps s when it has a version's shape.
func version(s string) string {
	s = strings.TrimSpace(s)
	if f := strings.Fields(s); len(f) > 0 {
		s = f[len(f)-1]
	}
	if versionRE.MatchString(s) {
		return s
	}
	return ""
}

// ident keeps s when it is an identifier.
func ident(s string) string {
	s = strings.TrimSpace(s)
	if identRE.MatchString(s) {
		return s
	}
	return ""
}

// word keeps s when it is a short lowercase word.
func word(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if wordRE.MatchString(s) {
		return s
	}
	return ""
}

func check(id, status, hint string) *nodev1.Check {
	return &nodev1.Check{Id: id, Status: status, Hint: sanitize.Line(hint, 160)}
}
