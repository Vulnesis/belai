package hostmgmt

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/vulnetix/belai/internal/config"
	"github.com/vulnetix/belai/internal/factorylink/nodev1"
	"github.com/vulnetix/belai/internal/products"
	"github.com/vulnetix/belai/internal/sanitize"
	"github.com/vulnetix/belai/internal/session"
	"github.com/vulnetix/belai/internal/vaultenv"
)

// The read kinds and the diagnostics actions (§5.8).

// maxLogLines caps log_tail.
const maxLogLines = 1000

func runInventoryRefresh(ctx context.Context, c *call, _ *Plan) result {
	c.m.mu.Lock()
	c.m.preAt = time.Time{}
	c.m.mu.Unlock()
	if err := c.m.report(ctx, true); err != nil {
		return failed("the inventory could not be reported")
	}
	return done(resultJSON(map[string]bool{"reported": true}))
}

func runProductProbe(ctx context.Context, c *call, _ *Plan) result {
	st := c.m.o.Prober.Probe(ctx, c.p["product"], true)
	c.m.poke()
	b, err := protojson.Marshal(st)
	if err != nil {
		return failed("the probe result could not be encoded")
	}
	return done(string(b))
}

// preflight runs rc.Preflight through the hook, at most once a minute unless
// fresh.
func (m *Manager) preflight(ctx context.Context, fresh bool) []*nodev1.Check {
	if m.o.Hooks.Preflight == nil {
		return nil
	}
	m.mu.Lock()
	if !fresh && !m.preAt.IsZero() && m.o.Now().Sub(m.preAt) < time.Minute {
		out := m.pre
		m.mu.Unlock()
		return out
	}
	m.mu.Unlock()
	checks := m.o.Hooks.Preflight(ctx)
	for _, ch := range checks {
		ch.Hint = sanitize.Line(vaultenv.Default.Scrub(ch.Hint), 160)
	}
	m.mu.Lock()
	m.pre, m.preAt = checks, m.o.Now()
	m.mu.Unlock()
	return checks
}

func runPreflight(ctx context.Context, c *call, _ *Plan) result {
	checks := c.m.preflight(ctx, true)
	c.m.poke()
	out := []map[string]string{}
	for _, ch := range checks {
		out = append(out, map[string]string{"id": ch.GetId(), "status": ch.GetStatus(), "hint": ch.GetHint()})
	}
	return done(resultJSON(map[string]any{"checks": out}))
}

// tailLines reads the last n lines of path, reading at most 4 MiB from the
// end.
func tailLines(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const window = 4 << 20
	off := max(info.Size()-window, 0)
	buf := make([]byte, info.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && len(buf) > 0 {
		return nil, err
	}
	if off > 0 {
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		}
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

func runLogTail(_ context.Context, c *call, _ *Plan) result {
	n := 200
	if v := c.p["lines"]; v != "" {
		n, _ = strconv.Atoi(v)
	}
	lines, err := tailLines(filepath.Join(c.m.o.Home, "rc", "rc.log"), n)
	if err != nil && !os.IsNotExist(err) {
		return failed("rc.log could not be read")
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, sanitize.Line(vaultenv.Default.Scrub(l), 1000))
	}
	return done(resultJSON(map[string]any{"lines": out}))
}

// sessionsRoot is where session files live.
func sessionsRoot() string {
	st, err := session.NewStore()
	if err != nil {
		return ""
	}
	return st.Root
}

// oldSessions lists the session files older than cutoff and their bytes.
func oldSessions(root string, cutoff time.Time) ([]string, int64) {
	var out []string
	var total int64
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(info.Name(), ".jsonl") {
			return nil
		}
		if info.ModTime().Before(cutoff) {
			out = append(out, path)
			total += info.Size()
		}
		return nil
	})
	sort.Strings(out)
	return out, total
}

func planSessionPrune(_ context.Context, c *call) (*Plan, string) {
	s, err := config.LoadGlobal()
	if err != nil {
		return nil, "the host's settings could not be read"
	}
	days := s.SessionRetention()
	return &Plan{Params: map[string]string{"session_retention_days": strconv.Itoa(days)},
		Notes: []string{"removes session files untouched for session_retention_days"}}, ""
}

func runSessionPrune(_ context.Context, c *call, pl *Plan) result {
	days, _ := strconv.Atoi(pl.Params["session_retention_days"])
	st, err := session.NewStore()
	if err != nil {
		return failed("the session store could not be opened")
	}
	maxAge := time.Duration(days) * 24 * time.Hour
	files, bytes := oldSessions(st.Root, time.Now().Add(-maxAge))
	n, err := st.Prune(maxAge)
	if err != nil {
		return failed("the session store could not be pruned")
	}
	if n < len(files) {
		bytes = bytes * int64(n) / int64(max(len(files), 1))
	}
	return done(resultJSON(map[string]int64{"removed": int64(n), "bytes_freed": bytes}))
}

// homeRel is products.HomeRel.
func homeRel(home, p string) string { return products.HomeRel(home, p) }

func sortStrings(s []string) { sort.Strings(s) }
