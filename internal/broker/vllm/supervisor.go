// Package vllm launches and supervises a vLLM OpenAI-compatible server for
// the broker. The argv is built from the validated config only, the server
// binds loopback so the broker is its only front door, and a per-launch API
// key reaches it through VLLM_API_KEY in its environment (never argv, which
// other local users can read). The server runs with the scrubbed environment
// plus the variables the operator listed, in its own process group, and is
// restarted with exponential backoff when it exits or stops answering
// /health.
package vllm

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vulnetix/belai/internal/broker/config"
	"github.com/vulnetix/belai/internal/proc"
)

// State is the supervisor's view of the server.
type State string

const (
	StateStopped  State = "stopped"
	StateStarting State = "starting"
	StateReady    State = "ready"
	StateFailed   State = "failed"
)

// ErrNotReady is returned by Ensure when the server did not become ready.
var ErrNotReady = errors.New("model server is not ready")

// Supervisor owns one vLLM process (or watches an external server).
type Supervisor struct {
	cfg    config.VLLM
	log    *slog.Logger
	client *http.Client

	upstream string
	apiKey   string

	mu       sync.Mutex
	state    State
	ready    chan struct{} // closed while ready
	lastErr  string
	restarts int
	pid      int

	demand   chan struct{}
	lastUsed atomic.Int64
}

// New builds a supervisor. It does not start anything.
func New(cfg config.VLLM, log *slog.Logger) (*Supervisor, error) {
	if log == nil {
		log = slog.Default()
	}
	s := &Supervisor{
		cfg:    cfg,
		log:    log,
		state:  StateStopped,
		ready:  make(chan struct{}),
		demand: make(chan struct{}, 1),
		// Loopback traffic must never go through HTTP(S)_PROXY.
		client: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}},
	}
	if cfg.ExternalURL != "" {
		s.upstream = trimSlash(cfg.ExternalURL)
		if cfg.ExternalKeyEnv != "" {
			s.apiKey = os.Getenv(cfg.ExternalKeyEnv)
		}
		return s, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	s.apiKey = hex.EncodeToString(b)
	s.upstream = "http://127.0.0.1:" + strconv.Itoa(cfg.Port)
	return s, nil
}

func trimSlash(u string) string {
	for len(u) > 0 && u[len(u)-1] == '/' {
		u = u[:len(u)-1]
	}
	if len(u) > 3 && u[len(u)-3:] == "/v1" {
		u = u[:len(u)-3]
	}
	return u
}

// Upstream is the server's base URL without /v1.
func (s *Supervisor) Upstream() string { return s.upstream }

// APIKey is the credential the broker sends upstream.
func (s *Supervisor) APIKey() string { return s.apiKey }

// Args returns the vLLM argv after the binary. It is exported for tests and
// for `belai-broker print-args`.
func Args(c config.VLLM) []string {
	a := []string{"serve", c.Model, "--host", "127.0.0.1", "--port", strconv.Itoa(c.Port)}
	if c.ServedModelName != "" {
		a = append(a, "--served-model-name", c.ServedModelName)
	}
	if c.Quantization != "" {
		a = append(a, "--quantization", c.Quantization)
	}
	if c.DType != "" {
		a = append(a, "--dtype", c.DType)
	}
	if c.GPUMemoryUtilization > 0 {
		a = append(a, "--gpu-memory-utilization", strconv.FormatFloat(c.GPUMemoryUtilization, 'f', -1, 64))
	}
	if c.MaxModelLen > 0 {
		a = append(a, "--max-model-len", strconv.Itoa(c.MaxModelLen))
	}
	if c.MaxNumSeqs > 0 {
		a = append(a, "--max-num-seqs", strconv.Itoa(c.MaxNumSeqs))
	}
	if c.EnablePrefixCaching {
		a = append(a, "--enable-prefix-caching")
	}
	return append(a, c.ExtraArgs...)
}

// Status is a snapshot for the stats endpoint.
type Status struct {
	State    State  `json:"state"`
	PID      int    `json:"pid,omitempty"`
	Restarts int    `json:"restarts"`
	LastErr  string `json:"last_error,omitempty"`
	External bool   `json:"external"`
}

// Status returns the current snapshot.
func (s *Supervisor) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{State: s.state, PID: s.pid, Restarts: s.restarts, LastErr: s.lastErr, External: s.cfg.ExternalURL != ""}
}

func (s *Supervisor) setState(st State, errText string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st == s.state && errText == "" {
		return
	}
	was := s.state
	s.state = st
	if errText != "" {
		s.lastErr = errText
	}
	switch {
	case st == StateReady && was != StateReady:
		close(s.ready)
	case st != StateReady && was == StateReady:
		s.ready = make(chan struct{})
	}
	s.log.Info("model server state", "state", st, "was", was)
}

// Touch records use, for idle_stop.
func (s *Supervisor) Touch() { s.lastUsed.Store(time.Now().UnixNano()) }

// Ensure asks for the server and waits until it is ready or ctx ends.
func (s *Supervisor) Ensure(ctx context.Context) error {
	s.Touch()
	s.mu.Lock()
	ch := s.ready
	s.mu.Unlock()
	select {
	case <-ch:
		return nil
	default:
	}
	select {
	case s.demand <- struct{}{}:
	default:
	}
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ErrNotReady
	}
}

// Run supervises until ctx ends, then stops the server and returns.
func (s *Supervisor) Run(ctx context.Context) {
	if s.cfg.ExternalURL != "" {
		s.watchExternal(ctx)
		return
	}
	backoff := s.cfg.RestartBackoff
	wanted := s.cfg.Start == "eager"
	for ctx.Err() == nil {
		if !wanted {
			select {
			case <-ctx.Done():
				return
			case <-s.demand:
				wanted = true
			}
		}
		started := time.Now()
		reason := s.runOnce(ctx)
		if ctx.Err() != nil {
			s.setState(StateStopped, "")
			return
		}
		if reason == errIdle {
			s.setState(StateStopped, "")
			wanted = false
			continue
		}
		s.mu.Lock()
		s.restarts++
		s.mu.Unlock()
		s.setState(StateFailed, reason.Error())
		if time.Since(started) > 10*time.Minute {
			backoff = s.cfg.RestartBackoff
		}
		s.log.Warn("model server exited; restarting", "err", reason, "backoff", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, s.cfg.MaxBackoff)
	}
}

var errIdle = errors.New("idle")

// runOnce launches the server, waits for health, and returns why it ended.
func (s *Supervisor) runOnce(ctx context.Context) error {
	bin, err := exec.LookPath(s.cfg.Binary)
	if err != nil {
		return fmt.Errorf("find %s: %w", s.cfg.Binary, err)
	}
	cmd := exec.Command(bin, Args(s.cfg)...)
	cmd.Env = append(proc.ScrubEnvKeeping(os.Environ(), s.cfg.PassEnv), "VLLM_API_KEY="+s.apiKey)
	setGroup(cmd)
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	s.setState(StateStarting, "")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", s.cfg.Binary, err)
	}
	s.mu.Lock()
	s.pid = cmd.Process.Pid
	s.mu.Unlock()
	s.log.Info("model server launched", "pid", cmd.Process.Pid, "model", s.cfg.Model, "port", s.cfg.Port)
	var logs sync.WaitGroup
	logs.Add(2)
	go s.pipe(&logs, stdout)
	go s.pipe(&logs, stderr)

	exited := make(chan error, 1)
	go func() {
		logs.Wait()
		exited <- cmd.Wait()
	}()
	defer func() {
		s.mu.Lock()
		s.pid = 0
		s.mu.Unlock()
	}()

	stop := func() {
		terminate(cmd.Process.Pid)
		select {
		case <-exited:
		case <-time.After(s.cfg.StopGrace):
			kill(cmd.Process.Pid)
			<-exited
		}
	}

	deadline := time.Now().Add(s.cfg.StartupTimeout)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	fails := 0
	for {
		select {
		case <-ctx.Done():
			s.setState(StateStopped, "")
			stop()
			return ctx.Err()
		case err := <-exited:
			if err == nil {
				err = errors.New("exited with status 0")
			}
			return fmt.Errorf("model server exited: %w", err)
		case <-tick.C:
		}
		healthy := s.healthy(ctx)
		st := s.Status().State
		switch {
		case st == StateStarting && healthy:
			s.setState(StateReady, "")
			s.Touch()
			tick.Reset(s.cfg.HealthInterval)
		case st == StateStarting && time.Now().After(deadline):
			stop()
			return fmt.Errorf("not healthy after %s", s.cfg.StartupTimeout)
		case st == StateReady && !healthy:
			fails++
			if fails >= 3 {
				stop()
				return errors.New("health check failed 3 times")
			}
		case st == StateReady:
			fails = 0
			if s.cfg.IdleStop > 0 && time.Since(time.Unix(0, s.lastUsed.Load())) > s.cfg.IdleStop {
				s.log.Info("model server idle; stopping", "idle_stop", s.cfg.IdleStop)
				s.setState(StateStopped, "")
				stop()
				return errIdle
			}
		}
	}
}

func (s *Supervisor) watchExternal(ctx context.Context) {
	s.setState(StateStarting, "")
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		if s.healthy(ctx) {
			s.setState(StateReady, "")
			t.Reset(s.cfg.HealthInterval)
		} else if s.Status().State == StateReady {
			s.setState(StateFailed, "external server failed its health check")
			t.Reset(time.Second)
		}
		select {
		case <-ctx.Done():
			s.setState(StateStopped, "")
			return
		case <-t.C:
		case <-s.demand:
		}
	}
}

func (s *Supervisor) healthy(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.upstream+"/health", nil)
	if err != nil {
		return false
	}
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// pipe forwards the server's output to the broker log, one line at a time.
func (s *Supervisor) pipe(wg *sync.WaitGroup, r io.Reader) {
	defer wg.Done()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		s.log.Info("vllm", "line", sc.Text())
	}
}
