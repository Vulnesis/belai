package vllm

import (
	"context"
	"net"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/vulnetix/belai/internal/broker/config"
	"github.com/vulnetix/belai/internal/broker/fakevllm"
)

func TestMain(m *testing.M) {
	fakevllm.MaybeRun()
	os.Exit(m.Run())
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestArgsMatchOperatorCommand(t *testing.T) {
	got := Args(config.VLLM{
		Model: "Qwen/Qwen3.8-27B-AWQ", Quantization: "awq_marlin", DType: "float16",
		GPUMemoryUtilization: 0.92, MaxModelLen: 4096, MaxNumSeqs: 16, EnablePrefixCaching: true, Port: 8001,
	})
	want := []string{"serve", "Qwen/Qwen3.8-27B-AWQ", "--host", "127.0.0.1", "--port", "8001",
		"--quantization", "awq_marlin", "--dtype", "float16", "--gpu-memory-utilization", "0.92",
		"--max-model-len", "4096", "--max-num-seqs", "16", "--enable-prefix-caching"}
	if !slices.Equal(got, want) {
		t.Fatalf("args\n got %q\nwant %q", got, want)
	}
}

func testCfg(t *testing.T, start string) config.VLLM {
	return config.VLLM{
		Binary: os.Args[0], Model: "fake", Port: freePort(t), Start: start,
		PassEnv:        []string{fakevllm.EnvRun},
		StartupTimeout: 20 * time.Second, StopGrace: 2 * time.Second,
		RestartBackoff: 100 * time.Millisecond, MaxBackoff: time.Second, HealthInterval: 100 * time.Millisecond,
	}
}

func TestSupervisorOnDemandStartAndStop(t *testing.T) {
	t.Setenv(fakevllm.EnvRun, "1")
	s, err := New(testCfg(t, "on_demand"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	time.Sleep(200 * time.Millisecond)
	if st := s.Status().State; st != StateStopped {
		t.Fatalf("on_demand started early: %s", st)
	}
	wctx, wcancel := context.WithTimeout(ctx, 20*time.Second)
	defer wcancel()
	if err := s.Ensure(wctx); err != nil {
		t.Fatalf("ensure: %v (%+v)", err, s.Status())
	}
	pid := s.Status().PID
	if pid == 0 {
		t.Fatal("no pid while ready")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	if s.Status().State != StateStopped {
		t.Fatalf("state after stop: %s", s.Status().State)
	}
}

func TestSupervisorReportsMissingBinary(t *testing.T) {
	c := testCfg(t, "eager")
	c.Binary = "belai-no-such-vllm"
	s, _ := New(c, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st := s.Status(); st.State == StateFailed && st.LastErr != "" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("status %+v", s.Status())
}
