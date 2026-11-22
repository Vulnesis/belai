// Command belai-broker fronts a vLLM server with an OpenAI-compatible API for
// Belai and any OpenAI SDK. It launches and supervises vLLM, serves Belai's
// nonce endpoint and verifies sealed blocks (docs/broker.md), and records
// per-request analytics to SQLite or Postgres off the serving path.
//
//	belai-broker serve -config broker.yaml
//	belai-broker keygen            # prints a new client key and its digest
//	belai-broker hash-key < key    # prints the digest of a key on stdin
//	belai-broker print-args -config broker.yaml
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vulnetix/belai/internal/broker/analytics"
	"github.com/vulnetix/belai/internal/broker/config"
	"github.com/vulnetix/belai/internal/broker/noncegate"
	"github.com/vulnetix/belai/internal/broker/server"
	"github.com/vulnetix/belai/internal/broker/vllm"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "keygen":
		err = keygen()
	case "hash-key":
		err = hashKey()
	case "print-args":
		err = printArgs(os.Args[2:])
	case "-h", "-help", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "belai-broker:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  belai-broker serve -config broker.yaml
  belai-broker keygen
  belai-broker hash-key < keyfile
  belai-broker print-args -config broker.yaml`)
}

func loadConfig(args []string, name string) (*config.Config, error) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	path := fs.String("config", "broker.yaml", "path to the broker config")
	_ = fs.Parse(args)
	return config.Load(*path)
}

func keygen() error {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	key := "sk-belai-" + hex.EncodeToString(b)
	fmt.Println("key:   ", key)
	fmt.Println("sha256:", server.HashKey(key))
	return nil
}

func hashKey() error {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return errors.New("no key on stdin")
	}
	fmt.Println(server.HashKey(strings.TrimSpace(line)))
	return nil
}

func printArgs(args []string) error {
	cfg, err := loadConfig(args, "print-args")
	if err != nil {
		return err
	}
	if cfg.VLLM.ExternalURL != "" {
		return errors.New("vllm.external_url is set; the broker launches nothing")
	}
	fmt.Println(cfg.VLLM.Binary, strings.Join(vllm.Args(cfg.VLLM), " "))
	return nil
}

func serve(args []string) error {
	cfg, err := loadConfig(args, "serve")
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	secret, err := noncegate.LoadSecret(cfg.Nonce.SecretFile, cfg.Nonce.SecretEnv)
	if err != nil {
		return fmt.Errorf("nonce secret: %w", err)
	}
	issuer, err := noncegate.NewIssuer(secret, cfg.Nonce.TTL)
	if err != nil {
		return err
	}

	var store analytics.Store
	if cfg.Analytics.Driver != analytics.DriverNone {
		octx, cancel := context.WithTimeout(ctx, 30*time.Second)
		st, err := analytics.Open(octx, cfg.Analytics.Driver, cfg.AnalyticsDSN())
		cancel()
		if err != nil {
			return fmt.Errorf("analytics: %w", err)
		}
		store = st
	}
	rec := analytics.NewRecorder(store, analytics.Options{
		Buffer: cfg.Analytics.Buffer, BatchSize: cfg.Analytics.BatchSize,
		FlushInterval: cfg.Analytics.FlushInterval, Logger: log,
	})

	sup, err := vllm.New(cfg.VLLM, log)
	if err != nil {
		return err
	}
	supCtx, supCancel := context.WithCancel(context.Background())
	supDone := make(chan struct{})
	go func() { sup.Run(supCtx); close(supDone) }()

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.New(cfg, sup, issuer, rec, log),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		supCancel()
		<-supDone
		return err
	}
	log.Info("broker listening", "addr", ln.Addr().String(), "model", cfg.VLLM.ServedName(), "tls", cfg.TLS != nil)
	srvErr := make(chan error, 1)
	go func() {
		if cfg.TLS != nil {
			srvErr <- hs.ServeTLS(ln, cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			srvErr <- hs.Serve(ln)
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err = <-srvErr:
		log.Error("server stopped", "err", err)
	}
	// Order matters: stop taking requests and let streams finish, then stop
	// vLLM, then flush the analytics that those last requests produced.
	sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	_ = hs.Shutdown(sctx)
	cancel()
	supCancel()
	<-supDone
	fctx, fcancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer fcancel()
	if cerr := rec.Close(fctx); cerr != nil {
		log.Warn("analytics flush", "err", cerr)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
