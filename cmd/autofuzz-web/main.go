package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"autofuzz/internal/webui"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "HTTP listen address")
	promefuzzPath := flag.String("promefuzz", "", "Path to the PromeFuzz checkout (required)")
	configPath := flag.String("promefuzz-config", "", "PromeFuzz config.toml path (default: <promefuzz>/config.toml)")
	pythonPath := flag.String("python", "", "Python executable from the PromeFuzz venv (default: <promefuzz>/.venv/bin/python)")
	workspace := flag.String("workspace", "", "Default workspace for target repositories and results")
	codexCommand := flag.String("codex-command", "codex", "Codex CLI executable used by tasks")
	codexModel := flag.String("codex-model", "", "Optional Codex model for tasks")
	codexProfile := flag.String("codex-profile", "", "Optional Codex profile for tasks")
	poolSize := flag.Int("pool-size", 0, "Default PromeFuzz/Codex concurrency")
	jobs := flag.Int("jobs", 0, "Default build parallelism")
	maxFuzzDrivers := flag.Int("max-fuzz-drivers", 0, "Default max child fuzz drivers")
	flag.Parse()

	if *promefuzzPath == "" {
		fmt.Fprintln(os.Stderr, "error: --promefuzz is required (PromeFuzz 路径是启动 autofuzz-web 的必要参数)")
		flag.Usage()
		os.Exit(2)
	}

	// Service-level defaults: these prefill the create-task form in the web UI.
	defaults := webui.DefaultRunRequest()
	defaults.PromeFuzzRoot = *promefuzzPath
	if *configPath != "" {
		defaults.ConfigPath = *configPath
	}
	if *pythonPath != "" {
		defaults.PythonPath = *pythonPath
	}
	if *workspace != "" {
		defaults.Workspace = *workspace
	}
	defaults.CodexCommand = *codexCommand
	if *codexModel != "" {
		defaults.CodexModel = *codexModel
	}
	if *codexProfile != "" {
		defaults.CodexProfile = *codexProfile
	}
	if *poolSize > 0 {
		defaults.PoolSize = *poolSize
	}
	if *jobs > 0 {
		defaults.Jobs = *jobs
	}
	if *maxFuzzDrivers > 0 {
		defaults.MaxFuzzDrivers = *maxFuzzDrivers
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	manager := webui.NewManager(ctx, defaults)
	server := &http.Server{
		Addr: *listen, Handler: webui.NewServer(manager),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	}()
	fmt.Printf("Autofuzz Web: http://%s\n", *listen)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
