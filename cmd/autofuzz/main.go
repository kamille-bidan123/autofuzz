package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"autofuzz/internal/agent"
	"autofuzz/internal/state"
)

func main() {
	options := agent.DefaultOptions()
	var stopAfter string
	flag.StringVar(&options.Ref, "ref", "", "Git ref, tag, or branch to clone")
	flag.StringVar(&options.Workspace, "workspace", options.Workspace, "Workspace for target repositories and results")
	flag.StringVar(&options.PromeFuzzRoot, "promefuzz", options.PromeFuzzRoot, "Path to the PromeFuzz checkout (required)")
	flag.StringVar(&options.ConfigPath, "promefuzz-config", options.ConfigPath, "PromeFuzz config.toml path (default: <promefuzz>/config.toml)")
	flag.StringVar(&options.PythonPath, "python", options.PythonPath, "Python executable from the PromeFuzz virtual environment (default: <promefuzz>/.venv/bin/python)")
	flag.IntVar(&options.PoolSize, "pool-size", options.PoolSize, "PromeFuzz/Codex concurrency")
	flag.IntVar(&options.Jobs, "jobs", options.Jobs, "Build parallelism")
	flag.IntVar(&options.MaxFuzzDrivers, "max-fuzz-drivers", options.MaxFuzzDrivers, "Maximum child fuzz drivers to run concurrently (default: nproc)")
	flag.StringVar(&options.CodexCommand, "codex-command", options.CodexCommand, "Codex CLI executable used for autonomous build and configuration")
	flag.StringVar(&options.CodexModel, "codex-model", options.CodexModel, "Optional Codex model for autonomous build and configuration")
	flag.StringVar(&options.CodexProfile, "codex-profile", options.CodexProfile, "Optional Codex profile for autonomous build and configuration")
	flag.BoolVar(&options.Resume, "resume", false, "Resume an existing target state")
	flag.BoolVar(&options.Verbose, "verbose", false, "Stream command output as well as writing logs")
	flag.DurationVar(&options.FuzzInterval, "fuzz-interval", options.FuzzInterval, "Interval between fuzz/coverage assessments")
	flag.StringVar(&stopAfter, "stop-after", string(state.StageFuzzing), "Stop after a named stage")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: autofuzz [options] <local-directory-or-git-url>\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	options.RepositoryURL = flag.Arg(0)
	options.StopAfter = state.Stage(stopAfter)

	autoAgent, err := agent.New(options)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := autoAgent.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
