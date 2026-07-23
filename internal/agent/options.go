package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"autofuzz/internal/state"
)

type Options struct {
	RepositoryURL  string
	Ref            string
	Workspace      string
	PromeFuzzRoot  string
	ConfigPath     string
	PythonPath     string
	PoolSize       int
	Jobs           int
	MaxFuzzDrivers int
	CodexCommand   string
	CodexModel     string
	CodexProfile   string
	Resume         bool
	Verbose        bool
	StopAfter      state.Stage
	FuzzInterval   time.Duration
}

func (o *Options) Normalize() error {
	if o.PromeFuzzRoot == "" {
		return fmt.Errorf("promefuzz is required")
	}
	var err error
	if o.PromeFuzzRoot, err = filepath.Abs(o.PromeFuzzRoot); err != nil {
		return fmt.Errorf("resolve promefuzz: %w", err)
	}
	if o.ConfigPath == "" {
		o.ConfigPath = filepath.Join(o.PromeFuzzRoot, "config.toml")
	}
	if o.PythonPath == "" {
		o.PythonPath = filepath.Join(o.PromeFuzzRoot, ".venv", "bin", "python")
	}
	for _, item := range []struct {
		name  string
		value *string
	}{
		{"workspace", &o.Workspace},
		{"promefuzz-config", &o.ConfigPath},
		{"python", &o.PythonPath},
	} {
		*item.value, err = filepath.Abs(*item.value)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", item.name, err)
		}
	}
	if o.MaxFuzzDrivers == 0 {
		o.MaxFuzzDrivers = runtime.NumCPU()
	}
	if o.PoolSize < 1 || o.Jobs < 1 || o.MaxFuzzDrivers < 1 {
		return fmt.Errorf("pool-size, jobs and max-fuzz-drivers must be positive")
	}
	if o.CodexCommand == "" {
		return fmt.Errorf("codex-command cannot be empty")
	}
	if _, err := os.Stat(filepath.Join(o.PromeFuzzRoot, "PromeFuzz.py")); err != nil {
		return fmt.Errorf("invalid PromeFuzz root: %w", err)
	}
	if info, err := os.Stat(o.ConfigPath); err != nil || info.IsDir() {
		return fmt.Errorf("PromeFuzz config not found: %s", o.ConfigPath)
	}
	if info, err := os.Stat(o.PythonPath); err != nil || info.IsDir() {
		return fmt.Errorf("virtual-environment Python not found: %s", o.PythonPath)
	}
	validStages := map[state.Stage]bool{
		state.StageBuilt:      true,
		state.StageConfigured: true, state.StagePreprocessed: true,
		state.StageComprehended: true, state.StageGenerated: true, state.StageFuzzing: true,
	}
	if !validStages[o.StopAfter] {
		return fmt.Errorf("invalid stop-after stage %q", o.StopAfter)
	}
	return nil
}

func DefaultOptions() Options {
	return Options{
		Workspace: "autofuzz-work",
		PoolSize:  5, Jobs: runtime.NumCPU(), MaxFuzzDrivers: runtime.NumCPU(), StopAfter: state.StageFuzzing, FuzzInterval: 30 * time.Minute,
		CodexCommand: "codex",
	}
}
