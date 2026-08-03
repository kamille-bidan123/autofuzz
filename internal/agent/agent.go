package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"autofuzz/internal/fuzzing"
	"autofuzz/internal/repository"
	"autofuzz/internal/runevent"
	"autofuzz/internal/runner"
	"autofuzz/internal/state"
)

type Agent struct {
	Options   Options
	Runner    runner.Runner
	State     *state.RunState
	TargetDir string
	StatePath string
	LogsDir   string

	eventMu          sync.RWMutex
	eventSink        runevent.Sink
	activeStage      state.Stage
	fuzzControllerMu sync.RWMutex
	fuzzController   *fuzzing.FuzzController
	corpusMonitorMu  sync.RWMutex
	corpusMonitor    *fuzzing.CorpusMonitor
	coverageMu       sync.RWMutex
	coverageData     any
	snapshotCmpMu    sync.RWMutex
	snapshotCmp      map[int]fuzzing.CoverageStatus // frozen past-snapshot exports (cached)
}

func New(options Options) (*Agent, error) {
	if err := options.Normalize(); err != nil {
		return nil, err
	}
	normalizedInput, sourceKind, err := repository.NormalizeInput(options.RepositoryURL)
	if err != nil {
		return nil, err
	}
	options.RepositoryURL = normalizedInput
	name, err := repository.ProjectName(options.RepositoryURL)
	if err != nil {
		return nil, err
	}
	if options.ProjectName != "" {
		name = options.ProjectName
	}
	targetDir := filepath.Join(options.Workspace, name)
	statePath := filepath.Join(targetDir, "agent-state.json")
	var runState *state.RunState
	if options.Resume {
		runState, err = state.Load(statePath)
		if err != nil {
			return nil, fmt.Errorf("resume state: %w", err)
		}
		if runState.RepositoryURL != options.RepositoryURL {
			return nil, fmt.Errorf("state belongs to a different repository")
		}
		if err := runState.RestoreResumeStage(); err != nil {
			return nil, fmt.Errorf("resume state: %w", err)
		}
	} else {
		if _, err := os.Stat(statePath); err == nil {
			return nil, fmt.Errorf("state already exists; pass --resume or choose another workspace")
		}
		runState = state.New(options.RepositoryURL, options.Ref, name, filepath.Join(targetDir, "source"))
		runState.SourceKind = sourceKind
		runState.TaskKind = options.TaskKind
		runState.ParentTaskID = options.ParentTaskID
		runState.OriginDriverID = options.Origin.DriverID
		runState.OriginDriverSeq = options.Origin.DriverSeq
		runState.OriginCrashes = append([]string(nil), options.Origin.Crashes...)
		runState.OriginSnapshotDir = options.Origin.SnapshotDir
		runState.OriginSourceDir = options.Origin.SourceDir
		runState.OriginBuildDir = options.Origin.BuildDir
		runState.OriginInstallDir = options.Origin.InstallDir
	}
	agent := &Agent{
		Options: options, State: runState,
		TargetDir: targetDir, StatePath: statePath, LogsDir: filepath.Join(targetDir, "logs"),
		snapshotCmp: map[int]fuzzing.CoverageStatus{},
	}
	agent.Runner = runner.Runner{Verbose: options.Verbose, OnLine: agent.onCommandLine}
	return agent, nil
}

func (a *Agent) Run(ctx context.Context) error {
	if err := os.MkdirAll(a.TargetDir, 0o755); err != nil {
		return err
	}
	if err := a.State.Save(a.StatePath); err != nil {
		return err
	}
	if !a.State.Stage.AtLeast(state.StageCloned) || !validPreparedSource(a.State) {
		a.stageStarted(state.StageCloned, "正在复制本地源码或浅克隆 Git 仓库")
		commit, err := repository.Prepare(ctx, a.Runner, a.Options.RepositoryURL, a.State.SourceKind, a.Options.Ref, a.State.SourceDir, filepath.Join(a.LogsDir, "clone"))
		if err != nil {
			return a.fail(state.StageCloned, err)
		}
		a.State.Commit = commit
		a.State.Stage = state.StageCloned
		a.State.RunStatus = ""
		if err := a.State.Save(a.StatePath); err != nil {
			return err
		}
		a.stageCompleted(state.StageCloned, "源码准备完成")
	}
	fmt.Printf("repository ready: %s @ %s\n", a.State.SourceDir, shortCommit(a.State.Commit))
	return a.runRemaining(ctx)
}

func isGitCheckout(path string) bool {
	info, err := os.Stat(filepath.Join(path, ".git"))
	return err == nil && info.IsDir()
}

func validPreparedSource(runState *state.RunState) bool {
	if runState.SourceKind == "local" {
		info, err := os.Stat(runState.SourceDir)
		return err == nil && info.IsDir() && runState.Commit != ""
	}
	return isGitCheckout(runState.SourceDir)
}

func shortCommit(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

func (a *Agent) setCorpusMonitor(m *fuzzing.CorpusMonitor) {
	a.corpusMonitorMu.Lock()
	a.corpusMonitor = m
	a.corpusMonitorMu.Unlock()
}

func (a *Agent) setCoverageData(data any) {
	a.coverageMu.Lock()
	a.coverageData = fuzzing.CloneCoverageData(data)
	a.coverageMu.Unlock()
}

// CoverageData returns the cached llvm-cov export result from the corpus
// monitor, or nil when no monitor is active (e.g. not in the fuzzing stage).
func (a *Agent) CoverageData() any {
	a.coverageMu.RLock()
	data := a.coverageData
	a.coverageMu.RUnlock()
	if data != nil {
		return fuzzing.CloneCoverageData(data)
	}
	a.corpusMonitorMu.RLock()
	m := a.corpusMonitor
	a.corpusMonitorMu.RUnlock()
	if m == nil {
		return nil
	}
	return m.CoverageCache()
}

// NewHistoricalAgent creates a minimal Agent for reading historical task
// data from disk (SnapshotComparison, coverage export). No live fuzzing.
func NewHistoricalAgent(targetDir string, runState *state.RunState, logsDir string) *Agent {
	return &Agent{
		TargetDir:   targetDir,
		State:       runState,
		LogsDir:     logsDir,
		snapshotCmp: map[int]fuzzing.CoverageStatus{},
	}
}
