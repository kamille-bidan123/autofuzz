package fuzzing

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMultiFuzzWindowCycles = 3
	multiCoverageEmitInterval    = 15 * time.Second
)

type FuzzTarget struct {
	DriverID    int
	Source      string
	BuildScript string
}

type runningTarget struct {
	state            *TargetState
	cfg              FuzzConfig
	cancel           context.CancelFunc
	tracker          *FuzzStatusTracker
	monitor          *CorpusMonitor
	startedIteration int
}

type targetCycleData struct {
	state    *TargetState
	status   FuzzStatus
	coverage CorpusCoverageStatus
	cache    CoverageSnapshot
	plateau  bool
}

type MultiCoverageSnapshot struct {
	Timestamp                time.Time                `json:"timestamp"`
	Available                bool                     `json:"available"`
	Mode                     string                   `json:"mode"`
	Iteration                int                      `json:"iteration"`
	SeedCount                int                      `json:"seed_count"`
	ActiveTargets            int                      `json:"active_targets"`
	MaxParallelTargets       int                      `json:"max_parallel_targets"`
	RunningTargets           []int                    `json:"running_targets"`
	QueuedTargets            []int                    `json:"queued_targets"`
	NextTargets              []int                    `json:"next_targets,omitempty"`
	FuzzIntervalSeconds      int64                    `json:"fuzz_interval_seconds,omitempty"`
	NextAnalysisAt           *time.Time               `json:"next_analysis_at,omitempty"`
	AnalysisRemainingSeconds int64                    `json:"analysis_remaining_seconds,omitempty"`
	Coverage                 CoverageStatus           `json:"coverage"`
	Targets                  []TargetCoverageSnapshot `json:"targets"`
}

type TargetCoverageSnapshot struct {
	DriverID       int             `json:"driver_id"`
	Seq            int             `json:"seq"`
	Status         string          `json:"status"`
	Available      bool            `json:"available"`
	SeedCount      int             `json:"seed_count"`
	CorpusDir      string          `json:"corpus_dir"`
	Summary        CoverageSummary `json:"summary"`
	Coverage       CoverageStatus  `json:"coverage,omitempty"`
	UncoveredCount int             `json:"uncovered_count"`
	Plateau        bool            `json:"plateau"`
	FuzzStatus     FuzzStatus      `json:"fuzz_status"`
}

// StartMultiFuzzingPhase starts the multi-target fuzzing phase and returns a
// controller compatible with the single-driver fuzzing loop.
func StartMultiFuzzingPhase(ctx context.Context, cfg FuzzConfig) FuzzController {
	ctrl := FuzzController{
		Trigger: make(chan struct{}, 1),
		Done:    make(chan error, 1),
	}
	if cfg.TriggerCh == nil {
		cfg.TriggerCh = ctrl.Trigger
	}
	go func() {
		ctrl.Done <- RunMultiFuzzingPhase(ctx, cfg)
	}()
	return ctrl
}

func RunMultiFuzzingPhase(ctx context.Context, cfg FuzzConfig) error {
	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Minute
	}
	if err := os.MkdirAll(cfg.LogsDir, 0o755); err != nil {
		return err
	}

	targets, err := DiscoverFuzzTargets(cfg.DriverDir)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no child fuzz drivers found in %s", cfg.DriverDir)
	}
	maxParallel := resolveMultiFuzzParallelism(cfg, len(targets))
	cfg.logf("[fuzzing] multi driver concurrency = %d/%d\n", maxParallel, len(targets))
	targetByID := map[int]FuzzTarget{}
	for _, target := range targets {
		targetByID[target.DriverID] = target
	}

	statePath := filepath.Join(cfg.LogsDir, "multi-fuzzing-state.json")
	st, err := LoadMultiFuzzState(statePath)
	if err != nil {
		return err
	}
	if st == nil {
		st = &MultiFuzzState{
			Version:     MultiFuzzStateVersion,
			Mode:        "multi",
			TargetCount: len(targets),
			Targets:     map[int]*TargetState{},
		}
	}
	st.TargetCount = len(targets)
	if st.NextTargetIndex < 0 {
		st.NextTargetIndex = 0
	}

	flowPath := filepath.Join(cfg.LogsDir, "fuzz-flow.json")
	flow, _ := LoadFuzzFlow(flowPath)
	if flow == nil {
		flow = &FuzzFlowSnapshot{}
	}
	emitFlow := func(phase FuzzFlowPhase, status, trigger, message string, driverID int) {
		flow.Iteration = st.Iteration
		flow.DriverID = driverID
		flow.TargetCount = len(targets)
		if driverID != 0 {
			if targetState := st.Targets[driverID]; targetState != nil {
				flow.DriverSeq = targetState.Seq
			}
		} else {
			flow.DriverSeq = 0
		}
		flow.Phase = phase
		flow.Status = status
		flow.Trigger = trigger
		flow.Message = message
		if err := flow.Save(flowPath); err != nil {
			cfg.logf("[fuzzing] flow state save failed: %v\n", err)
		}
		if cfg.FlowSink != nil {
			cfg.FlowSink(*flow)
		}
	}

	emitFlow(FuzzFlowStarting, "running", "", fmt.Sprintf("正在创建 %d 个子 driver 初始快照", len(targets)), 0)
	if err := ensureInitialTargetSnapshots(ctx, cfg, st, targets); err != nil {
		emitFlow(FuzzFlowStarting, "failed", "", err.Error(), 0)
		return err
	}
	if err := st.Save(statePath); err != nil {
		return err
	}

	running := map[int]*runningTarget{}
	stopAll := func() {
		for _, rt := range running {
			stopRunningTarget(rt)
		}
		if cfg.OnCoverageChanged != nil {
			cfg.OnCoverageChanged(nil)
		}
	}
	defer stopAll()

	var lastCycleData []targetCycleData
	nextAnalysisAt := time.Now().Add(cfg.Interval)
	emitCoverage := func(data []targetCycleData) {
		if cfg.OnCoverageChanged != nil {
			cfg.OnCoverageChanged(buildMultiCoverageSnapshot(data, st, targets, maxParallel, cfg.Interval, nextAnalysisAt))
		}
	}

	fillRunningTargets(ctx, cfg, st, targets, running, maxParallel, st.Iteration)
	if len(running) == 0 {
		return fmt.Errorf("no child fuzz driver could be started")
	}
	markQueuedTargets(st, targets, running)
	if err := st.Save(statePath); err != nil {
		return err
	}
	lastCycleData = collectMultiLiveData(running, st.Iteration)
	emitCoverage(lastCycleData)
	emitFlow(FuzzFlowFuzzing, "idle", "", multiFuzzingIdleMessage(len(running), len(targets), maxParallel, "正在并行 fuzz"), 0)

	settleRunningSet := func(protectedDriverID int) error {
		rotated := rotateExpiredTargets(cfg, running, st.Iteration, protectedDriverID)
		started := fillRunningTargets(ctx, cfg, st, targets, running, maxParallel, st.Iteration)
		markQueuedTargets(st, targets, running)
		if rotated > 0 || started > 0 {
			cfg.logf("[fuzzing] scheduler rotated %d driver(s), started %d driver(s); active=%d/%d\n", rotated, started, len(running), len(targets))
		}
		if err := st.Save(statePath); err != nil {
			cfg.logf("[fuzzing] multi state save failed: %v\n", err)
		}
		if rotated > 0 || started > 0 {
			lastCycleData = collectMultiLiveData(running, st.Iteration)
		}
		emitCoverage(lastCycleData)
		if len(running) == 0 {
			return fmt.Errorf("no active child fuzz drivers after scheduling")
		}
		return nil
	}

	analysisTimer := time.NewTimer(time.Until(nextAnalysisAt))
	defer analysisTimer.Stop()
	coverageTicker := time.NewTicker(multiCoverageEmitInterval)
	defer coverageTicker.Stop()
	for {
		triggerSource := "interval"
		select {
		case <-analysisTimer.C:
		case <-coverageTicker.C:
			lastCycleData = collectMultiLiveData(running, st.Iteration)
			emitCoverage(lastCycleData)
			continue
		case <-cfg.TriggerCh:
			if !analysisTimer.Stop() {
				select {
				case <-analysisTimer.C:
				default:
				}
			}
			triggerSource = "manual"
		case <-ctx.Done():
			return ctx.Err()
		}
		nextAnalysisAt = time.Now().Add(cfg.Interval)
		analysisTimer.Reset(time.Until(nextAnalysisAt))

		st.Iteration++
		cycleStarted := time.Now()
		flow.CycleStarted = &cycleStarted
		emitFlow(FuzzFlowCollecting, "running", triggerSource, "正在采集所有子 driver 的运行状态与覆盖数据", 0)

		cycleData := collectMultiCycleData(cfg, running, st.Iteration)
		lastCycleData = cycleData
		emitCoverage(lastCycleData)
		if err := st.Save(statePath); err != nil {
			cfg.logf("[fuzzing] multi state save failed: %v\n", err)
		}

		emitFlow(FuzzFlowSelecting, "running", triggerSource, "正在按硬策略选择到达平台期的子 driver", 0)
		selected := selectPlateauTarget(cycleData)
		if selected == nil {
			cfg.logf("[fuzzing] iteration %d: no plateau target selected\n", st.Iteration)
			if err := settleRunningSet(0); err != nil {
				return err
			}
			flow.CycleStarted = nil
			emitFlow(FuzzFlowFuzzing, "idle", "", multiFuzzingIdleMessage(len(running), len(targets), maxParallel, "暂无平台期候选"), 0)
			continue
		}

		driverID := selected.state.DriverID
		target := targetByID[driverID]
		st.CurrentDriverID = driverID
		cfg.logf("[fuzzing] iteration %d: selected driver %d for LLM optimization\n", st.Iteration, driverID)

		emitFlow(FuzzFlowPrechecking, "running", triggerSource, fmt.Sprintf("正在为 driver %d 创建临时优化目录并预检", driverID), driverID)
		tmpDir, precheckCov, err := prepareLLMWorkDir(ctx, cfg, target, selected.state, st.Iteration)
		if err != nil {
			finishedAt := time.Now()
			msg := fmt.Sprintf("driver %d precheck failed: %v", driverID, err)
			cfg.logf("[fuzzing] %s\n", msg)
			flow.LastResult = &FuzzFlowResult{Iteration: st.Iteration, DriverID: driverID, DriverSeq: selected.state.Seq, Trigger: triggerSource, StartedAt: cycleStarted, FinishedAt: finishedAt, PlateauReached: true, Error: err.Error()}
			appendHistory(cfg.LogsDir, FuzzIteration{Iteration: st.Iteration, DriverID: driverID, Seq: selected.state.Seq, Trigger: triggerSource, FuzzStatus: selected.status, Coverage: selected.coverage, Error: err.Error(), StartedAt: cycleStarted, FinishedAt: finishedAt})
			emitFlow(FuzzFlowPrechecking, "failed", triggerSource, msg, driverID)
			if err := settleRunningSet(0); err != nil {
				return err
			}
			flow.CycleStarted = nil
			emitFlow(FuzzFlowFuzzing, "idle", "", multiFuzzingIdleMessage(len(running), len(targets), maxParallel, fmt.Sprintf("driver %d 预检失败", driverID)), 0)
			continue
		}
		if len(precheckCov.Uncovered) > 0 {
			selected.coverage = precheckCov
		}

		emitFlow(FuzzFlowAnalyzing, "running", triggerSource, fmt.Sprintf("Codex 正在分析 driver %d 的平台期覆盖卡点", driverID), driverID)
		analyzer := CodexAnalyzer{
			Command:   cfg.CodexCommand,
			Model:     cfg.CodexModel,
			Profile:   cfg.CodexProfile,
			Timeout:   30 * time.Minute,
			Runner:    cfg.Runner,
			EventSink: cfg.EventSink,
			LogSink:   cfg.LogSink,
		}
		response, analysisErr := analyzer.AnalyzeTarget(ctx, TargetAnalysisRequest{
			DriverID:       driverID,
			FuzzStatus:     selected.status,
			CoverageStatus: selected.coverage,
			SourceDir:      cfg.SourceDir,
			WorkDir:        tmpDir,
			BuildScript:    filepath.Join(tmpDir, "build_cov_driver.sh"),
			BinaryPath:     filepath.Join(tmpDir, "cov_driver"),
		}, filepath.Join(tmpDir, "codex-analysis"))

		if analysisErr != nil {
			finishedAt := time.Now()
			cfg.logf("[fuzzing] driver %d Codex analysis failed: %v\n", driverID, analysisErr)
			flow.LastResult = &FuzzFlowResult{Iteration: st.Iteration, DriverID: driverID, DriverSeq: selected.state.Seq, Trigger: triggerSource, StartedAt: cycleStarted, FinishedAt: finishedAt, PlateauReached: true, Error: analysisErr.Error()}
			appendHistory(cfg.LogsDir, FuzzIteration{Iteration: st.Iteration, DriverID: driverID, Seq: selected.state.Seq, Trigger: triggerSource, FuzzStatus: selected.status, Coverage: selected.coverage, Analysis: AnalysisResponse{PlateauReached: true}, Error: analysisErr.Error(), StartedAt: cycleStarted, FinishedAt: finishedAt})
			emitFlow(FuzzFlowAnalyzing, "failed", triggerSource, analysisErr.Error(), driverID)
			if err := settleRunningSet(0); err != nil {
				return err
			}
			flow.CycleStarted = nil
			emitFlow(FuzzFlowFuzzing, "idle", "", multiFuzzingIdleMessage(len(running), len(targets), maxParallel, fmt.Sprintf("driver %d 分析失败", driverID)), 0)
			continue
		}

		emitFlow(FuzzFlowValidating, "running", triggerSource, fmt.Sprintf("正在复核 driver %d 的 proof seed 覆盖效果", driverID), driverID)
		validated := false
		var validationErr error
		if response.NeedsUpdate {
			validationErr = validateTargetAnalysis(ctx, cfg, tmpDir, target, selected.state.SourceHash, response)
			validated = validationErr == nil
		}

		finishedAt := time.Now()
		targetBranchText := formatTargetBranch(response.TargetBranch)
		flow.LastResult = &FuzzFlowResult{
			Iteration: st.Iteration, DriverID: driverID, DriverSeq: selected.state.Seq, Trigger: triggerSource,
			StartedAt: cycleStarted, FinishedAt: finishedAt, PlateauReached: true,
			NeedsUpdate: response.NeedsUpdate, Analysis: response.Analysis, TargetBranch: targetBranchText,
		}

		history := FuzzIteration{
			Iteration: st.Iteration, DriverID: driverID, Seq: selected.state.Seq, Trigger: triggerSource,
			FuzzStatus: selected.status, Coverage: selected.coverage,
			Analysis:  AnalysisResponse{PlateauReached: true, NeedsUpdate: response.NeedsUpdate, Analysis: response.Analysis},
			StartedAt: cycleStarted, FinishedAt: finishedAt,
		}

		if response.NeedsUpdate && !validated {
			history.Error = validationErr.Error()
			flow.LastResult.Error = validationErr.Error()
			appendHistory(cfg.LogsDir, history)
			emitFlow(FuzzFlowValidating, "failed", triggerSource, validationErr.Error(), driverID)
			if err := settleRunningSet(0); err != nil {
				return err
			}
			flow.CycleStarted = nil
			emitFlow(FuzzFlowFuzzing, "idle", "", multiFuzzingIdleMessage(len(running), len(targets), maxParallel, fmt.Sprintf("driver %d proof seed 复核失败，未创建新快照", driverID)), 0)
			continue
		}
		if !response.NeedsUpdate {
			appendHistory(cfg.LogsDir, history)
			emitFlow(FuzzFlowApplying, "idle", triggerSource, fmt.Sprintf("driver %d 本轮无需修改", driverID), driverID)
			if err := settleRunningSet(0); err != nil {
				return err
			}
			flow.CycleStarted = nil
			emitFlow(FuzzFlowFuzzing, "idle", "", multiFuzzingIdleMessage(len(running), len(targets), maxParallel, fmt.Sprintf("driver %d 本轮无需修改", driverID)), 0)
			continue
		}

		emitFlow(FuzzFlowPromoting, "running", triggerSource, fmt.Sprintf("driver %d 验证通过，正在转正为新快照", driverID), driverID)
		if err := promoteTargetSnapshot(cfg, st, target, running[driverID], tmpDir); err != nil {
			history.Error = err.Error()
			flow.LastResult.Error = err.Error()
			appendHistory(cfg.LogsDir, history)
			emitFlow(FuzzFlowPromoting, "failed", triggerSource, err.Error(), driverID)
			if err := settleRunningSet(0); err != nil {
				return err
			}
			flow.CycleStarted = nil
			emitFlow(FuzzFlowFuzzing, "idle", "", multiFuzzingIdleMessage(len(running), len(targets), maxParallel, fmt.Sprintf("driver %d 转正失败，旧版本继续运行", driverID)), 0)
			continue
		}
		history.Regenerated = true
		flow.LastResult.Regenerated = true
		appendHistory(cfg.LogsDir, history)
		delete(running, driverID)
		if err := st.Save(statePath); err != nil {
			cfg.logf("[fuzzing] multi state save failed: %v\n", err)
		}

		emitFlow(FuzzFlowRestarting, "running", triggerSource, fmt.Sprintf("正在重启 driver %d 的 fuzz 进程", driverID), driverID)
		rt, err := startRunningTarget(ctx, cfg, st.Targets[driverID])
		if err != nil {
			st.Targets[driverID].Status = "start_failed"
			st.Targets[driverID].LastError = err.Error()
			emitFlow(FuzzFlowRestarting, "failed", triggerSource, err.Error(), driverID)
			if err := settleRunningSet(0); err != nil {
				return err
			}
			flow.CycleStarted = nil
			emitFlow(FuzzFlowFuzzing, "idle", "", multiFuzzingIdleMessage(len(running), len(targets), maxParallel, fmt.Sprintf("driver %d 重启失败", driverID)), 0)
			continue
		}
		rt.startedIteration = st.Iteration
		running[driverID] = rt
		if err := settleRunningSet(driverID); err != nil {
			return err
		}
		flow.CycleStarted = nil
		emitFlow(FuzzFlowFuzzing, "idle", "", multiFuzzingIdleMessage(len(running), len(targets), maxParallel, fmt.Sprintf("driver %d 已升级到 v%d", driverID, st.Targets[driverID].Seq)), 0)
	}
}

func DiscoverFuzzTargets(driverDir string) ([]FuzzTarget, error) {
	entries, err := os.ReadDir(driverDir)
	if err != nil {
		return nil, err
	}
	var targets []FuzzTarget
	for _, entry := range entries {
		if entry.IsDir() || !isCompiledDriverSource(entry.Name()) {
			continue
		}
		base := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		if !strings.HasPrefix(base, "fuzz_driver_") {
			continue
		}
		driverID, err := strconv.Atoi(strings.TrimPrefix(base, "fuzz_driver_"))
		if err != nil || driverID <= 0 {
			continue
		}
		targets = append(targets, FuzzTarget{
			DriverID:    driverID,
			Source:      filepath.Join(driverDir, entry.Name()),
			BuildScript: filepath.Join(driverDir, fmt.Sprintf("build_fuzz_driver_%d.sh", driverID)),
		})
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].DriverID < targets[j].DriverID })
	return targets, nil
}

func ensureInitialTargetSnapshots(ctx context.Context, cfg FuzzConfig, st *MultiFuzzState, targets []FuzzTarget) error {
	for _, target := range targets {
		targetState := st.Targets[target.DriverID]
		if targetState != nil && targetSnapshotUsesRootDriver(targetState.CurrentSnapshot, target) {
			if targetState.BinaryPath == "" {
				targetState.BinaryPath = filepath.Join(targetState.CurrentSnapshot, "cov_driver")
			}
			if !fileExists(targetState.BinaryPath) {
				if err := buildTargetSnapshot(ctx, cfg, targetState.CurrentSnapshot, "rebuild-current"); err != nil {
					targetState.Status = "build_failed"
					targetState.LastError = err.Error()
					cfg.logf("[fuzzing] driver %d current snapshot rebuild failed: %v\n", target.DriverID, err)
					continue
				}
			}
			seq := targetState.Seq
			if seq <= 0 {
				seq = 1
			}
			updateTargetStateFromSnapshot(targetState, target, targetState.CurrentSnapshot, seq)
			targetState.Status = "ready"
			targetState.LastError = ""
			continue
		}

		if targetState != nil && targetState.CurrentSnapshot != "" {
			cfg.logf("[fuzzing] driver %d ignores legacy evolved snapshot %s; rebuilding v1 from %s\n", target.DriverID, targetState.CurrentSnapshot, target.Source)
		}

		snapDir := targetSnapshotDir(cfg.LogsDir, target.DriverID, 1)
		if targetState == nil {
			targetState = &TargetState{DriverID: target.DriverID, Seq: 1}
			st.Targets[target.DriverID] = targetState
		} else {
			targetState.Seq = 1
			targetState.CurrentSnapshot = ""
			targetState.Source = ""
			targetState.SourceHash = ""
			targetState.BinaryPath = ""
			targetState.CorpusDir = ""
			targetState.CoverageHistory = nil
			targetState.LastCoverage = nil
			targetState.LastLLMIteration = 0
		}
		if err := prepareTargetSnapshot(cfg.DriverDir, cfg.BuildScript, target, snapDir); err != nil {
			targetState.Status = "build_failed"
			targetState.LastError = err.Error()
			cfg.logf("[fuzzing] driver %d initial snapshot prepare failed: %v\n", target.DriverID, err)
			continue
		}
		if err := buildTargetSnapshot(ctx, cfg, snapDir, "build-initial"); err != nil {
			targetState.Status = "build_failed"
			targetState.LastError = err.Error()
			cfg.logf("[fuzzing] driver %d initial build failed: %v\n", target.DriverID, err)
			continue
		}
		updateTargetStateFromSnapshot(targetState, target, snapDir, 1)
		targetState.Status = "ready"
		targetState.LastError = ""
	}
	if err := splitUnifiedCorpusOnce(cfg, targets, st); err != nil {
		cfg.logf("[fuzzing] corpus split failed: %v\n", err)
	}
	return nil
}

func prepareTargetSnapshot(driverDir, templateBuildScript string, target FuzzTarget, snapDir string) error {
	if err := os.MkdirAll(filepath.Join(snapDir, "driver"), 0o755); err != nil {
		return err
	}
	for _, dir := range []string{"corpus", "monitor", "crashes", "unique_crashes"} {
		if err := os.MkdirAll(filepath.Join(snapDir, dir), 0o755); err != nil {
			return err
		}
	}
	if err := copyFile(target.Source, filepath.Join(snapDir, "driver", filepath.Base(target.Source))); err != nil {
		return err
	}
	return writeTargetBuildScript(driverDir, templateBuildScript, target, snapDir)
}

func writeTargetBuildScript(driverDir, templateBuildScript string, target FuzzTarget, snapDir string) error {
	sourceBuildScript := target.BuildScript
	if !fileExists(sourceBuildScript) {
		sourceBuildScript = templateBuildScript
	}
	data, err := os.ReadFile(sourceBuildScript)
	if err != nil {
		return err
	}
	content := string(data)
	targetSource := filepath.Join(snapDir, "driver", filepath.Base(target.Source))
	replacedSource := false
	for _, old := range []string{
		target.Source,
		filepath.Join(driverDir, "synthesized", "*.c"),
		filepath.Join(driverDir, "synthesized", "*.cc"),
		filepath.Join(driverDir, "synthesized", "*.cpp"),
		filepath.Join(driverDir, "synthesized", "*.cxx"),
		filepath.Join(driverDir, "synthesized", "*"),
		"synthesized/*.c",
		"synthesized/*.cc",
		"synthesized/*.cpp",
		"synthesized/*.cxx",
	} {
		var replaced bool
		content, replaced = replaceBuildArgument(content, old, shellQuote(targetSource))
		replacedSource = replacedSource || replaced
	}
	if !replacedSource {
		var replaced bool
		content, replaced = replaceBuildArgument(content, filepath.Base(target.Source), shellQuote(targetSource))
		replacedSource = replaced
	}
	if !replacedSource {
		return fmt.Errorf("cannot rewrite child driver source in %s", sourceBuildScript)
	}
	targetOutput := shellQuote(filepath.Join(snapDir, "cov_driver"))
	for _, old := range []string{
		filepath.Join(driverDir, "cov_synthesized_driver"),
		filepath.Join(driverDir, fmt.Sprintf("fuzz_driver_%d", target.DriverID)),
		filepath.Join(driverDir, fmt.Sprintf("cov_fuzz_driver_%d", target.DriverID)),
		"fuzz_driver_" + strconv.Itoa(target.DriverID),
		"cov_fuzz_driver_" + strconv.Itoa(target.DriverID),
	} {
		content = replaceOutputArgument(content, old, targetOutput)
	}
	if !strings.Contains(content, "-fprofile-instr-generate") {
		content = strings.Replace(content, " -o ", " -fprofile-instr-generate -fcoverage-mapping -o ", 1)
	}
	if !strings.Contains(content, "-fsanitize=fuzzer,address") {
		content = strings.Replace(content, "-fsanitize=fuzzer ", "-fsanitize=fuzzer,address ", 1)
	}
	path := filepath.Join(snapDir, "build_cov_driver.sh")
	return os.WriteFile(path, []byte(content), 0o755)
}

func buildTargetSnapshot(ctx context.Context, cfg FuzzConfig, snapDir, name string) error {
	buildScript := filepath.Join(snapDir, "build_cov_driver.sh")
	patchBuildScript(buildScript)
	buildCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if _, err := cfg.Runner.Run(buildCtx, snapDir, name, snapDir, nil, buildScript); err != nil {
		return err
	}
	if !fileExists(filepath.Join(snapDir, "cov_driver")) {
		return fmt.Errorf("target build script did not produce %s", filepath.Join(snapDir, "cov_driver"))
	}
	return nil
}

func updateTargetStateFromSnapshot(targetState *TargetState, target FuzzTarget, snapDir string, seq int) {
	targetState.DriverID = target.DriverID
	targetState.Seq = seq
	targetState.Source = filepath.Join(snapDir, "driver", filepath.Base(target.Source))
	targetState.CurrentSnapshot = snapDir
	targetState.BinaryPath = filepath.Join(snapDir, "cov_driver")
	targetState.CorpusDir = filepath.Join(snapDir, "corpus")
	if hash, err := driverSourceHash(filepath.Join(snapDir, "driver")); err == nil {
		targetState.SourceHash = hash
	}
}

func targetSnapshotUsesRootDriver(snapDir string, target FuzzTarget) bool {
	if snapDir == "" || target.Source == "" {
		return false
	}
	targetSource := filepath.Join(snapDir, "driver", filepath.Base(target.Source))
	if !fileExists(targetSource) {
		return false
	}
	buildScript := filepath.Join(snapDir, "build_cov_driver.sh")
	data, err := os.ReadFile(buildScript)
	if err != nil {
		return false
	}
	content := string(data)
	if strings.Contains(content, "wrapper.c") ||
		strings.Contains(content, "synthesized/*.") ||
		strings.Contains(content, filepath.Join(snapDir, "synthesized")) {
		return false
	}
	return strings.Contains(content, targetSource) || strings.Contains(content, filepath.Base(target.Source))
}

func splitUnifiedCorpusOnce(cfg FuzzConfig, targets []FuzzTarget, st *MultiFuzzState) error {
	marker := filepath.Join(cfg.LogsDir, "driver-targets", ".corpus-migrated")
	if fileExists(marker) {
		return nil
	}
	sourceCorpus := filepath.Join(cfg.DriverDir, "corpus")
	entries, err := os.ReadDir(sourceCorpus)
	if err != nil {
		if os.IsNotExist(err) {
			return os.WriteFile(marker, []byte(time.Now().Format(time.RFC3339)+"\n"), 0o644)
		}
		return err
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].DriverID < targets[j].DriverID })
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(sourceCorpus, entry.Name()))
		if err != nil || len(data) == 0 {
			continue
		}
		index := int(data[0]) % len(targets)
		driverID := targets[index].DriverID
		targetState := st.Targets[driverID]
		if targetState == nil || targetState.CorpusDir == "" {
			continue
		}
		payload := data[1:]
		sum := sha1.Sum(payload)
		name := hex.EncodeToString(sum[:])
		if err := os.WriteFile(filepath.Join(targetState.CorpusDir, name), payload, 0o644); err != nil {
			return err
		}
	}
	return os.WriteFile(marker, []byte(time.Now().Format(time.RFC3339)+"\n"), 0o644)
}

func startRunningTarget(ctx context.Context, parent FuzzConfig, targetState *TargetState) (*runningTarget, error) {
	targetCtx, cancel := context.WithCancel(ctx)
	targetCfg := parent
	targetCfg.DriverDir = targetState.CurrentSnapshot
	targetCfg.BuildScript = filepath.Join(targetState.CurrentSnapshot, "build_cov_driver.sh")
	targetCfg.BinaryPath = targetState.BinaryPath
	targetCfg.CorpusDir = targetState.CorpusDir
	targetCfg.ForkWorkers = 1
	targetCfg.OnMonitorChanged = nil
	targetCfg.OnCoverageChanged = nil
	tracker := NewFuzzStatusTracker()
	stderrPath := filepath.Join(targetState.CurrentSnapshot, "fuzz.stderr.log")
	stdoutPath := filepath.Join(targetState.CurrentSnapshot, "fuzz.stdout.log")
	if err := startFuzzer(targetCtx, targetCfg, targetState.CurrentSnapshot, stderrPath, stdoutPath, tracker); err != nil {
		cancel()
		return nil, err
	}
	monitor := NewCorpusMonitor(targetCfg, filepath.Join(targetState.CurrentSnapshot, "monitor"))
	monitor.Start(targetCtx)
	targetState.Status = "running"
	targetState.LastError = ""
	return &runningTarget{state: targetState, cfg: targetCfg, cancel: cancel, tracker: tracker, monitor: monitor}, nil
}

func stopRunningTarget(rt *runningTarget) {
	if rt == nil {
		return
	}
	if rt.cancel != nil {
		rt.cancel()
	}
	if rt.monitor != nil {
		rt.monitor.Stop()
	}
}

func resolveMultiFuzzParallelism(cfg FuzzConfig, totalTargets int) int {
	if totalTargets <= 0 {
		return 0
	}
	limit := cfg.MaxParallelDrivers
	if limit <= 0 {
		limit = runtime.NumCPU()
	}
	if limit < 1 {
		limit = 1
	}
	if limit > totalTargets {
		limit = totalTargets
	}
	return limit
}

func fillRunningTargets(ctx context.Context, cfg FuzzConfig, st *MultiFuzzState, targets []FuzzTarget, running map[int]*runningTarget, maxParallel, iteration int) int {
	if maxParallel <= 0 || len(running) >= maxParallel || len(targets) == 0 {
		return 0
	}
	started := 0
	attempts := 0
	for len(running) < maxParallel && attempts < len(targets) {
		if err := ctx.Err(); err != nil {
			return started
		}
		idx := st.NextTargetIndex % len(targets)
		st.NextTargetIndex = (idx + 1) % len(targets)
		attempts++
		target := targets[idx]
		if _, ok := running[target.DriverID]; ok {
			continue
		}
		targetState := st.Targets[target.DriverID]
		if targetState == nil || targetState.Status == "build_failed" || targetState.Status == "start_failed" {
			continue
		}
		rt, err := startRunningTarget(ctx, cfg, targetState)
		if err != nil {
			targetState.Status = "start_failed"
			targetState.LastError = err.Error()
			cfg.logf("[fuzzing] driver %d start failed: %v\n", target.DriverID, err)
			continue
		}
		rt.startedIteration = iteration
		running[target.DriverID] = rt
		started++
	}
	return started
}

func rotateExpiredTargets(cfg FuzzConfig, running map[int]*runningTarget, iteration, protectedDriverID int) int {
	rotated := 0
	for driverID, rt := range running {
		if driverID == protectedDriverID {
			continue
		}
		if iteration-rt.startedIteration < defaultMultiFuzzWindowCycles {
			continue
		}
		stopRunningTarget(rt)
		rt.state.Status = "queued"
		delete(running, driverID)
		rotated++
		cfg.logf("[fuzzing] driver %d yielded fuzz slot after %d cycle(s)\n", driverID, iteration-rt.startedIteration)
	}
	return rotated
}

func markQueuedTargets(st *MultiFuzzState, targets []FuzzTarget, running map[int]*runningTarget) {
	for _, target := range targets {
		targetState := st.Targets[target.DriverID]
		if targetState == nil {
			continue
		}
		if _, ok := running[target.DriverID]; ok {
			continue
		}
		switch targetState.Status {
		case "", "ready", "running":
			targetState.Status = "queued"
		}
	}
}

func multiFuzzingIdleMessage(active, total, maxParallel int, suffix string) string {
	base := fmt.Sprintf("%d/%d 个子 driver 正在运行（并发上限 %d）", active, total, maxParallel)
	if strings.TrimSpace(suffix) == "" {
		return base
	}
	return base + "，" + suffix
}

func collectMultiCycleData(cfg FuzzConfig, running map[int]*runningTarget, iteration int) []targetCycleData {
	var out []targetCycleData
	ids := make([]int, 0, len(running))
	for id := range running {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		rt := running[id]
		status := rt.tracker.Snapshot()
		var cov CorpusCoverageStatus
		if rt.monitor != nil {
			if snapshot, err := rt.monitor.Snapshot(cfg.SourceDir, cfg.BuildDir, cfg.logf); err == nil {
				cov = snapshot
			} else {
				cfg.logf("[fuzzing] driver %d coverage snapshot failed: %v\n", id, err)
			}
		}
		cache := CoverageSnapshot{}
		if rt.monitor != nil {
			cache = rt.monitor.CoverageCache()
		}
		point := coveragePointFromCorpus(iteration, cov)
		rt.state.LastCoverage = &point
		rt.state.CoverageHistory = append(rt.state.CoverageHistory, point)
		if len(rt.state.CoverageHistory) > 20 {
			rt.state.CoverageHistory = rt.state.CoverageHistory[len(rt.state.CoverageHistory)-20:]
		}
		plateau := targetReachedPlateau(rt.state.CoverageHistory)
		out = append(out, targetCycleData{
			state: rt.state, status: status, coverage: cov, cache: cache,
			plateau: plateau,
		})
	}
	return out
}

func collectMultiLiveData(running map[int]*runningTarget, iteration int) []targetCycleData {
	var out []targetCycleData
	ids := make([]int, 0, len(running))
	for id := range running {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		rt := running[id]
		status := rt.tracker.Snapshot()
		cache := CoverageSnapshot{}
		if rt.monitor != nil {
			cache = rt.monitor.CoverageCache()
		}
		cov := CorpusCoverageStatus{CorpusDir: rt.state.CorpusDir}
		if cache.Available {
			cov = CoverageStatusToCorpusCoverage(cache.Coverage, cache.SeedCount, false, rt.state.CorpusDir)
			point := coveragePointFromCorpus(iteration, cov)
			rt.state.LastCoverage = &point
		} else if rt.state.LastCoverage != nil {
			cov.Summary = CoverageSummary{
				ExecutedFunctions: rt.state.LastCoverage.ExecutedFunctions,
				FullFunctions:     rt.state.LastCoverage.FullFunctions,
				PartialFunctions:  rt.state.LastCoverage.PartialFunctions,
			}
		}
		out = append(out, targetCycleData{
			state: rt.state, status: status, coverage: cov, cache: cache,
			plateau: targetReachedPlateau(rt.state.CoverageHistory),
		})
	}
	return out
}

func coveragePointFromCorpus(iteration int, cov CorpusCoverageStatus) CoverageSummaryPoint {
	return CoverageSummaryPoint{
		Iteration: iteration, Timestamp: time.Now(),
		ExecutedFunctions: cov.Summary.ExecutedFunctions,
		FullFunctions:     cov.Summary.FullFunctions,
		PartialFunctions:  cov.Summary.PartialFunctions,
		UncoveredCount:    len(cov.Uncovered),
	}
}

func targetReachedPlateau(history []CoverageSummaryPoint) bool {
	if len(history) < 3 {
		return false
	}
	a := history[len(history)-3]
	b := history[len(history)-2]
	c := history[len(history)-1]
	return !coverageImproved(a, b) && !coverageImproved(b, c)
}

func coverageImproved(prev, next CoverageSummaryPoint) bool {
	if next.ExecutedFunctions > prev.ExecutedFunctions {
		return true
	}
	if next.FullFunctions > prev.FullFunctions {
		return true
	}
	if next.PartialFunctions > prev.PartialFunctions {
		return true
	}
	if prev.UncoveredCount > 0 && next.UncoveredCount < prev.UncoveredCount {
		return true
	}
	return false
}

func selectPlateauTarget(data []targetCycleData) *targetCycleData {
	var selected *targetCycleData
	for i := range data {
		item := &data[i]
		if !item.plateau || len(item.coverage.Uncovered) == 0 {
			continue
		}
		if selected == nil || len(item.coverage.Uncovered) > len(selected.coverage.Uncovered) ||
			(len(item.coverage.Uncovered) == len(selected.coverage.Uncovered) && item.state.DriverID < selected.state.DriverID) {
			selected = item
		}
	}
	return selected
}

func buildMultiCoverageSnapshot(data []targetCycleData, st *MultiFuzzState, targets []FuzzTarget, maxParallel int, fuzzInterval time.Duration, nextAnalysisAt time.Time) MultiCoverageSnapshot {
	snapshot := MultiCoverageSnapshot{
		Timestamp:                time.Now(),
		Mode:                     "multi",
		Iteration:                st.Iteration,
		MaxParallelTargets:       maxParallel,
		RunningTargets:           []int{},
		QueuedTargets:            []int{},
		NextTargets:              []int{},
		FuzzIntervalSeconds:      int64(fuzzInterval / time.Second),
		AnalysisRemainingSeconds: remainingSeconds(nextAnalysisAt),
		Targets:                  []TargetCoverageSnapshot{},
	}
	if !nextAnalysisAt.IsZero() {
		next := nextAnalysisAt
		snapshot.NextAnalysisAt = &next
	}
	runningTargets, queuedTargets := schedulerTargetQueues(st, targets)
	snapshot.RunningTargets = runningTargets
	snapshot.QueuedTargets = queuedTargets
	snapshot.ActiveTargets = len(runningTargets)
	if maxParallel > 0 {
		nextLimit := maxParallel
		if nextLimit > len(queuedTargets) {
			nextLimit = len(queuedTargets)
		}
		snapshot.NextTargets = append(snapshot.NextTargets, queuedTargets[:nextLimit]...)
	}
	var coverages []CoverageStatus
	seen := map[int]bool{}
	for _, item := range data {
		seen[item.state.DriverID] = true
		if item.cache.Available {
			coverages = append(coverages, CloneCoverageStatus(item.cache.Coverage))
			snapshot.Available = true
			snapshot.SeedCount += item.cache.SeedCount
		}
		snapshot.Targets = append(snapshot.Targets, TargetCoverageSnapshot{
			DriverID: item.state.DriverID, Seq: item.state.Seq, Status: item.state.Status,
			Available: item.cache.Available, SeedCount: item.cache.SeedCount,
			CorpusDir: item.state.CorpusDir, Summary: item.coverage.Summary, Coverage: CloneCoverageStatus(item.cache.Coverage),
			UncoveredCount: len(item.coverage.Uncovered),
			Plateau:        item.plateau, FuzzStatus: item.status,
		})
	}
	for _, target := range targets {
		if seen[target.DriverID] {
			continue
		}
		targetState := st.Targets[target.DriverID]
		if targetState == nil {
			continue
		}
		summary := CoverageSummary{}
		uncoveredCount := 0
		if targetState.LastCoverage != nil {
			summary = CoverageSummary{
				ExecutedFunctions: targetState.LastCoverage.ExecutedFunctions,
				FullFunctions:     targetState.LastCoverage.FullFunctions,
				PartialFunctions:  targetState.LastCoverage.PartialFunctions,
			}
			uncoveredCount = targetState.LastCoverage.UncoveredCount
		}
		snapshot.Targets = append(snapshot.Targets, TargetCoverageSnapshot{
			DriverID: targetState.DriverID, Seq: targetState.Seq, Status: targetState.Status,
			Available: false, CorpusDir: targetState.CorpusDir, Summary: summary,
			UncoveredCount: uncoveredCount,
			Plateau:        targetReachedPlateau(targetState.CoverageHistory),
		})
	}
	sort.Slice(snapshot.Targets, func(i, j int) bool { return snapshot.Targets[i].DriverID < snapshot.Targets[j].DriverID })
	snapshot.Coverage = unionCoverageStatuses(coverages)
	return snapshot
}

func remainingSeconds(deadline time.Time) int64 {
	if deadline.IsZero() {
		return 0
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0
	}
	return int64((remaining + time.Second - 1) / time.Second)
}

func schedulerTargetQueues(st *MultiFuzzState, targets []FuzzTarget) ([]int, []int) {
	if len(targets) == 0 {
		return nil, nil
	}
	var running []int
	for _, target := range targets {
		targetState := st.Targets[target.DriverID]
		if targetState != nil && targetState.Status == "running" {
			running = append(running, target.DriverID)
		}
	}
	sort.Ints(running)

	var queued []int
	start := st.NextTargetIndex % len(targets)
	if start < 0 {
		start = 0
	}
	for offset := 0; offset < len(targets); offset++ {
		target := targets[(start+offset)%len(targets)]
		targetState := st.Targets[target.DriverID]
		if targetState == nil {
			continue
		}
		switch targetState.Status {
		case "build_failed", "start_failed", "running":
			continue
		default:
			queued = append(queued, target.DriverID)
		}
	}
	return running, queued
}

func unionCoverageStatuses(statuses []CoverageStatus) CoverageStatus {
	type key struct {
		fn   string
		file string
	}
	full := map[key]FunctionCoverage{}
	partial := map[key]PartialFunctionCoverage{}
	for _, status := range statuses {
		for _, fc := range status.Full {
			k := key{fn: fc.Function, file: fc.File}
			full[k] = fc
			delete(partial, k)
		}
		for _, pc := range status.Partial {
			k := key{fn: pc.Function, file: pc.File}
			if _, ok := full[k]; ok {
				continue
			}
			existing := partial[k]
			if existing.Function == "" {
				existing = CloneCoverageStatus(CoverageStatus{Partial: []PartialFunctionCoverage{pc}}).Partial[0]
			} else {
				existing.EntryCount += pc.EntryCount
				existing.UncoveredBranches = mergeUncoveredBranches(existing.UncoveredBranches, pc.UncoveredBranches)
			}
			partial[k] = existing
		}
	}
	out := CoverageStatus{Full: []FunctionCoverage{}, Partial: []PartialFunctionCoverage{}}
	for _, fc := range full {
		out.Full = append(out.Full, fc)
	}
	for _, pc := range partial {
		out.Partial = append(out.Partial, pc)
	}
	sort.Slice(out.Full, func(i, j int) bool { return out.Full[i].Function < out.Full[j].Function })
	sort.Slice(out.Partial, func(i, j int) bool { return out.Partial[i].Function < out.Partial[j].Function })
	out.Summary = CoverageSummary{
		ExecutedFunctions: len(out.Full) + len(out.Partial),
		FullFunctions:     len(out.Full),
		PartialFunctions:  len(out.Partial),
	}
	return out
}

func mergeUncoveredBranches(a, b []UncoveredBranch) []UncoveredBranch {
	type key struct {
		line    int
		col     int
		missing string
	}
	seen := map[key]UncoveredBranch{}
	for _, branch := range append(a, b...) {
		k := key{line: branch.Location[0], col: branch.Location[1], missing: branch.Missing}
		if existing, ok := seen[k]; ok {
			if existing.Counts == nil {
				existing.Counts = map[string]int64{}
			}
			for side, count := range branch.Counts {
				existing.Counts[side] += count
			}
			seen[k] = existing
			continue
		}
		branch.Counts = cloneCounts(branch.Counts)
		seen[k] = branch
	}
	out := make([]UncoveredBranch, 0, len(seen))
	for _, branch := range seen {
		out = append(out, branch)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Location[0] != out[j].Location[0] {
			return out[i].Location[0] < out[j].Location[0]
		}
		return out[i].Location[1] < out[j].Location[1]
	})
	return out
}

func prepareLLMWorkDir(ctx context.Context, cfg FuzzConfig, target FuzzTarget, targetState *TargetState, iteration int) (string, CorpusCoverageStatus, error) {
	parent := filepath.Join(cfg.LogsDir, "llm-work", formatDriverID(target.DriverID))
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", CorpusCoverageStatus{}, err
	}
	tmpDir, err := os.MkdirTemp(parent, fmt.Sprintf("iter-%04d-", iteration))
	if err != nil {
		return "", CorpusCoverageStatus{}, err
	}
	if err := copySnapshotForLLM(targetState.CurrentSnapshot, tmpDir); err != nil {
		return tmpDir, CorpusCoverageStatus{}, err
	}
	if err := rewriteSnapshotPaths(tmpDir, targetState.CurrentSnapshot, tmpDir); err != nil {
		return tmpDir, CorpusCoverageStatus{}, err
	}
	if err := buildTargetSnapshot(ctx, cfg, tmpDir, "precheck-build"); err != nil {
		return tmpDir, CorpusCoverageStatus{}, err
	}
	cov, err := collectTargetAggregateCoverage(cfg, targetState.CurrentSnapshot, filepath.Join(tmpDir, "cov_driver"), targetState.BinaryPath, filepath.Join(tmpDir, "corpus"))
	return tmpDir, cov, err
}

func collectTargetAggregateCoverage(cfg FuzzConfig, snapshotDir, binaryPath, fallbackBinaryPath, corpusDir string) (CorpusCoverageStatus, error) {
	profdataPath := filepath.Join(snapshotDir, "monitor", "aggregate.profdata")
	if !fileExists(profdataPath) {
		return CorpusCoverageStatus{CorpusDir: corpusDir}, nil
	}
	cs, err := CollectCoverageStatus(profdataPath, binaryPath, cfg.SourceDir, cfg.BuildDir)
	if err != nil && fallbackBinaryPath != "" && fallbackBinaryPath != binaryPath {
		cs, err = CollectCoverageStatus(profdataPath, fallbackBinaryPath, cfg.SourceDir, cfg.BuildDir)
	}
	if err != nil {
		return CorpusCoverageStatus{}, err
	}
	return CoverageStatusToCorpusCoverage(cs, countCorpusSeeds(corpusDir), false, corpusDir), nil
}

func validateTargetAnalysis(ctx context.Context, cfg FuzzConfig, tmpDir string, target FuzzTarget, currentHash string, response TargetAnalysisResponse) error {
	if response.DriverID != target.DriverID {
		return fmt.Errorf("LLM returned driver_id=%d, expected %d", response.DriverID, target.DriverID)
	}
	if !response.CompilePassed {
		return fmt.Errorf("LLM reported compile_passed=false")
	}
	if !response.BranchCovered {
		return fmt.Errorf("LLM reported branch_covered=false")
	}
	if response.TargetBranch.Function == "" || response.TargetBranch.Line <= 0 || response.TargetBranch.Missing == "" {
		return fmt.Errorf("LLM did not return a concrete target branch")
	}
	if err := validateChangedFiles(tmpDir, target, response.ChangedFiles); err != nil {
		return err
	}
	if currentHash != "" {
		updatedHash, err := driverSourceHash(filepath.Join(tmpDir, "driver"))
		if err != nil {
			return err
		}
		if updatedHash == currentHash {
			return fmt.Errorf("LLM reported an update but target driver source did not change")
		}
	}
	if err := buildTargetSnapshot(ctx, cfg, tmpDir, "validate-build"); err != nil {
		return fmt.Errorf("validate build: %w", err)
	}
	seedPath, err := resolveProofSeed(tmpDir, response.ProofSeed)
	if err != nil {
		return err
	}
	covered, err := verifyProofSeedCoversBranch(ctx, cfg, tmpDir, filepath.Join(tmpDir, "cov_driver"), seedPath, response.TargetBranch)
	if err != nil {
		return err
	}
	if !covered {
		return fmt.Errorf("proof seed did not cover target branch %s", formatTargetBranch(response.TargetBranch))
	}
	return nil
}

func validateChangedFiles(tmpDir string, target FuzzTarget, changed []string) error {
	if len(changed) == 0 {
		return fmt.Errorf("LLM reported an update but changed_files is empty")
	}
	targetSource := filepath.Join(tmpDir, "driver", filepath.Base(target.Source))
	allowed := map[string]bool{
		targetSource: true,
		filepath.Join(tmpDir, "build_cov_driver.sh"): true,
	}
	for _, raw := range changed {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		path := raw
		if !filepath.IsAbs(path) {
			path = filepath.Join(tmpDir, path)
		}
		clean, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if !isPathUnder(clean, tmpDir) {
			return fmt.Errorf("changed file escapes temp dir: %s", raw)
		}
		if !allowed[filepath.Clean(clean)] {
			return fmt.Errorf("changed file is outside allowed target files: %s", raw)
		}
	}
	return nil
}

func resolveProofSeed(tmpDir, proofSeed string) (string, error) {
	if strings.TrimSpace(proofSeed) == "" {
		return "", fmt.Errorf("LLM did not provide proof_seed")
	}
	path := proofSeed
	if !filepath.IsAbs(path) {
		path = filepath.Join(tmpDir, path)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if !isPathUnder(abs, tmpDir) {
		return "", fmt.Errorf("proof_seed escapes temp dir: %s", proofSeed)
	}
	if !fileExists(abs) {
		return "", fmt.Errorf("proof_seed not found: %s", proofSeed)
	}
	return abs, nil
}

func verifyProofSeedCoversBranch(ctx context.Context, cfg FuzzConfig, driverDir, binaryPath, seedPath string, branch TargetBranch) (bool, error) {
	workDir := filepath.Join(driverDir, "go-proof")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return false, err
	}
	reach, ok := runSeedCoverage(ctx, binaryPath, cfg.SourceDir, cfg.BuildDir, driverDir, seedPath, workDir, 0)
	if !ok {
		return false, fmt.Errorf("proof seed produced no usable coverage profile")
	}
	if !branchReached(reach, branch) {
		return false, nil
	}
	profdataPath := filepath.Join(workDir, "seed-0.profdata")
	status, err := CollectCoverageStatus(profdataPath, binaryPath, cfg.SourceDir, cfg.BuildDir)
	if err != nil {
		return false, err
	}
	return branchMissingDirectionCovered(status, branch), nil
}

func branchReached(reach map[string]map[[2]int]bool, branch TargetBranch) bool {
	locs := reach[branch.Function]
	if len(locs) == 0 {
		return false
	}
	if branch.Column > 0 {
		return locs[[2]int{branch.Line, branch.Column}]
	}
	for loc := range locs {
		if loc[0] == branch.Line {
			return true
		}
	}
	return false
}

func branchMissingDirectionCovered(status CoverageStatus, branch TargetBranch) bool {
	functionExecuted := false
	for _, fc := range status.Full {
		if coverageFunctionMatches(fc.Function, fc.File, branch) {
			return true
		}
	}
	for _, pc := range status.Partial {
		if !coverageFunctionMatches(pc.Function, pc.File, branch) {
			continue
		}
		functionExecuted = true
		for _, uncovered := range pc.UncoveredBranches {
			if branchMatches(uncovered, branch) && uncovered.Missing == branch.Missing {
				return false
			}
		}
		return true
	}
	return functionExecuted
}

func coverageFunctionMatches(function, file string, branch TargetBranch) bool {
	if function != branch.Function {
		return false
	}
	if branch.File == "" {
		return true
	}
	return filepath.Clean(file) == filepath.Clean(branch.File) || filepath.Base(file) == filepath.Base(branch.File)
}

func branchMatches(uncovered UncoveredBranch, branch TargetBranch) bool {
	if uncovered.Location[0] != branch.Line {
		return false
	}
	return branch.Column <= 0 || uncovered.Location[1] == branch.Column
}

func promoteTargetSnapshot(cfg FuzzConfig, st *MultiFuzzState, target FuzzTarget, current *runningTarget, tmpDir string) error {
	targetState := st.Targets[target.DriverID]
	if targetState == nil {
		return fmt.Errorf("driver %d state not found", target.DriverID)
	}
	oldCorpus := targetState.CorpusDir
	nextSeq := targetState.Seq + 1
	finalDir := targetSnapshotDir(cfg.LogsDir, target.DriverID, nextSeq)
	if _, err := os.Stat(finalDir); err == nil {
		return fmt.Errorf("target snapshot already exists: %s", finalDir)
	}
	if err := copyDirFiles(oldCorpus, filepath.Join(tmpDir, "corpus"), false); err != nil {
		return err
	}
	if err := rewriteSnapshotPaths(tmpDir, tmpDir, finalDir); err != nil {
		return err
	}
	if err := os.Rename(tmpDir, finalDir); err != nil {
		return err
	}
	stopRunningTarget(current)
	updateTargetStateFromSnapshot(targetState, target, finalDir, nextSeq)
	targetState.Status = "ready"
	targetState.LastLLMIteration = st.Iteration
	targetState.LastError = ""
	return nil
}

func copySnapshotForLLM(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, name := range []string{"driver", "corpus"} {
		if err := copyDir(filepath.Join(src, name), filepath.Join(dst, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	for _, name := range []string{"build_cov_driver.sh"} {
		path := filepath.Join(src, name)
		if fileExists(path) {
			if err := copyFile(path, filepath.Join(dst, name)); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
			continue
		}
		if err := copyFile(srcPath, dstPath); err != nil {
			return err
		}
	}
	return nil
}

func copyDirFiles(src, dst string, overwrite bool) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		dstPath := filepath.Join(dst, entry.Name())
		if !overwrite && fileExists(dstPath) {
			continue
		}
		if err := copyFile(filepath.Join(src, entry.Name()), dstPath); err != nil {
			return err
		}
	}
	return nil
}

func rewriteSnapshotPaths(root, oldBase, newBase string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Base(path) != "build_cov_driver.sh" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := strings.ReplaceAll(string(data), oldBase, newBase)
		return os.WriteFile(path, []byte(content), 0o755)
	})
}

func shellQuote(path string) string {
	return "'" + strings.ReplaceAll(path, "'", "'\\''") + "'"
}

func doubleQuote(path string) string {
	return `"` + strings.ReplaceAll(path, `"`, `\"`) + `"`
}

func replaceBuildArgument(content, old, replacement string) (string, bool) {
	replaced := false
	for _, candidate := range []string{shellQuote(old), doubleQuote(old), old} {
		if strings.Contains(content, candidate) {
			content = strings.ReplaceAll(content, candidate, replacement)
			replaced = true
		}
	}
	return content, replaced
}

func replaceOutputArgument(content, old, replacement string) string {
	for _, candidate := range []string{shellQuote(old), doubleQuote(old), old} {
		content = strings.ReplaceAll(content, " -o "+candidate, " -o "+replacement)
	}
	return content
}

func formatTargetBranch(branch TargetBranch) string {
	data, _ := json.Marshal(branch)
	return string(data)
}
