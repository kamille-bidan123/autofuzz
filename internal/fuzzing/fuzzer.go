package fuzzing

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"autofuzz/internal/runner"
)

// FuzzConfig holds all parameters needed to run the fuzzing phase.
type FuzzConfig struct {
	DriverDir    string        // directory containing the synthesized driver and build scripts
	SourceDir    string        // target library source directory
	BuildDir     string        // out-of-tree build directory (sources may be copied here; llvm-cov reports them under here)
	BuildScript  string        // build_cov_synthesized_driver.sh path
	BinaryPath   string        // cov_synthesized_driver binary path
	CorpusDir    string        // corpus directory for libFuzzer
	Interval     time.Duration // how often to collect status
	CodexCommand string
	CodexModel   string
	CodexProfile string
	Runner       runner.Runner
	LogsDir      string
	EventSink    func(json.RawMessage)
	// MaxSeeds caps how many corpus seeds are replayed per analysis cycle
	// (largest by size). 0 means DefaultMaxCorpusSeeds.
	MaxSeeds int
	// ForkWorkers is the libFuzzer -fork worker count. <=0 means use the
	// number of logical CPUs (nproc).
	ForkWorkers int

	// TriggerCh is an optional channel that, when signaled, causes the
	// fuzz loop to immediately skip the remaining wait and proceed to
	// the analysis phase. Used by the web UI's debug button.
	TriggerCh chan struct{} `json:"-"`

	// LogSink is an optional callback for forwarding log lines to the
	// web UI event stream. If nil, logf falls back to fmt.Printf.
	LogSink func(message string)

	// OnMonitorChanged is called when a CorpusMonitor is started or stopped
	// (nil when stopped). Allows the web UI to access real-time coverage data
	// via the monitor's CoverageCache().
	OnMonitorChanged func(*CorpusMonitor)

	// FlowSink receives structured state transitions for the repeating
	// fuzz/analyze/rebuild loop. The same snapshots are persisted to disk.
	FlowSink func(FuzzFlowSnapshot)
}

// logf prints a formatted message to the LogSink (if set) or stdout.
func (cfg FuzzConfig) logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if cfg.LogSink != nil {
		cfg.LogSink(msg)
	}
	fmt.Println(msg)
}

// FuzzController is returned by RunFuzzingPhaseStart so the caller can
// signal a manual trigger.
type FuzzController struct {
	Trigger chan struct{}
	Done    chan error
}

// StartFuzzingPhase is like RunFuzzingPhase but returns immediately with
// a controller for out-of-band triggering. The caller signals Trigger to
// force an immediate analysis cycle, and receives the final error on Done.
func StartFuzzingPhase(ctx context.Context, cfg FuzzConfig) FuzzController {
	ctrl := FuzzController{
		Trigger: make(chan struct{}, 1),
		Done:    make(chan error, 1),
	}
	if cfg.TriggerCh == nil {
		cfg.TriggerCh = ctrl.Trigger
	}
	go func() {
		ctrl.Done <- RunFuzzingPhase(ctx, cfg)
	}()
	return ctrl
}

// TriggerAnalysis sends a non-blocking signal to the fuzz loop to
// immediately skip the remaining wait and run the LLM analysis. It reports
// whether a new trigger was queued.
func (c FuzzController) TriggerAnalysis() bool {
	select {
	case c.Trigger <- struct{}{}:
		return true
	default:
		return false
	}
}

// FuzzIteration records the results of a single fuzz+analyze+regenerate cycle.
type FuzzIteration struct {
	Iteration   int                  `json:"iteration"`
	Seq         int                  `json:"seq"` // driver version that ran this cycle
	Trigger     string               `json:"trigger,omitempty"`
	FuzzStatus  FuzzStatus           `json:"fuzz_status"`
	Coverage    CorpusCoverageStatus `json:"coverage_status"`
	Analysis    AnalysisResponse     `json:"analysis"`
	Regenerated bool                 `json:"regenerated"`
	Error       string               `json:"error,omitempty"`
	StartedAt   time.Time            `json:"started_at"`
	FinishedAt  time.Time            `json:"finished_at"`
}

// RunFuzzingPhase is the main entry point for the fuzzing phase.
// It runs the coverage-instrumented synthesized driver as a long-running
// fuzzer, collects per-seed coverage each interval (without stopping the
// fuzzer), sends the data to Codex which edits driver sources directly, and on
// a driver change rebuilds + restarts. The phase runs until the fuzzer exits
// or the context is cancelled; plateau no longer stops the loop. On exit,
// crashes across all driver snapshots are triaged against the final binary.
// Crash artifacts land inside the driver version's snapshot dir so every crash
// stays reproducible against the driver version that found it.
func RunFuzzingPhase(ctx context.Context, cfg FuzzConfig) error {
	if err := os.MkdirAll(cfg.LogsDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.CorpusDir, 0o755); err != nil {
		return err
	}

	statePath := filepath.Join(cfg.LogsDir, "fuzzing-state.json")
	flowPath := filepath.Join(cfg.LogsDir, "fuzz-flow.json")
	synthesizedDir := filepath.Join(cfg.DriverDir, "synthesized")

	iteration := 0 // analysis cycle counter (~per interval)
	seq := 0       // driver version counter (only on build)
	needRebuild := true
	lastBuiltHash := ""
	var currentSnapshot string
	flow, _ := LoadFuzzFlow(flowPath)
	if flow == nil {
		flow = &FuzzFlowSnapshot{}
	}
	var pendingHistory *FuzzIteration
	emitFlow := func(phase FuzzFlowPhase, status, trigger, message string) {
		flow.Iteration = iteration
		if phase == FuzzFlowRebuilding && flow.LastResult != nil {
			flow.Iteration = flow.LastResult.Iteration
		}
		flow.DriverSeq = seq
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

	// Resume the fuzzing phase if a checkpoint exists, else scan prior
	// snapshots. We avoid overwriting an existing snapshot when the driver
	// source is unchanged (reuse the binary + snapshot) and only build a new
	// snapshot when the source actually changed.
	if st, _ := LoadFuzzState(statePath); st != nil {
		iteration = st.Iteration
		seq = st.Seq
		lastBuiltHash = st.DriverSourceHash
		currentSnapshot = st.CurrentSnapshot
	} else if n, _ := highestSnapshotSeq(cfg.LogsDir); n > 0 {
		// No checkpoint but snapshots exist (older run): infer the last-built
		// hash from the highest snapshot's synthesized source.
		seq = n
		currentSnapshot = snapshotDirPath(cfg.LogsDir, n)
		if h, err := driverSourceHash(filepath.Join(currentSnapshot, "synthesized")); err == nil {
			lastBuiltHash = h
		}
	}
	// Decide reuse-vs-rebuild by comparing the live source fingerprint to the
	// last-built one. A fresh entry (no state, no snapshots) leaves needRebuild
	// true and seq 0, so the first iteration builds fuzz-001.
	if lastBuiltHash != "" {
		if liveHash, err := driverSourceHash(synthesizedDir); err == nil &&
			liveHash == lastBuiltHash && fileExists(cfg.BinaryPath) &&
			currentSnapshot != "" && fileExists(currentSnapshot) {
			needRebuild = false
			cfg.logf("[fuzzing] resume: driver source unchanged, reusing %s (v%d) without rebuild\n", currentSnapshot, seq)
		} else {
			needRebuild = true
			cfg.logf("[fuzzing] resume: driver source changed or binary/snapshot missing, will build new snapshot\n")
		}
	}

	// persist writes the checkpoint so the next resume continues from here.
	persist := func() {
		st := &FuzzState{
			Iteration:        iteration,
			Seq:              seq,
			DriverSourceHash: lastBuiltHash,
			CurrentSnapshot:  currentSnapshot,
			BinaryPath:       cfg.BinaryPath,
		}
		if err := st.Save(statePath); err != nil {
			cfg.logf("[fuzzing] state save failed: %v\n", err)
		}
	}

	// The fuzzer runs continuously across analysis intervals. These hold the
	// current fuzzer's context/cancel and stderr tracker; they are replaced
	// only when the driver is regenerated (needRebuild path).
	var fuzzCtx context.Context
	var fuzzCancel context.CancelFunc
	var statusTracker *FuzzStatusTracker
	var monitor *CorpusMonitor
	fuzzerRunning := false

	for {
		iteration++
		var snapDir string // set in needRebuild; persistent home of this driver version

		// (Re)build and start the fuzzer when the driver changed, OR start it
		// from the existing binary when resuming with an unchanged driver.
		triggered := false
		needStart := false
		if needRebuild {
			seq++
			snapDir = snapshotDirPath(cfg.LogsDir, seq)
			phase := FuzzFlowStarting
			message := fmt.Sprintf("正在准备 fuzz driver v%d", seq)
			if flow.LastResult != nil && flow.LastResult.NeedsUpdate && !flow.LastResult.Regenerated {
				phase = FuzzFlowRebuilding
				message = fmt.Sprintf("正在重建 fuzz driver v%d", seq)
			}
			emitFlow(phase, "running", flow.Trigger, message)
			if err := os.MkdirAll(snapDir, 0o755); err != nil {
				emitFlow(phase, "failed", flow.Trigger, err.Error())
				return err
			}
			cfg.logf("[fuzzing] iteration %d: building driver v%d (snapshot %s)\n", iteration, seq, snapDir)
			if err := cfg.buildCovDriver(ctx, snapDir); err != nil {
				emitFlow(phase, "failed", flow.Trigger, err.Error())
				return err
			}
			if flow.LastResult != nil && flow.LastResult.NeedsUpdate && !flow.LastResult.Regenerated {
				flow.LastResult.Regenerated = true
				if pendingHistory != nil {
					pendingHistory.Regenerated = true
					appendHistory(cfg.LogsDir, *pendingHistory)
					pendingHistory = nil
				} else {
					result := flow.LastResult
					appendHistory(cfg.LogsDir, FuzzIteration{
						Iteration: result.Iteration, Seq: result.DriverSeq, Trigger: result.Trigger,
						Analysis:    AnalysisResponse{PlateauReached: result.PlateauReached, Analysis: result.Analysis, NeedsUpdate: result.NeedsUpdate},
						Regenerated: true, StartedAt: result.StartedAt, FinishedAt: result.FinishedAt,
					})
				}
			}
			// Snapshot the driver sources that this binary was built from, so
			// any crash found while this driver runs can later be reproduced by
			// rebuilding from this snapshot.
			if err := snapshotDriver(filepath.Join(cfg.DriverDir, "synthesized"), filepath.Join(snapDir, "synthesized")); err != nil {
				cfg.logf("[fuzzing] driver snapshot failed: %v\n", err)
			}
			// Persist the compiled binary and build script alongside the source
			// so the snapshot is self-contained: the monitor profdata and crashes
			// can be re-analyzed / replayed against this exact binary even after
			// later driver versions overwrite the live binary in DriverDir.
			if err := copyFile(cfg.BinaryPath, filepath.Join(snapDir, filepath.Base(cfg.BinaryPath))); err != nil {
				cfg.logf("[fuzzing] binary snapshot failed: %v\n", err)
			}
			if err := copyFile(cfg.BuildScript, filepath.Join(snapDir, filepath.Base(cfg.BuildScript))); err != nil {
				cfg.logf("[fuzzing] build-script snapshot failed: %v\n", err)
			}
			// Record the fingerprint of the source this binary was just built
			// from, so the next resume can detect whether it changed.
			if h, err := driverSourceHash(synthesizedDir); err == nil {
				lastBuiltHash = h
			}
			currentSnapshot = snapDir
			needRebuild = false
			needStart = true
			// Persist immediately after a rebuild so the state reflects the
			// new seq + hash + snapshot even if the run is killed during
			// the subsequent fuzz-wait interval (before the end-of-iteration
			// persist). Without this, a kill mid-interval leaves the state
			// pointing at the OLD seq → an unnecessary rebuild on resume.
			persist()
		} else if !fuzzerRunning {
			// Resume reuse path: driver source unchanged since the last build,
			// so reuse the existing snapshot dir and binary without rebuilding.
			snapDir = currentSnapshot
			cfg.logf("[fuzzing] iteration %d: starting fuzzer on existing driver v%d (snapshot %s), no rebuild\n", iteration, seq, snapDir)
			needStart = true
		} else {
			snapDir = snapshotDirPath(cfg.LogsDir, seq)
			cfg.logf("[fuzzing] iteration %d: fuzzer still running on driver v%d, no rebuild\n", iteration, seq)
		}
		if needStart {
			var err error
			fuzzCtx, fuzzCancel, statusTracker, triggered, err = cfg.startFuzzerAndWaitInit(ctx, snapDir)
			if err != nil {
				return err
			}
			// Start a background corpus monitor that incrementally replays new
			// seeds and maintains a running aggregate profdata, so that the
			// LLM analysis cycle can take coverage data instantly.
			if monitor != nil {
				if cfg.OnMonitorChanged != nil {
					cfg.OnMonitorChanged(nil)
				}
				monitor.Stop()
			}
			monitor = NewCorpusMonitor(cfg, filepath.Join(snapDir, "monitor"))
			monitor.Start(ctx)
			if cfg.OnMonitorChanged != nil {
				cfg.OnMonitorChanged(monitor)
			}
			fuzzerRunning = true
			flow.CycleStarted = nil
			emitFlow(FuzzFlowFuzzing, "idle", "", fmt.Sprintf("fuzz driver v%d 持续运行，等待下一轮分析", seq))
		}

		// Run for the configured interval (or until manually triggered).
		// The fuzzer keeps running; we do NOT stop it to collect coverage.
		triggerSource := "interval"
		if triggered {
			triggerSource = "manual"
			cfg.logf("[fuzzing] iteration %d: skipping fuzz wait (triggered during INIT)\n", iteration)
		} else {
			cfg.logf("[fuzzing] iteration %d: fuzzing for %s (or click trigger button)\n", iteration, cfg.Interval)
			timer := time.NewTimer(cfg.Interval)
			select {
			case <-timer.C:
				cfg.logf("[fuzzing] iteration %d: interval elapsed, proceeding to analysis\n", iteration)
			case <-cfg.TriggerCh:
				timer.Stop()
				triggerSource = "manual"
				cfg.logf("[fuzzing] iteration %d: manually triggered, proceeding to analysis\n", iteration)
			case <-fuzzCtx.Done():
				timer.Stop()
				if monitor != nil {
					if cfg.OnMonitorChanged != nil {
						cfg.OnMonitorChanged(nil)
					}
					monitor.Stop()
				}
				return fmt.Errorf("fuzzer exited unexpectedly: %w", fuzzCtx.Err())
			case <-ctx.Done():
				timer.Stop()
				if fuzzCancel != nil {
					fuzzCancel()
				}
				if monitor != nil {
					if cfg.OnMonitorChanged != nil {
						cfg.OnMonitorChanged(nil)
					}
					monitor.Stop()
				}
				return ctx.Err()
			}
		}
		cycleStarted := time.Now()
		flow.CycleStarted = &cycleStarted
		emitFlow(FuzzFlowCollecting, "running", triggerSource, "正在采集 fuzz 状态与覆盖数据")

		// Collect fuzz status from the (still-running) tracker.
		fuzzStatus := statusTracker.Snapshot()
		cfg.logf("[fuzzing] iteration %d: %s\n", iteration, fuzzStatus.String())

		// Coverage data is maintained incrementally by the background corpus
		// monitor. Snapshot returns instantly (one llvm-cov export on the
		// running aggregate profdata + cached per-seed reach data).
		var corpusCov CorpusCoverageStatus
		if monitor != nil {
			var covErr error
			corpusCov, covErr = monitor.Snapshot(cfg.SourceDir, cfg.BuildDir, cfg.logf)
			if covErr != nil {
				cfg.logf("[fuzzing] iteration %d: corpus coverage error: %v\n", iteration, covErr)
				corpusCov = CorpusCoverageStatus{}
			}
		} else {
			cfg.logf("[fuzzing] iteration %d: no corpus monitor, coverage empty\n", iteration)
		}
		cfg.logf("[fuzzing] iteration %d: %s\n", iteration, corpusCov.String())

		// Send to Codex for analysis. The codex prompt/response + logs are
		// ephemeral; the driver edits codex makes persist in DriverDir (real).
		// Codex reads the driver sources directly from DriverDir/synthesized/
		// (it has read access there); the entry source is NOT inlined.
		cfg.logf("[fuzzing] iteration %d: asking Codex for analysis\n", iteration)
		emitFlow(FuzzFlowAnalyzing, "running", triggerSource, "Codex 正在分析覆盖停滞并评估 driver 优化")
		analyzer := CodexAnalyzer{
			Command:   cfg.CodexCommand,
			Model:     cfg.CodexModel,
			Profile:   cfg.CodexProfile,
			Timeout:   30 * time.Minute,
			Runner:    cfg.Runner,
			EventSink: cfg.EventSink,
			LogSink:   cfg.LogSink,
		}
		analysisTmp, err := os.MkdirTemp(cfg.LogsDir, "analysis-")
		if err != nil {
			return err
		}
		analysisResp, aErr := analyzer.Analyze(ctx, AnalysisRequest{
			FuzzStatus:     fuzzStatus,
			CoverageStatus: corpusCov,
			SourceDir:      cfg.SourceDir,
			DriverDir:      cfg.DriverDir,
		}, analysisTmp)
		_ = os.RemoveAll(analysisTmp) // codex prompt/response are ephemeral
		if aErr != nil {
			cfg.logf("[fuzzing] Codex analysis error: %v\n", aErr)
			finishedAt := time.Now()
			flow.LastResult = &FuzzFlowResult{Iteration: iteration, DriverSeq: seq, Trigger: triggerSource, StartedAt: cycleStarted, FinishedAt: finishedAt, Error: aErr.Error()}
			emitFlow(FuzzFlowAnalyzing, "failed", triggerSource, aErr.Error())
			appendHistory(cfg.LogsDir, FuzzIteration{Iteration: iteration, Seq: seq, Trigger: triggerSource, FuzzStatus: fuzzStatus, Coverage: corpusCov, Analysis: AnalysisResponse{}, Regenerated: false, Error: aErr.Error(), StartedAt: cycleStarted, FinishedAt: finishedAt})
			persist()
			flow.CycleStarted = nil
			emitFlow(FuzzFlowFuzzing, "idle", "", fmt.Sprintf("上轮分析失败，fuzz driver v%d 继续运行", seq))
			continue
		}

		cfg.logf("[fuzzing] iteration %d: plateau=%v needs_update=%v\n",
			iteration, analysisResp.PlateauReached, analysisResp.NeedsUpdate)
		emitFlow(FuzzFlowApplying, "running", triggerSource, "正在校验 Codex 分析结果与 driver 源码变化")

		// A model response is not sufficient evidence that the driver changed.
		// Only compiled source files affect the binary; backup or note files must
		// not create a duplicate driver version.
		if analysisResp.NeedsUpdate {
			updatedHash, hashErr := driverSourceHash(synthesizedDir)
			if hashErr != nil {
				cfg.logf("[fuzzing] iteration %d: cannot verify driver source update: %v; keeping current version\n", iteration, hashErr)
				analysisResp.NeedsUpdate = false
			} else if updatedHash == lastBuiltHash {
				cfg.logf("[fuzzing] iteration %d: Codex reported an update but compiled driver sources are unchanged; keeping v%d\n", iteration, seq)
				analysisResp.NeedsUpdate = false
			}
		}

		finishedAt := time.Now()
		flow.LastResult = &FuzzFlowResult{
			Iteration: iteration, DriverSeq: seq, Trigger: triggerSource,
			StartedAt: cycleStarted, FinishedAt: finishedAt,
			PlateauReached: analysisResp.PlateauReached, NeedsUpdate: analysisResp.NeedsUpdate,
			Analysis: analysisResp.Analysis,
		}

		// Codex edits the synthesized driver sources directly (it has write
		// access to DriverDir). Preserve those files exactly and rebuild+restart
		// the fuzzer with the new driver (new snapshot + crash dir).
		if analysisResp.NeedsUpdate {
			cfg.logf("[fuzzing] iteration %d: Codex edited driver sources, scheduling rebuild\n", iteration)
			record := FuzzIteration{Iteration: iteration, Seq: seq, Trigger: triggerSource, FuzzStatus: fuzzStatus, Coverage: corpusCov, Analysis: analysisResp, Regenerated: false, StartedAt: cycleStarted, FinishedAt: finishedAt}
			appendHistory(cfg.LogsDir, record)
			pendingHistory = &record
			emitFlow(FuzzFlowRebuilding, "running", triggerSource, "Codex 已修改 driver，正在安排重建与重启")

			// Stop the corpus monitor and fuzzer before rebuilding the driver.
			if monitor != nil {
				if cfg.OnMonitorChanged != nil {
					cfg.OnMonitorChanged(nil)
				}
				monitor.Stop()
				monitor = nil
			}
			if fuzzCancel != nil {
				fuzzCancel()
			}
			fuzzerRunning = false

			// Driver changed: rebuild and restart the fuzzer on the next loop
			// (new seq, new snapshot, crashes go to the new snapshot dir).
			needRebuild = true
			persist()
			continue
		}
		appendHistory(cfg.LogsDir, FuzzIteration{Iteration: iteration, Seq: seq, Trigger: triggerSource, FuzzStatus: fuzzStatus, Coverage: corpusCov, Analysis: analysisResp, Regenerated: false, StartedAt: cycleStarted, FinishedAt: finishedAt})

		// No driver update needed. Whether or not plateau is reached, the
		// fuzzer keeps running into the next interval. Crash triage is
		// deferred to phase exit (ctx cancel or fuzzer exit).
		if analysisResp.PlateauReached {
			cfg.logf("[fuzzing] iteration %d: plateau reached but no driver update, continuing to fuzz\n", iteration)
		} else {
			cfg.logf("[fuzzing] iteration %d: no plateau yet, continuing\n", iteration)
		}
		persist()
		flow.CycleStarted = nil
		emitFlow(FuzzFlowFuzzing, "idle", "", fmt.Sprintf("fuzz driver v%d 持续运行，等待下一轮分析", seq))
	}
}

// buildCovDriver patches the build script for ASan and runs it to produce the
// coverage-instrumented driver binary.
func (cfg FuzzConfig) buildCovDriver(ctx context.Context, logDir string) error {
	patchBuildScript(cfg.BuildScript)
	buildCtx, buildCancel := context.WithTimeout(ctx, 10*time.Minute)
	defer buildCancel()
	if _, err := cfg.Runner.Run(buildCtx, logDir, "build", cfg.DriverDir, nil, cfg.BuildScript); err != nil {
		return fmt.Errorf("build cov synthesized driver: %w", err)
	}
	if !fileExists(cfg.BinaryPath) {
		return fmt.Errorf("build script did not produce %s", cfg.BinaryPath)
	}
	return nil
}

// startFuzzerAndWaitInit starts the long-running fuzzer and blocks until the
// INITED line is seen (or a timeout / cancellation). It returns the fuzzer
// context, its cancel func, the persistent status tracker, and whether a
// manual trigger arrived during INIT (in which case the caller should skip the
// interval wait and run analysis immediately).
func (cfg FuzzConfig) startFuzzerAndWaitInit(ctx context.Context, snapDir string) (context.Context, context.CancelFunc, *FuzzStatusTracker, bool, error) {
	fuzzCtx, fuzzCancel := context.WithCancel(ctx)
	statusTracker := NewFuzzStatusTracker()
	stderrPath := filepath.Join(snapDir, "fuzz.stderr.log")
	stdoutPath := filepath.Join(snapDir, "fuzz.stdout.log")
	if err := startFuzzer(fuzzCtx, cfg, snapDir, stderrPath, stdoutPath, statusTracker); err != nil {
		fuzzCancel()
		return nil, nil, nil, false, fmt.Errorf("start fuzzer: %w", err)
	}
	cfg.logf("[fuzzing] waiting for fuzzer to INIT\n")
	initDeadline := time.After(5 * time.Minute)
	for {
		select {
		case <-time.After(500 * time.Millisecond):
			if statusTracker.initialCovSet {
				cfg.logf("[fuzzing] INITED detected, initial cov=%d\n", statusTracker.initialCov)
				return fuzzCtx, fuzzCancel, statusTracker, false, nil
			}
		case <-initDeadline:
			cfg.logf("[fuzzing] no INITED line after 5min, proceeding anyway\n")
			return fuzzCtx, fuzzCancel, statusTracker, false, nil
		case <-fuzzCtx.Done():
			err := fuzzCtx.Err()
			fuzzCancel()
			return nil, nil, nil, false, err
		case <-ctx.Done():
			fuzzCancel()
			return nil, nil, nil, false, ctx.Err()
		case <-cfg.TriggerCh:
			cfg.logf("[fuzzing] manually triggered during INIT, proceeding to analysis\n")
			return fuzzCtx, fuzzCancel, statusTracker, true, nil
		}
	}
}

// copyCorpus copies all regular files from src to dst as a read-only snapshot
// of the libFuzzer corpus. libFuzzer writes seed files atomically, so a
// file-level copy is safe to run concurrently with the live fuzzer.
func copyCorpus(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			continue
		}
		_ = os.WriteFile(filepath.Join(dst, e.Name()), data, 0o644)
	}
	return nil
}

// startFuzzer runs the libFuzzer binary with fork=1, ignore_crash=1,
// and streams stderr lines to the status tracker.
func startFuzzer(ctx context.Context, cfg FuzzConfig, logDir, stderrPath, stdoutPath string, tracker *FuzzStatusTracker) error {
	stderrFile, err := os.Create(stderrPath)
	if err != nil {
		return err
	}
	stdoutFile, err := os.Create(stdoutPath)
	if err != nil {
		stderrFile.Close()
		return err
	}

	// -artifact_prefix is a literal filename prefix; keep the trailing '/' so
	// crash/oom/leak files land inside <snapDir>/crashes/ instead of cwd.
	crashesDir := filepath.Join(logDir, "crashes")
	if err := os.MkdirAll(crashesDir, 0o755); err != nil {
		stdoutFile.Close()
		stderrFile.Close()
		return err
	}
	cfg.logf("[fuzzing] crash artifacts -> %s/\n", crashesDir)

	// fork worker count: default to the number of logical CPUs (nproc).
	fork := cfg.ForkWorkers
	if fork <= 0 {
		fork = runtime.NumCPU()
	}
	cfg.logf("[fuzzing] fork workers = %d (nproc=%d)\n", fork, runtime.NumCPU())

	args := []string{
		cfg.BinaryPath,
		"-fork=" + fmt.Sprintf("%d", fork),
		"-ignore_crashes=1",
		"-use_value_profile=1",
		"-artifact_prefix=" + crashesDir + "/",
		cfg.CorpusDir,
	}

	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = cfg.DriverDir
	// Disable ASan stack symbolization for the live fuzzer: llvm-symbolizer is
	// re-spawned per crash and is pathologically slow (often >15s, sometimes
	// hanging) on the large coverage+ASan binary, which stalls fork-mode
	// corpus merges and prevents the fuzzer from ever reaching INITED. Crash
	// inputs are still saved to -artifact_prefix and symbolicated later during
	// crash triage (replayCrash), so no stack info is lost.
	env := append(os.Environ(), "LLVM_PROFILE_FILE=/dev/null")
	cmd.Env = withAsanSymbolizeDisabled(env)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Multi-writer for stderr: file + tracker
	stderrWriters := []io.Writer{stderrFile}
	if cfg.Runner.Verbose {
		stderrWriters = append(stderrWriters, os.Stderr)
	}
	stdoutWriters := []io.Writer{stdoutFile}
	if cfg.Runner.Verbose {
		stdoutWriters = append(stdoutWriters, os.Stdout)
	}

	stderrPipe := &lineSplitter{writers: stderrWriters, callback: tracker.ProcessLine}
	cmd.Stdout = io.MultiWriter(stdoutWriters...)
	cmd.Stderr = stderrPipe

	if err := cmd.Start(); err != nil {
		stderrFile.Close()
		stdoutFile.Close()
		return err
	}

	// Wait in a goroutine so the context can cancel
	go func() {
		_ = cmd.Wait()
		stderrPipe.Flush()
		stderrFile.Close()
		stdoutFile.Close()
	}()

	return nil
}

// withAsanSymbolizeDisabled returns env with ASAN_OPTIONS forced to include
// symbolize=0, replacing any existing symbolize= token while preserving other
// options (e.g. detect_leaks). If ASAN_OPTIONS is unset, adds it. The live
// fuzzer and per-seed replay paths use this so llvm-symbolizer is not
// re-spawned per crash (it is pathologically slow / can hang on the large
// coverage+ASan binary, stalling fork-mode merges and replay). Crash triage
// (replayCrash) keeps symbolization on to extract stacks.
func withAsanSymbolizeDisabled(env []string) []string {
	for i, kv := range env {
		if !strings.HasPrefix(kv, "ASAN_OPTIONS=") {
			continue
		}
		existing := strings.TrimPrefix(kv, "ASAN_OPTIONS=")
		var parts []string
		for _, p := range strings.Split(existing, ":") {
			if p == "" || strings.HasPrefix(p, "symbolize=") {
				continue
			}
			parts = append(parts, p)
		}
		parts = append(parts, "symbolize=0")
		env[i] = "ASAN_OPTIONS=" + strings.Join(parts, ":")
		return env
	}
	return append(env, "ASAN_OPTIONS=symbolize=0")
}

// lineSplitter writes data to multiple writers and calls a callback
// for each complete line. Similar to runner.lineWriter but standalone.
type lineSplitter struct {
	writers  []io.Writer
	callback func(string)
	pending  []byte
}

func (w *lineSplitter) Write(data []byte) (int, error) {
	for _, writer := range w.writers {
		if _, err := writer.Write(data); err != nil {
			return 0, err
		}
	}
	if w.callback == nil {
		return len(data), nil
	}
	w.pending = append(w.pending, data...)
	for {
		index := strings.IndexByte(string(w.pending), '\n')
		if index < 0 {
			break
		}
		line := strings.TrimSuffix(string(w.pending[:index]), "\r")
		w.pending = w.pending[index+1:]
		w.callback(line)
	}
	return len(data), nil
}

func (w *lineSplitter) Flush() {
	if w.callback != nil && len(w.pending) > 0 {
		w.callback(strings.TrimSuffix(string(w.pending), "\r"))
	}
	w.pending = nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// ParseStderrForStatus is a utility function that reads a libFuzzer stderr
// log file and returns a FuzzStatus. Useful for post-hoc analysis.
func ParseStderrForStatus(path string) (FuzzStatus, error) {
	file, err := os.Open(path)
	if err != nil {
		return FuzzStatus{}, err
	}
	defer file.Close()

	tracker := NewFuzzStatusTracker()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		tracker.ProcessLine(scanner.Text())
	}
	return tracker.Snapshot(), nil
}

// patchBuildScript ensures -fsanitize=address is present in the cov build
// script. The library was compiled with ASan, so the linker needs -fsanitize=address
// to resolve __asan_* symbols. Older versions of the synthesizer omitted it.
func patchBuildScript(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(data)
	if strings.Contains(content, "-fsanitize=fuzzer,address") {
		return
	}
	content = strings.Replace(content, "-fsanitize=fuzzer ", "-fsanitize=fuzzer,address ", 1)
	content = strings.Replace(content, "-fsanitize=fuzzer\n", "-fsanitize=fuzzer,address\n", 1)
	content = strings.Replace(content, "-fsanitize=fuzzer\"", "-fsanitize=fuzzer,address\"", 1)
	if content != string(data) {
		_ = os.WriteFile(path, []byte(content), 0o755)
	}
}

// findTool searches for a binary in PATH, falling back to versioned names
// (e.g. llvm-profdata-18) and common LLVM install directories.
func findTool(name string) string {
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	for _, suffix := range []string{"-18", "-17", "-16", "-15", "-14"} {
		if path, err := exec.LookPath(name + suffix); err == nil {
			return path
		}
	}
	for _, dir := range []string{"/usr/lib/llvm-18/bin", "/usr/lib/llvm-17/bin", "/usr/lib/llvm-16/bin"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// findCovTool searches for llvm-cov binary.
func findCovTool() string {
	return findTool("llvm-cov")
}
