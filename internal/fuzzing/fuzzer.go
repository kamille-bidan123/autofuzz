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
	PythonPath   string // for the synthesize_into_one script
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
// immediately skip the remaining wait and run the LLM analysis.
func (c FuzzController) TriggerAnalysis() {
	select {
	case c.Trigger <- struct{}{}:
	default:
	}
}

// FuzzIteration records the results of a single fuzz+analyze+regenerate cycle.
type FuzzIteration struct {
	Iteration   int                  `json:"iteration"`
	Seq         int                  `json:"seq"` // driver version that ran this cycle
	FuzzStatus  FuzzStatus           `json:"fuzz_status"`
	Coverage    CorpusCoverageStatus `json:"coverage_status"`
	Analysis    AnalysisResponse     `json:"analysis"`
	Regenerated bool                 `json:"regenerated"`
	StartedAt   time.Time            `json:"started_at"`
	FinishedAt  time.Time            `json:"finished_at"`
}

// RunFuzzingPhase is the main entry point for the fuzzing phase.
// It runs the coverage-instrumented synthesized driver as a long-running
// fuzzer, collects per-seed coverage each interval (without stopping the
// fuzzer), sends the data to Codex which edits driver sources directly, and on
// a driver change rebuilds + restarts. Crash artifacts land inside the driver
// version's snapshot dir so every crash stays reproducible against the driver
// version that found it.
func RunFuzzingPhase(ctx context.Context, cfg FuzzConfig) error {
	if err := os.MkdirAll(cfg.LogsDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.CorpusDir, 0o755); err != nil {
		return err
	}

	iteration := 0 // analysis cycle counter (~per interval)
	seq := 0       // driver version counter (only on build)
	needRebuild := true

	// The fuzzer runs continuously across analysis intervals. These hold the
	// current fuzzer's context/cancel and stderr tracker; they are replaced
	// only when the driver is regenerated (needRebuild path).
	var fuzzCtx context.Context
	var fuzzCancel context.CancelFunc
	var statusTracker *FuzzStatusTracker

	for {
		iteration++
		var snapDir string // set in needRebuild; persistent home of this driver version

		// (Re)build and start the fuzzer only when the driver changed.
		triggered := false
		if needRebuild {
			seq++
			snapDir = filepath.Join(cfg.LogsDir, "driver-snapshots", fmt.Sprintf("fuzz-%03d", seq))
			if err := os.MkdirAll(snapDir, 0o755); err != nil {
				return err
			}
			cfg.logf("[fuzzing] iteration %d: building driver v%d (snapshot %s)\n", iteration, seq, snapDir)
			if err := cfg.buildCovDriver(ctx, snapDir); err != nil {
				return err
			}
			// Snapshot the driver sources that this binary was built from, so
			// any crash found while this driver runs can later be reproduced by
			// rebuilding from this snapshot.
			if err := snapshotDriver(filepath.Join(cfg.DriverDir, "synthesized"), filepath.Join(snapDir, "synthesized")); err != nil {
				cfg.logf("[fuzzing] driver snapshot failed: %v\n", err)
			}
			var err error
			fuzzCtx, fuzzCancel, statusTracker, triggered, err = cfg.startFuzzerAndWaitInit(ctx, snapDir)
			if err != nil {
				return err
			}
			needRebuild = false
		} else {
			snapDir = filepath.Join(cfg.LogsDir, "driver-snapshots", fmt.Sprintf("fuzz-%03d", seq))
			cfg.logf("[fuzzing] iteration %d: fuzzer still running on driver v%d, no rebuild\n", iteration, seq)
		}

		// Run for the configured interval (or until manually triggered).
		// The fuzzer keeps running; we do NOT stop it to collect coverage.
		if triggered {
			cfg.logf("[fuzzing] iteration %d: skipping fuzz wait (triggered during INIT)\n", iteration)
		} else {
			cfg.logf("[fuzzing] iteration %d: fuzzing for %s (or click trigger button)\n", iteration, cfg.Interval)
			timer := time.NewTimer(cfg.Interval)
			select {
			case <-timer.C:
				cfg.logf("[fuzzing] iteration %d: interval elapsed, proceeding to analysis\n", iteration)
			case <-cfg.TriggerCh:
				timer.Stop()
				cfg.logf("[fuzzing] iteration %d: manually triggered, proceeding to analysis\n", iteration)
			case <-fuzzCtx.Done():
				timer.Stop()
				return fmt.Errorf("fuzzer exited unexpectedly: %w", fuzzCtx.Err())
			case <-ctx.Done():
				timer.Stop()
				if fuzzCancel != nil {
					fuzzCancel()
				}
				return ctx.Err()
			}
		}

		// Collect fuzz status from the (still-running) tracker.
		fuzzStatus := statusTracker.Snapshot()
		cfg.logf("[fuzzing] iteration %d: %s\n", iteration, fuzzStatus.String())

		// Per-seed coverage. The corpus snapshot + profiles are ephemeral:
		// keep them in a tmp dir and delete as soon as CorpusCoverageStatus is
		// in memory, so we don't persist per-iteration coverage clutter.
		covTmp, err := os.MkdirTemp(cfg.LogsDir, "cov-")
		if err != nil {
			return err
		}
		corpusSnapshotDir := filepath.Join(covTmp, "corpus-snapshot")
		if err := copyCorpus(cfg.CorpusDir, corpusSnapshotDir); err != nil {
			cfg.logf("[fuzzing] iteration %d: corpus snapshot failed: %v\n", iteration, err)
		}
		corpusCov, covErr := CollectCorpusCoverage(ctx, cfg.BinaryPath, cfg.SourceDir, cfg.DriverDir, corpusSnapshotDir, covTmp, cfg.MaxSeeds, cfg.logf)
		_ = os.RemoveAll(covTmp) // coverage data is now in memory (corpusCov)
		if covErr != nil {
			cfg.logf("[fuzzing] iteration %d: corpus coverage error: %v\n", iteration, covErr)
			corpusCov = CorpusCoverageStatus{}
		}
		cfg.logf("[fuzzing] iteration %d: %s\n", iteration, corpusCov.String())

		// Read the entry source code
		synthesizedDir := filepath.Join(cfg.DriverDir, "synthesized")
		entrySource, err := ReadEntrySource(synthesizedDir)
		if err != nil {
			cfg.logf("[fuzzing] could not read entry source: %v\n", err)
			entrySource = ""
		}

		// Send to Codex for analysis. The codex prompt/response + logs are
		// ephemeral; the driver edits codex makes persist in DriverDir (real).
		cfg.logf("[fuzzing] iteration %d: asking Codex for analysis\n", iteration)
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
			DriverSource:   entrySource,
			SourceDir:      cfg.SourceDir,
			DriverDir:      cfg.DriverDir,
		}, analysisTmp)
		_ = os.RemoveAll(analysisTmp) // codex prompt/response are ephemeral
		if aErr != nil {
			cfg.logf("[fuzzing] Codex analysis error: %v\n", aErr)
			appendHistory(cfg.LogsDir, FuzzIteration{Iteration: iteration, Seq: seq, FuzzStatus: fuzzStatus, Coverage: corpusCov, Analysis: AnalysisResponse{}, Regenerated: false, StartedAt: time.Now().Add(-time.Duration(fuzzStatus.DurationSeconds) * time.Second), FinishedAt: time.Now()})
			continue
		}

		cfg.logf("[fuzzing] iteration %d: plateau=%v needs_update=%v\n",
			iteration, analysisResp.PlateauReached, analysisResp.NeedsUpdate)

		appendHistory(cfg.LogsDir, FuzzIteration{Iteration: iteration, Seq: seq, FuzzStatus: fuzzStatus, Coverage: corpusCov, Analysis: analysisResp, Regenerated: false, StartedAt: time.Now().Add(-time.Duration(fuzzStatus.DurationSeconds) * time.Second), FinishedAt: time.Now()})

		// Codex edits the synthesized driver sources directly (it has write
		// access to DriverDir). If it reports edits, re-merge entry.c and
		// rebuild+restart the fuzzer with the new driver (new snapshot + crash dir).
		if analysisResp.NeedsUpdate {
			cfg.logf("[fuzzing] iteration %d: Codex edited driver sources, re-synthesizing\n", iteration)

			// Stop the fuzzer before rebuilding the driver.
			if fuzzCancel != nil {
				fuzzCancel()
			}

			// Re-synthesize the merged driver (entry.c). Logs are ephemeral.
			synthesizeScript := filepath.Join(cfg.DriverDir, "synthesize_into_one")
			if fileExists(synthesizeScript) {
				synTmp, err := os.MkdirTemp(cfg.LogsDir, "synth-")
				if err != nil {
					return err
				}
				synCtx, synCancel := context.WithTimeout(ctx, 2*time.Minute)
				_, runErr := cfg.Runner.Run(synCtx, synTmp, "synthesize", cfg.DriverDir, nil,
					cfg.PythonPath, synthesizeScript, cfg.DriverDir)
				synCancel()
				_ = os.RemoveAll(synTmp)
				if runErr != nil {
					cfg.logf("[fuzzing] re-synthesis failed: %v\n", runErr)
					needRebuild = true
					continue
				}
			}

			appendHistory(cfg.LogsDir, FuzzIteration{Iteration: iteration, Seq: seq, FuzzStatus: fuzzStatus, Coverage: corpusCov, Analysis: analysisResp, Regenerated: true, StartedAt: time.Now().Add(-time.Duration(fuzzStatus.DurationSeconds) * time.Second), FinishedAt: time.Now()})

			// Driver changed: rebuild and restart the fuzzer on the next loop
			// (new seq, new snapshot, crashes go to the new snapshot dir).
			needRebuild = true
			continue
		}

		// If no update needed and plateau reached, triage crashes and stop.
		if analysisResp.PlateauReached && !analysisResp.NeedsUpdate {
			cfg.logf("[fuzzing] iteration %d: plateau reached, no driver update needed, stopping\n", iteration)
			if fuzzCancel != nil {
				fuzzCancel()
			}
			if err := triageCrashes(cfg, seq); err != nil {
				cfg.logf("[fuzzing] crash triage error: %v\n", err)
			}
			return nil
		}

		// If no plateau yet, the fuzzer is still running; keep fuzzing into
		// the next interval without rebuilding.
		cfg.logf("[fuzzing] iteration %d: no plateau yet, continuing\n", iteration)
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
	cmd.Env = append(os.Environ(),
		// The live fuzzer no longer feeds coverage data (coverage comes from
		// per-seed replay). Discard its profraw to avoid disk clutter.
		"LLVM_PROFILE_FILE=/dev/null",
	)
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
