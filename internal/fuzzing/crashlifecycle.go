package fuzzing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// snapshotDriver copies the synthesized driver sources into the snapshot dir so
// the driver the current binary was built from can be rebuilt later to reproduce
// crashes found while this driver version ran.
func snapshotDriver(srcSynthesizedDir, dstDir string) error {
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(srcSynthesizedDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(srcSynthesizedDir, e.Name()))
		if err != nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(dstDir, e.Name()), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// copyFile copies a single regular file from src to dst, preserving the
// source's permission bits (so an executable binary stays executable and a
// shell script keeps its +x). It is best-effort like snapshotDriver: callers
// log the error rather than aborting the snapshot.
func copyFile(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, info.Mode().Perm())
}

// appendHistory appends one JSON record per analysis cycle to
// fuzzing-history.jsonl. This is the only persistent per-cycle artifact;
// coverage/profiles and codex prompt/response are ephemeral.
func appendHistory(logsDir string, record FuzzIteration) {
	data, _ := json.Marshal(record)
	path := filepath.Join(logsDir, "fuzzing-history.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(data, '\n'))
}

type snapshotCrash struct {
	path string
	seq  int
}

var seqDirRe = regexp.MustCompile(`^fuzz-(\d+)$`)

func parseSeqFromDir(name string) (int, bool) {
	m := seqDirRe.FindStringSubmatch(name)
	if m == nil {
		return 0, false
	}
	var n int
	if _, err := fmt.Sscanf(m[1], "%d", &n); err != nil {
		return 0, false
	}
	return n, true
}

// gatherSnapshotCrashes scans all driver-snapshots/fuzz-<seq>/crashes/ dirs and
// returns every crash input with its driver version (seq). Only build
// iterations have a crashes/ dir (the fuzzer's -artifact_prefix is fixed at
// start), so crashes are naturally grouped by driver version.
func gatherSnapshotCrashes(logsDir string) []snapshotCrash {
	root := filepath.Join(logsDir, "driver-snapshots")
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []snapshotCrash
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		seq, ok := parseSeqFromDir(e.Name())
		if !ok {
			continue
		}
		crashesDir := filepath.Join(root, e.Name(), "crashes")
		crashes, err := os.ReadDir(crashesDir)
		if err != nil {
			continue
		}
		for _, c := range crashes {
			if c.IsDir() {
				continue
			}
			out = append(out, snapshotCrash{path: filepath.Join(crashesDir, c.Name()), seq: seq})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	return out
}

var asanFrameRe = regexp.MustCompile(`(?m)^\s*#\d+\s+0x[0-9a-f]+\s+in\s+(\S+)`)
var asanTypeRe = regexp.MustCompile(`AddressSanitizer:\s+(\S+)`)

// CrashAnalysisEntry is one unique crash in a snapshot's crash-analysis.json.
type CrashAnalysisEntry struct {
	File            string `json:"file"`
	Type            string `json:"type"`
	Stack           string `json:"stack"`
	ASanReport      string `json:"asan_report,omitempty"`
	Signature       string `json:"signature,omitempty"`
	UniquePath      string `json:"unique_path,omitempty"`
	ReportPath      string `json:"report_path,omitempty"`
	ReportStatus    string `json:"report_status,omitempty"`
	ReportError     string `json:"report_error,omitempty"`
	ReportUpdatedAt string `json:"report_updated_at,omitempty"`
	Classification  string `json:"classification,omitempty"`
	Analysis        string `json:"analysis,omitempty"`
}

// parseASanType extracts the ASan error type (e.g. "heap-use-after-free",
// "SEGV", "heap-buffer-overflow") from the crash stderr.
func parseASanType(stderr string) string {
	if strings.Contains(stderr, "LeakSanitizer") {
		return "leak"
	}
	m := asanTypeRe.FindStringSubmatch(stderr)
	if m == nil {
		return "unknown"
	}
	return m[1]
}

// parseASanStack returns the top ASan frame function names as a dedup signature.
func parseASanStack(stderr string) string {
	matches := asanFrameRe.FindAllStringSubmatch(stderr, 5)
	var fns []string
	for _, m := range matches {
		fns = append(fns, m[1])
	}
	if len(fns) == 0 {
		// not an ASan report (oom/timeout/non-crash); use a short tail
		if len(stderr) > 200 {
			stderr = stderr[len(stderr)-200:]
		}
		return "(non-asan) " + stderr
	}
	return "stack: " + strings.Join(fns, " <- ")
}

const maxASanReportBytes = 12 * 1024

type crashReplayResult struct {
	Reproduced bool
	Type       string
	Stack      string
	ASanReport string
}

func trimASanReport(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if len(stderr) <= maxASanReportBytes {
		return stderr
	}
	return stderr[:maxASanReportBytes] + "\n... <ASan report truncated>"
}

func crashReplayEnv(env []string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if strings.HasPrefix(kv, "DEBUGINFOD_URLS=") {
			continue
		}
		out = append(out, kv)
	}
	// Keep ASan symbolization enabled, but prevent llvm-symbolizer from spending
	// replay time on debuginfod lookups.
	return append(out, "LLVM_PROFILE_FILE=/dev/null")
}

// replayCrashDetailed runs the given binary once on a crash input and returns
// the full crash triage data needed by unique-crash LLM analysis. ASan
// symbolization is kept ON (not symbolize=0) because the stack function names
// are needed for dedup and the human/LLM report.
func replayCrashDetailed(ctx context.Context, binary, driverDir, crashPath string) crashReplayResult {
	replayCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(replayCtx, binary, "-runs=1", crashPath)
	cmd.Dir = driverDir
	cmd.Env = crashReplayEnv(os.Environ())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	stderrText := stderr.String()
	if replayCtx.Err() == context.DeadlineExceeded {
		return crashReplayResult{Reproduced: false, Type: "timeout", Stack: "(timeout)", ASanReport: trimASanReport(stderrText)}
	}
	if runErr != nil {
		return crashReplayResult{Reproduced: true, Type: parseASanType(stderrText), Stack: parseASanStack(stderrText), ASanReport: trimASanReport(stderrText)}
	}
	return crashReplayResult{ASanReport: trimASanReport(stderrText)}
}

// replayCrash runs the given binary once on a crash input. Returns whether it
// crashed (non-zero exit), the ASan error type, and the symbolized stack
// signature (top 5 frames) for existing dedup/triage callers.
func replayCrash(ctx context.Context, binary, driverDir, crashPath string) (reproduced bool, crashType string, stack string) {
	result := replayCrashDetailed(ctx, binary, driverDir, crashPath)
	return result.Reproduced, result.Type, result.Stack
}

type crashReportEntry struct {
	Seq         int    `json:"seq"`
	Crash       string `json:"crash"`
	Reproduces  bool   `json:"reproduces_on_final"`
	Stack       string `json:"stack,omitempty"`
	SnapshotDir string `json:"snapshot_dir"`
}

// triageCrashes replays every crash (across all driver versions) against the
// final binary once, dedups by ASan stack (or content hash for non-crashing),
// and writes crash-report.json. Crashes stay in their snapshot dirs, colocated
// with the driver source that can reproduce them; non-reproducing-on-final ones
// are reproduced by rebuilding their snapshot dir's driver.
func triageCrashes(cfg FuzzConfig, finalSeq int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	crashes := gatherSnapshotCrashes(cfg.LogsDir)
	seen := map[string]bool{}
	var report []crashReportEntry
	reproCount := 0
	for _, c := range crashes {
		reproduces, _, stack := replayCrash(ctx, cfg.BinaryPath, cfg.DriverDir, c.path)
		// dedup signature: reproducing -> ASan stack; non-reproducing -> content hash
		sig := stack
		if !reproduces {
			data, _ := os.ReadFile(c.path)
			sig = "no-crash:" + fmt.Sprintf("%x", data)
		}
		if seen[sig] {
			continue
		}
		seen[sig] = true
		if reproduces {
			reproCount++
		}
		report = append(report, crashReportEntry{
			Seq:         c.seq,
			Crash:       filepath.Base(c.path),
			Reproduces:  reproduces,
			Stack:       stack,
			SnapshotDir: filepath.Join(cfg.LogsDir, "driver-snapshots", fmt.Sprintf("fuzz-%03d", c.seq), "synthesized"),
		})
	}

	out, _ := json.MarshalIndent(struct {
		FinalSeq      int                `json:"final_seq"`
		Unique        int                `json:"unique_crashes"`
		Reproducing   int                `json:"reproducing_on_final"`
		NonReproCount int                `json:"archived_not_reproducing"`
		Crashes       []crashReportEntry `json:"crashes"`
	}{
		FinalSeq:      finalSeq,
		Unique:        len(report),
		Reproducing:   reproCount,
		NonReproCount: len(report) - reproCount,
		Crashes:       report,
	}, "", "  ")
	cfg.logf("[fuzzing] crash triage: %d unique crashes (%d reproducing on final v%d, %d archived)\n",
		len(report), reproCount, finalSeq, len(report)-reproCount)
	return os.WriteFile(filepath.Join(cfg.LogsDir, "crash-report.json"), out, 0o644)
}
