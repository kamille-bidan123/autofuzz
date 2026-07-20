package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"autofuzz/internal/fuzzing"
)

type snapshotEntry struct {
	Seq               int    `json:"seq"`
	Timestamp         string `json:"timestamp"`
	ExecutedFunctions int    `json:"executed_functions"`
	FullFunctions     int    `json:"full_functions"`
	PartialFunctions  int    `json:"partial_functions"`
	UncoveredCount    int    `json:"uncovered_count"`
	CrashCount        int    `json:"crash_count"`
	UniqueCrashCount  int    `json:"unique_crash_count"`
	CorpusCount       int    `json:"corpus_count"`
	DeltaExecuted     int    `json:"delta_executed"`
	DeltaUncovered    int    `json:"delta_uncovered"`
	Analysis          string `json:"analysis"`
}

// SnapshotComparison collects per-snapshot coverage data for the web UI's
// "driver version comparison" panel. For each driver snapshot (fuzz-NNN):
//   - Past snapshots: exports the frozen aggregate.profdata via llvm-cov
//     (cached — the profdata is frozen after the monitor stops, so the export
//     never changes and is cached for subsequent calls).
//   - Current snapshot: uses the monitor's 60s covCache (live, in-memory).
//
// Also counts crashes + corpus per snapshot and reads the LLM analysis text
// from fuzzing-history.jsonl (matched by seq). Returns deltas vs the previous
// snapshot so the web UI can color-code improvement/regression.
func (a *Agent) SnapshotComparison() any {
	fuzzingLogsDir := filepath.Join(a.LogsDir, "fuzzing")
	snapshotsDir := filepath.Join(fuzzingLogsDir, "driver-snapshots")

	entries, err := os.ReadDir(snapshotsDir)
	if err != nil {
		return []snapshotEntry{}
	}

	var seqs []int
	for _, e := range entries {
		if seq, ok := parseSnapshotSeq(e.Name()); ok {
			seqs = append(seqs, seq)
		}
	}
	sort.Ints(seqs)
	if len(seqs) == 0 {
		return []snapshotEntry{}
	}
	currentSeq := seqs[len(seqs)-1]

	analysisBySeq := readAnalysisBySeq(filepath.Join(fuzzingLogsDir, "fuzzing-history.jsonl"))

	var result []snapshotEntry
	prevExecuted, prevUncovered := 0, 0

	for _, seq := range seqs {
		snapDir := filepath.Join(snapshotsDir, fmt.Sprintf("fuzz-%03d", seq))

		var executed, full, partial, uncovered int

		if seq == currentSeq {
			// Current snapshot: use the monitor's live covCache (no export needed).
			if cov := a.CoverageData(); cov != nil {
				if cs, ok := cov.(fuzzing.CoverageSnapshot); ok && cs.Available {
					executed = cs.Coverage.Summary.ExecutedFunctions
					full = cs.Coverage.Summary.FullFunctions
					partial = cs.Coverage.Summary.PartialFunctions
					uncovered = countUncovered(cs.Coverage)
				}
			}
		}

		if executed == 0 {
			// Past snapshot (or current with no covCache): export the frozen
			// aggregate.profdata. Cached after first export (frozen → immutable).
			a.snapshotCmpMu.RLock()
			cached, ok := a.snapshotCmp[seq]
			a.snapshotCmpMu.RUnlock()
			if !ok {
				profdataPath := filepath.Join(snapDir, "monitor", "aggregate.profdata")
				binaryPath := filepath.Join(snapDir, "cov_synthesized_driver")
				if fileExists(profdataPath) && fileExists(binaryPath) {
					cs, err := fuzzing.CollectCoverageStatus(profdataPath, binaryPath, a.State.SourceDir, a.State.BuildDir)
					if err == nil {
						if seq != currentSeq {
							// Only cache past snapshots (current is live, don't cache).
							a.snapshotCmpMu.Lock()
							a.snapshotCmp[seq] = cs
							a.snapshotCmpMu.Unlock()
						}
						cached = cs
						ok = true
					}
				}
			}
			if ok {
				executed = cached.Summary.ExecutedFunctions
				full = cached.Summary.FullFunctions
				partial = cached.Summary.PartialFunctions
				uncovered = countUncovered(cached)
			}
		}

		crashCount := countFiles(filepath.Join(snapDir, "crashes"))
		uniqueCrashCount := readUniqueCrashCount(filepath.Join(snapDir, "crash-analysis.json"))
		corpusCount := countFiles(filepath.Join(snapDir, "corpus"))

		info, _ := os.Stat(snapDir)
		timestamp := ""
		if info != nil {
			timestamp = info.ModTime().Format("15:04:05")
		}

		result = append(result, snapshotEntry{
			Seq:               seq,
			Timestamp:         timestamp,
			ExecutedFunctions: executed,
			FullFunctions:     full,
			PartialFunctions:  partial,
			UncoveredCount:    uncovered,
			CrashCount:        crashCount,
			UniqueCrashCount:  uniqueCrashCount,
			CorpusCount:       corpusCount,
			DeltaExecuted:     executed - prevExecuted,
			DeltaUncovered:    uncovered - prevUncovered,
			Analysis:          analysisBySeq[seq],
		})

		prevExecuted = executed
		prevUncovered = uncovered
	}

	if result == nil {
		return []snapshotEntry{}
	}
	return result
}

func parseSnapshotSeq(name string) (int, bool) {
	if !strings.HasPrefix(name, "fuzz-") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimPrefix(name, "fuzz-"))
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

func countFiles(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			n++
		}
	}
	return n
}

// readUniqueCrashCount reads the unique_crashes field from a snapshot's
// crash-analysis.json. Returns 0 if the file doesn't exist (analysis hasn't
// run yet for this snapshot).
func readUniqueCrashCount(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var v struct {
		Unique int `json:"unique_crashes"`
	}
	if json.Unmarshal(data, &v) != nil {
		return 0
	}
	return v.Unique
}

func countUncovered(cs fuzzing.CoverageStatus) int {
	n := 0
	for _, pf := range cs.Partial {
		n += len(pf.UncoveredBranches)
	}
	return n
}

// readAnalysisBySeq reads fuzzing-history.jsonl and returns the latest LLM
// analysis text per driver version (seq). Each line is a FuzzIteration; the
// last record with a given seq wins (the most recent analysis for that version).
func readAnalysisBySeq(path string) map[int]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	out := map[int]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec struct {
			Seq      int `json:"seq"`
			Analysis struct {
				Analysis string `json:"analysis"`
			} `json:"analysis"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec.Analysis.Analysis != "" {
			out[rec.Seq] = rec.Analysis.Analysis
		}
	}
	return out
}
