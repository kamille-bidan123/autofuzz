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
	DriverID          int    `json:"driver_id,omitempty"`
	Seq               int    `json:"seq"`
	Timestamp         string `json:"timestamp"`
	ExecutedFunctions int    `json:"executed_functions"`
	FullFunctions     int    `json:"full_functions"`
	PartialFunctions  int    `json:"partial_functions"`
	UncoveredCount    int    `json:"uncovered_count"`
	CrashCount        int    `json:"crash_count"`
	UniqueCrashCount  int    `json:"unique_crash_count"`
	CrashReportCount  int    `json:"crash_report_count"`
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
	if multi := a.multiSnapshotComparison(fuzzingLogsDir); len(multi) > 0 {
		return multi
	}
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
	hasPrevious := false

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
		uniqueCrashCount, crashReportCount := readCrashAnalysisCounts(filepath.Join(snapDir, "crash-analysis.json"))
		corpusCount := countFiles(filepath.Join(snapDir, "corpus"))

		info, _ := os.Stat(snapDir)
		timestamp := ""
		if info != nil {
			timestamp = info.ModTime().Format("15:04:05")
		}
		deltaExecuted, deltaUncovered := 0, 0
		if hasPrevious {
			deltaExecuted = executed - prevExecuted
			deltaUncovered = uncovered - prevUncovered
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
			CrashReportCount:  crashReportCount,
			CorpusCount:       corpusCount,
			DeltaExecuted:     deltaExecuted,
			DeltaUncovered:    deltaUncovered,
			Analysis:          analysisBySeq[seq],
		})

		prevExecuted = executed
		prevUncovered = uncovered
		hasPrevious = true
	}

	if result == nil {
		return []snapshotEntry{}
	}
	return result
}

func (a *Agent) multiSnapshotComparison(fuzzingLogsDir string) []snapshotEntry {
	targetsDir := filepath.Join(fuzzingLogsDir, "driver-targets")
	targetEntries, err := os.ReadDir(targetsDir)
	if err != nil {
		return nil
	}
	analysisByTargetSeq := readAnalysisByTargetSeq(filepath.Join(fuzzingLogsDir, "fuzzing-history.jsonl"))
	var result []snapshotEntry
	for _, targetEntry := range targetEntries {
		if !targetEntry.IsDir() || !strings.HasPrefix(targetEntry.Name(), "driver-") {
			continue
		}
		driverID, err := strconv.Atoi(strings.TrimPrefix(targetEntry.Name(), "driver-"))
		if err != nil || driverID <= 0 {
			continue
		}
		targetDir := filepath.Join(targetsDir, targetEntry.Name())
		versionEntries, err := os.ReadDir(targetDir)
		if err != nil {
			continue
		}
		var seqs []int
		for _, versionEntry := range versionEntries {
			if !versionEntry.IsDir() || !strings.HasPrefix(versionEntry.Name(), "v") {
				continue
			}
			seq, err := strconv.Atoi(strings.TrimPrefix(versionEntry.Name(), "v"))
			if err == nil && seq > 0 {
				seqs = append(seqs, seq)
			}
		}
		sort.Ints(seqs)
		prevExecuted, prevUncovered := 0, 0
		hasPrevious := false
		for _, seq := range seqs {
			snapDir := filepath.Join(targetDir, fmt.Sprintf("v%03d", seq))
			executed, full, partial, uncovered := 0, 0, 0, 0
			profdataPath := filepath.Join(snapDir, "monitor", "aggregate.profdata")
			binaryPath := filepath.Join(snapDir, "cov_driver")
			if fileExists(profdataPath) && fileExists(binaryPath) {
				if cs, err := fuzzing.CollectCoverageStatus(profdataPath, binaryPath, a.State.SourceDir, a.State.BuildDir); err == nil {
					executed = cs.Summary.ExecutedFunctions
					full = cs.Summary.FullFunctions
					partial = cs.Summary.PartialFunctions
					uncovered = countUncovered(cs)
				}
			}
			info, _ := os.Stat(snapDir)
			timestamp := ""
			if info != nil {
				timestamp = info.ModTime().Format("15:04:05")
			}
			key := fmt.Sprintf("%d/%d", driverID, seq)
			uniqueCrashCount, crashReportCount := readCrashAnalysisCounts(filepath.Join(snapDir, "crash-analysis.json"))
			deltaExecuted, deltaUncovered := 0, 0
			if hasPrevious {
				deltaExecuted = executed - prevExecuted
				deltaUncovered = uncovered - prevUncovered
			}
			result = append(result, snapshotEntry{
				DriverID: driverID, Seq: seq, Timestamp: timestamp,
				ExecutedFunctions: executed, FullFunctions: full, PartialFunctions: partial,
				UncoveredCount: uncovered, CrashCount: countFiles(filepath.Join(snapDir, "crashes")),
				UniqueCrashCount: uniqueCrashCount,
				CrashReportCount: crashReportCount,
				CorpusCount:      countFiles(filepath.Join(snapDir, "corpus")),
				DeltaExecuted:    deltaExecuted, DeltaUncovered: deltaUncovered,
				Analysis: analysisByTargetSeq[key],
			})
			prevExecuted = executed
			prevUncovered = uncovered
			hasPrevious = true
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].DriverID != result[j].DriverID {
			return result[i].DriverID < result[j].DriverID
		}
		return result[i].Seq < result[j].Seq
	})
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

// readCrashAnalysisCounts reads unique crash and completed LLM report counts
// from a snapshot's crash-analysis.json. Returns zeros if the file doesn't
// exist or was written by an older version without report metadata.
func readCrashAnalysisCounts(path string) (int, int) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0
	}
	var v struct {
		Unique int `json:"unique_crashes"`
		List   []struct {
			ReportStatus string `json:"report_status"`
			ReportPath   string `json:"report_path"`
		} `json:"unique_list"`
	}
	if json.Unmarshal(data, &v) != nil {
		return 0, 0
	}
	reports := 0
	for _, entry := range v.List {
		if entry.ReportStatus == "completed" {
			reports++
		}
	}
	return v.Unique, reports
}

func countUncovered(cs fuzzing.CoverageStatus) int {
	n := 0
	for _, pf := range cs.Partial {
		n += len(pf.UncoveredBranches)
	}
	return n
}

// readAnalysisBySeq reads fuzzing-history.jsonl and associates each successful
// driver update with the version it produced. Analysis recorded while vN runs
// describes the source change that is built and snapshotted as vN+1.
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
			Seq         int  `json:"seq"`
			Regenerated bool `json:"regenerated"`
			Analysis    struct {
				Analysis string `json:"analysis"`
			} `json:"analysis"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec.Regenerated && rec.Analysis.Analysis != "" {
			out[rec.Seq+1] = rec.Analysis.Analysis
		}
	}
	return out
}

func readAnalysisByTargetSeq(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec struct {
			DriverID    int  `json:"driver_id"`
			Seq         int  `json:"seq"`
			Regenerated bool `json:"regenerated"`
			Analysis    struct {
				Analysis string `json:"analysis"`
			} `json:"analysis"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if rec.DriverID > 0 && rec.Regenerated && rec.Analysis.Analysis != "" {
			out[fmt.Sprintf("%d/%d", rec.DriverID, rec.Seq+1)] = rec.Analysis.Analysis
		}
	}
	return out
}
