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

type snapshotCoverageSummary struct {
	ExecutedFunctions int
	FullFunctions     int
	PartialFunctions  int
	UncoveredCount    int
}

// SnapshotComparison collects per-snapshot cached summary data for the web
// UI's "driver version comparison" panel. It never runs llvm-cov in the
// request path; instead it reads:
//   - live in-memory coverage cache for running tasks
//   - persisted multi-fuzz state summaries
//   - fuzzing-history.jsonl coverage summaries
//
// Also counts crashes + corpus per snapshot and reads the LLM analysis text
// matched by seq. Returns deltas vs the previous snapshot so the web UI can
// color-code improvement/regression.
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
	coverageBySeq := readCoverageBySeq(filepath.Join(fuzzingLogsDir, "fuzzing-history.jsonl"))
	if coverageBySeq == nil {
		coverageBySeq = map[int]snapshotCoverageSummary{}
	}
	if summary, ok := liveCoverageSummary(a.CoverageData()); ok {
		coverageBySeq[currentSeq] = summary
	}

	var result []snapshotEntry
	prevExecuted, prevUncovered := 0, 0
	hasPrevious := false

	for _, seq := range seqs {
		snapDir := filepath.Join(snapshotsDir, fmt.Sprintf("fuzz-%03d", seq))

		var executed, full, partial, uncovered int

		if summary, ok := coverageBySeq[seq]; ok {
			executed = summary.ExecutedFunctions
			full = summary.FullFunctions
			partial = summary.PartialFunctions
			uncovered = summary.UncoveredCount
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
	coverageByTargetSeq := readCoverageByTargetSeq(filepath.Join(fuzzingLogsDir, "fuzzing-history.jsonl"))
	if coverageByTargetSeq == nil {
		coverageByTargetSeq = map[string]snapshotCoverageSummary{}
	}
	for key, summary := range readMultiStateCoverage(filepath.Join(fuzzingLogsDir, "multi-fuzzing-state.json")) {
		if _, exists := coverageByTargetSeq[key]; !exists {
			coverageByTargetSeq[key] = summary
		}
	}
	for key, summary := range liveCoverageByTargetSeq(a.CoverageData()) {
		coverageByTargetSeq[key] = summary
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
			key := fmt.Sprintf("%d/%d", driverID, seq)
			if summary, ok := coverageByTargetSeq[key]; ok {
				executed = summary.ExecutedFunctions
				full = summary.FullFunctions
				partial = summary.PartialFunctions
				uncovered = summary.UncoveredCount
			}
			info, _ := os.Stat(snapDir)
			timestamp := ""
			if info != nil {
				timestamp = info.ModTime().Format("15:04:05")
			}
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

func readCoverageBySeq(path string) map[int]snapshotCoverageSummary {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	out := map[int]snapshotCoverageSummary{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec struct {
			Seq      int             `json:"seq"`
			Coverage json.RawMessage `json:"coverage_status"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil || rec.Seq <= 0 {
			continue
		}
		if !hasCoveragePayload(rec.Coverage) {
			continue
		}
		var coverage fuzzing.CorpusCoverageStatus
		if json.Unmarshal(rec.Coverage, &coverage) != nil {
			continue
		}
		out[rec.Seq] = snapshotCoverageSummaryFromCorpus(coverage)
	}
	return out
}

func readCoverageByTargetSeq(path string) map[string]snapshotCoverageSummary {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	out := map[string]snapshotCoverageSummary{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec struct {
			DriverID int             `json:"driver_id"`
			Seq      int             `json:"seq"`
			Coverage json.RawMessage `json:"coverage_status"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil || rec.DriverID <= 0 || rec.Seq <= 0 {
			continue
		}
		if !hasCoveragePayload(rec.Coverage) {
			continue
		}
		var coverage fuzzing.CorpusCoverageStatus
		if json.Unmarshal(rec.Coverage, &coverage) != nil {
			continue
		}
		out[fmt.Sprintf("%d/%d", rec.DriverID, rec.Seq)] = snapshotCoverageSummaryFromCorpus(coverage)
	}
	return out
}

func readMultiStateCoverage(path string) map[string]snapshotCoverageSummary {
	state, err := fuzzing.LoadMultiFuzzState(path)
	if err != nil || state == nil {
		return nil
	}
	out := map[string]snapshotCoverageSummary{}
	for _, version := range state.Versions {
		if version == nil || version.DriverID <= 0 || version.Seq <= 0 || version.LastCoverage == nil {
			continue
		}
		out[fmt.Sprintf("%d/%d", version.DriverID, version.Seq)] = snapshotCoverageSummary{
			ExecutedFunctions: version.LastCoverage.ExecutedFunctions,
			FullFunctions:     version.LastCoverage.FullFunctions,
			PartialFunctions:  version.LastCoverage.PartialFunctions,
			UncoveredCount:    version.LastCoverage.UncoveredCount,
		}
	}
	return out
}

func liveCoverageSummary(data any) (snapshotCoverageSummary, bool) {
	snapshot, ok := data.(fuzzing.CoverageSnapshot)
	if !ok {
		ptr, ok := data.(*fuzzing.CoverageSnapshot)
		if !ok || ptr == nil {
			return snapshotCoverageSummary{}, false
		}
		snapshot = *ptr
	}
	if !snapshot.Available {
		return snapshotCoverageSummary{}, false
	}
	return snapshotCoverageSummaryFromStatus(snapshot.Coverage), true
}

func liveCoverageByTargetSeq(data any) map[string]snapshotCoverageSummary {
	snapshot, ok := data.(fuzzing.MultiCoverageSnapshot)
	if !ok {
		ptr, ok := data.(*fuzzing.MultiCoverageSnapshot)
		if !ok || ptr == nil {
			return nil
		}
		snapshot = *ptr
	}
	out := map[string]snapshotCoverageSummary{}
	for _, target := range snapshot.Targets {
		if target.DriverID <= 0 || target.Seq <= 0 {
			continue
		}
		key := fmt.Sprintf("%d/%d", target.DriverID, target.Seq)
		out[key] = snapshotCoverageSummary{
			ExecutedFunctions: target.Summary.ExecutedFunctions,
			FullFunctions:     target.Summary.FullFunctions,
			PartialFunctions:  target.Summary.PartialFunctions,
			UncoveredCount:    target.UncoveredCount,
		}
	}
	return out
}

func snapshotCoverageSummaryFromStatus(status fuzzing.CoverageStatus) snapshotCoverageSummary {
	return snapshotCoverageSummary{
		ExecutedFunctions: status.Summary.ExecutedFunctions,
		FullFunctions:     status.Summary.FullFunctions,
		PartialFunctions:  status.Summary.PartialFunctions,
		UncoveredCount:    countUncovered(status),
	}
}

func snapshotCoverageSummaryFromCorpus(status fuzzing.CorpusCoverageStatus) snapshotCoverageSummary {
	return snapshotCoverageSummary{
		ExecutedFunctions: status.Summary.ExecutedFunctions,
		FullFunctions:     status.Summary.FullFunctions,
		PartialFunctions:  status.Summary.PartialFunctions,
		UncoveredCount:    len(status.Uncovered),
	}
}

func hasCoveragePayload(data json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(data))
	return trimmed != "" && trimmed != "null" && trimmed != "{}"
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
