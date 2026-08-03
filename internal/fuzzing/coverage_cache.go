package fuzzing

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const coverageCacheFileName = "coverage-cache.json"

type coverageSnapshotCacheFile struct {
	Timestamp   time.Time               `json:"timestamp"`
	Available   bool                    `json:"available"`
	SeedCount   int                     `json:"seed_count"`
	Coverage    coverageStatusCacheFile `json:"coverage"`
	APICoverage *APICoverageReport      `json:"api_coverage,omitempty"`
}

type coverageStatusCacheFile struct {
	Summary CoverageSummary             `json:"summary"`
	Full    []coverageFunctionCacheFile `json:"full"`
	Partial []coveragePartialCacheFile  `json:"partial"`
}

type coverageFunctionCacheFile struct {
	Function   string           `json:"function"`
	File       string           `json:"file"`
	StartLine  int              `json:"start_line,omitempty"`
	EndLine    int              `json:"end_line,omitempty"`
	EntryCount int64            `json:"entry_count"`
	Regions    []CoverageRegion `json:"regions,omitempty"`
}

type coveragePartialCacheFile struct {
	Function          string            `json:"function"`
	File              string            `json:"file"`
	StartLine         int               `json:"start_line,omitempty"`
	EndLine           int               `json:"end_line,omitempty"`
	EntryCount        int64             `json:"entry_count"`
	UncoveredBranches []UncoveredBranch `json:"uncovered_branches"`
	Regions           []CoverageRegion  `json:"regions,omitempty"`
}

func coverageCachePath(snapshotDir string) string {
	return filepath.Join(snapshotDir, "monitor", coverageCacheFileName)
}

func writeCoverageSnapshotCache(path string, snapshot CoverageSnapshot) error {
	data, err := json.MarshalIndent(newCoverageSnapshotCacheFile(snapshot), "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func LoadCoverageSnapshotCache(snapshotDir string) (CoverageSnapshot, error) {
	data, err := os.ReadFile(coverageCachePath(snapshotDir))
	if err != nil {
		return CoverageSnapshot{}, err
	}
	var cache coverageSnapshotCacheFile
	if err := json.Unmarshal(data, &cache); err != nil {
		return CoverageSnapshot{}, err
	}
	return cache.snapshot(), nil
}

func newCoverageSnapshotCacheFile(snapshot CoverageSnapshot) coverageSnapshotCacheFile {
	cloned := CloneCoverageSnapshot(snapshot)
	return coverageSnapshotCacheFile{
		Timestamp:   cloned.Timestamp,
		Available:   cloned.Available,
		SeedCount:   cloned.SeedCount,
		Coverage:    newCoverageStatusCacheFile(cloned.Coverage),
		APICoverage: CloneAPICoverageReport(cloned.APICoverage),
	}
}

func newCoverageStatusCacheFile(status CoverageStatus) coverageStatusCacheFile {
	out := coverageStatusCacheFile{
		Summary: status.Summary,
		Full:    make([]coverageFunctionCacheFile, 0, len(status.Full)),
		Partial: make([]coveragePartialCacheFile, 0, len(status.Partial)),
	}
	for _, fn := range status.Full {
		out.Full = append(out.Full, coverageFunctionCacheFile{
			Function:   fn.Function,
			File:       fn.File,
			StartLine:  fn.StartLine,
			EndLine:    fn.EndLine,
			EntryCount: fn.EntryCount,
			Regions:    append([]CoverageRegion(nil), fn.Regions...),
		})
	}
	for _, fn := range status.Partial {
		out.Partial = append(out.Partial, coveragePartialCacheFile{
			Function:          fn.Function,
			File:              fn.File,
			StartLine:         fn.StartLine,
			EndLine:           fn.EndLine,
			EntryCount:        fn.EntryCount,
			UncoveredBranches: cloneUncoveredBranches(fn.UncoveredBranches),
			Regions:           append([]CoverageRegion(nil), fn.Regions...),
		})
	}
	return out
}

func (cache coverageSnapshotCacheFile) snapshot() CoverageSnapshot {
	return CoverageSnapshot{
		Timestamp:   cache.Timestamp,
		Available:   cache.Available,
		SeedCount:   cache.SeedCount,
		Coverage:    cache.Coverage.status(),
		APICoverage: CloneAPICoverageReport(cache.APICoverage),
	}
}

func (cache coverageStatusCacheFile) status() CoverageStatus {
	out := CoverageStatus{
		Summary: cache.Summary,
		Full:    make([]FunctionCoverage, 0, len(cache.Full)),
		Partial: make([]PartialFunctionCoverage, 0, len(cache.Partial)),
	}
	for _, fn := range cache.Full {
		out.Full = append(out.Full, FunctionCoverage{
			Function:   fn.Function,
			File:       fn.File,
			StartLine:  fn.StartLine,
			EndLine:    fn.EndLine,
			EntryCount: fn.EntryCount,
			Regions:    append([]CoverageRegion(nil), fn.Regions...),
		})
	}
	for _, fn := range cache.Partial {
		out.Partial = append(out.Partial, PartialFunctionCoverage{
			Function:          fn.Function,
			File:              fn.File,
			StartLine:         fn.StartLine,
			EndLine:           fn.EndLine,
			EntryCount:        fn.EntryCount,
			UncoveredBranches: cloneUncoveredBranches(fn.UncoveredBranches),
			Regions:           append([]CoverageRegion(nil), fn.Regions...),
		})
	}
	return out
}

func liveCorpusMonitorForSnapshot(snapshotDir string) *CorpusMonitor {
	key := corpusMonitorSnapshotKey(snapshotDir)
	liveCorpusMonitors.RLock()
	monitor := liveCorpusMonitors.bySnapshot[key]
	liveCorpusMonitors.RUnlock()
	return monitor
}

func RefreshCoverageSnapshotCacheContext(
	ctx context.Context,
	snapshotDir, profdataPath, binaryPath, sourceDir, buildDir, taskDir, driverDir, corpusDir string,
	logf func(string, ...any),
) error {
	if monitor := liveCorpusMonitorForSnapshot(snapshotDir); monitor != nil {
		return monitor.RefreshCoverageCacheContext(ctx, logf)
	}

	seedCount := countCorpusSeeds(corpusDir)
	if !fileExists(profdataPath) || !fileExists(binaryPath) {
		if _, err := LoadCoverageSnapshotCache(snapshotDir); err == nil {
			return nil
		}
		return writeCoverageSnapshotCache(coverageCachePath(snapshotDir), CoverageSnapshot{
			Timestamp: time.Now(),
			SeedCount: seedCount,
		})
	}

	status, err := collectCoverageStatusRefreshContext(ctx, profdataPath, binaryPath, sourceDir, buildDir, taskDir, driverDir)
	if err != nil {
		return err
	}
	return writeCoverageSnapshotCache(coverageCachePath(snapshotDir), CoverageSnapshot{
		Timestamp: time.Now(),
		Available: true,
		SeedCount: seedCount,
		Coverage:  status,
	})
}
