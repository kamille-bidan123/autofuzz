package fuzzing

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRefreshCoverageSnapshotCacheContextPersistsCache(t *testing.T) {
	snapshotDir := t.TempDir()
	corpusDir := filepath.Join(snapshotDir, "corpus")
	monitorDir := filepath.Join(snapshotDir, "monitor")
	profdataPath := filepath.Join(monitorDir, "aggregate.profdata")
	binaryPath := filepath.Join(snapshotDir, "cov_driver")
	for _, path := range []string{corpusDir, monitorDir} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	if err := os.WriteFile(filepath.Join(corpusDir, "seed-1"), []byte("seed"), 0o644); err != nil {
		t.Fatalf("write corpus seed: %v", err)
	}
	if err := os.WriteFile(profdataPath, []byte("profdata"), 0o644); err != nil {
		t.Fatalf("write profdata: %v", err)
	}
	if err := os.WriteFile(binaryPath, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	original := coverageStatusExportFunc
	t.Cleanup(func() { coverageStatusExportFunc = original })
	want := CoverageStatus{Summary: CoverageSummary{
		ExecutedFunctions: 4,
		FullFunctions:     3,
		PartialFunctions:  1,
	},
		Full: []FunctionCoverage{{
			Function:   "full_fn",
			File:       "/src/full.c",
			StartLine:  10,
			EndLine:    12,
			EntryCount: 9,
			Regions: []CoverageRegion{
				{StartLine: 10, StartColumn: 1, EndLine: 12, EndColumn: 2, Count: 9, FileID: 0},
			},
		}},
		Partial: []PartialFunctionCoverage{{
			Function:   "partial_fn",
			File:       "/src/partial.c",
			StartLine:  20,
			EndLine:    23,
			EntryCount: 4,
			UncoveredBranches: []UncoveredBranch{{
				Location:  [2]int{21, 5},
				Condition: "flag",
				Missing:   "true",
				Counts: map[string]int64{
					"true":  0,
					"false": 4,
				},
			}},
			Regions: []CoverageRegion{
				{StartLine: 20, StartColumn: 1, EndLine: 23, EndColumn: 2, Count: 4, FileID: 0},
				{StartLine: 21, StartColumn: 3, EndLine: 21, EndColumn: 16, Count: 0, FileID: 0},
			},
		}},
	}
	coverageStatusExportFunc = func(_ context.Context, _, _, _, _, _, _ string) (CoverageStatus, error) {
		return want, nil
	}

	if err := RefreshCoverageSnapshotCacheContext(context.Background(), snapshotDir, profdataPath, binaryPath, "/src", "/build", snapshotDir, "", corpusDir, nil); err != nil {
		t.Fatalf("RefreshCoverageSnapshotCacheContext() error = %v", err)
	}

	got, err := LoadCoverageSnapshotCache(snapshotDir)
	if err != nil {
		t.Fatalf("LoadCoverageSnapshotCache() error = %v", err)
	}
	if !got.Available {
		t.Fatal("coverage cache should be available")
	}
	if got.SeedCount != 1 {
		t.Fatalf("SeedCount = %d, want 1", got.SeedCount)
	}
	if got.Coverage.Summary != want.Summary {
		t.Fatalf("coverage summary = %#v, want %#v", got.Coverage.Summary, want.Summary)
	}
	if !reflect.DeepEqual(got.Coverage.Full, want.Full) {
		t.Fatalf("full coverage = %#v, want %#v", got.Coverage.Full, want.Full)
	}
	if !reflect.DeepEqual(got.Coverage.Partial, want.Partial) {
		t.Fatalf("partial coverage = %#v, want %#v", got.Coverage.Partial, want.Partial)
	}
	if got.Timestamp.IsZero() {
		t.Fatal("cache timestamp should be populated")
	}
	data, err := os.ReadFile(filepath.Join(snapshotDir, "monitor", coverageCacheFileName))
	if err != nil {
		t.Fatalf("read coverage cache: %v", err)
	}
	if !strings.Contains(string(data), "\"regions\"") {
		t.Fatalf("coverage cache should persist regions, got %s", string(data))
	}
}

func TestLoadCoverageSnapshotCacheSupportsLegacyJSONWithoutRegions(t *testing.T) {
	snapshotDir := t.TempDir()
	monitorDir := filepath.Join(snapshotDir, "monitor")
	if err := os.MkdirAll(monitorDir, 0o755); err != nil {
		t.Fatal(err)
	}

	legacy := CoverageSnapshot{
		Timestamp: time.Date(2026, 8, 2, 3, 4, 5, 0, time.UTC),
		Available: true,
		SeedCount: 2,
		Coverage: CoverageStatus{
			Summary: CoverageSummary{
				ExecutedFunctions: 1,
				FullFunctions:     0,
				PartialFunctions:  1,
			},
			Partial: []PartialFunctionCoverage{{
				Function:   "legacy_fn",
				File:       "/src/legacy.c",
				StartLine:  7,
				EndLine:    9,
				EntryCount: 3,
				UncoveredBranches: []UncoveredBranch{{
					Location:  [2]int{8, 4},
					Condition: "legacy",
					Missing:   "false",
				}},
			}},
		},
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy snapshot: %v", err)
	}
	if err := os.WriteFile(filepath.Join(monitorDir, coverageCacheFileName), data, 0o644); err != nil {
		t.Fatalf("write legacy coverage cache: %v", err)
	}

	got, err := LoadCoverageSnapshotCache(snapshotDir)
	if err != nil {
		t.Fatalf("LoadCoverageSnapshotCache() error = %v", err)
	}
	if !got.Available || got.SeedCount != legacy.SeedCount {
		t.Fatalf("loaded legacy cache = %#v, want available seed_count=%d", got, legacy.SeedCount)
	}
	if !reflect.DeepEqual(got.Coverage.Partial, legacy.Coverage.Partial) {
		t.Fatalf("legacy partial coverage = %#v, want %#v", got.Coverage.Partial, legacy.Coverage.Partial)
	}
}
