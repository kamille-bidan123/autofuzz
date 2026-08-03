package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"autofuzz/internal/fuzzing"
	"autofuzz/internal/state"
)

func TestReadAnalysisBySeqAssociatesUpdateWithNextVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fuzzing-history.jsonl")
	history := "" +
		`{"seq":3,"regenerated":false,"analysis":{"analysis":"准备修改"}}` + "\n" +
		`{"seq":3,"regenerated":true,"analysis":{"analysis":"v4 的实际修改"}}` + "\n" +
		`{"seq":4,"regenerated":false,"analysis":{"analysis":"没有修改"}}` + "\n"
	if err := os.WriteFile(path, []byte(history), 0o644); err != nil {
		t.Fatal(err)
	}

	got := readAnalysisBySeq(path)
	if got[4] != "v4 的实际修改" {
		t.Fatalf("v4 analysis = %q", got[4])
	}
	if _, exists := got[3]; exists {
		t.Fatalf("v3 unexpectedly has update analysis %q", got[3])
	}
	if _, exists := got[5]; exists {
		t.Fatalf("v5 unexpectedly has update analysis %q", got[5])
	}
}

func TestSnapshotComparisonUsesHistoryCoverageCache(t *testing.T) {
	targetDir := t.TempDir()
	logsDir := filepath.Join(targetDir, "logs")
	fuzzingDir := filepath.Join(logsDir, "fuzzing")
	snap1 := filepath.Join(fuzzingDir, "driver-snapshots", "fuzz-001")
	snap2 := filepath.Join(fuzzingDir, "driver-snapshots", "fuzz-002")
	for _, dir := range []string{
		filepath.Join(snap1, "crashes"),
		filepath.Join(snap1, "corpus"),
		filepath.Join(snap2, "crashes"),
		filepath.Join(snap2, "corpus"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(snap1, "crashes", "c1"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snap1, "corpus", "seed1"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snap2, "corpus", "seed2"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snap2, "corpus", "seed3"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	crashAnalysis, err := json.Marshal(map[string]any{
		"unique_crashes": 1,
		"unique_list": []map[string]any{
			{"report_status": "completed", "report_path": "crash-reports/r1.json"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snap2, "crash-analysis.json"), crashAnalysis, 0o644); err != nil {
		t.Fatal(err)
	}
	history := "" +
		`{"seq":1,"coverage_status":{"summary":{"executed_functions":3,"full_functions":1,"partial_functions":2},"uncovered":[{},{}]}}` + "\n" +
		`{"seq":2,"coverage_status":{"summary":{"executed_functions":4,"full_functions":2,"partial_functions":2},"uncovered":[{}]}}` + "\n"
	if err := os.WriteFile(filepath.Join(fuzzingDir, "fuzzing-history.jsonl"), []byte(history), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewHistoricalAgent(targetDir, &state.RunState{SourceDir: "/src", BuildDir: "/build"}, logsDir)
	got, ok := a.SnapshotComparison().([]snapshotEntry)
	if !ok {
		t.Fatalf("SnapshotComparison type = %T", a.SnapshotComparison())
	}
	if len(got) != 2 {
		t.Fatalf("snapshot count = %d, want 2", len(got))
	}
	if got[0].Seq != 1 || got[0].ExecutedFunctions != 3 || got[0].UncoveredCount != 2 || got[0].CrashCount != 1 || got[0].CorpusCount != 1 {
		t.Fatalf("snapshot 1 = %#v", got[0])
	}
	if got[1].Seq != 2 || got[1].ExecutedFunctions != 4 || got[1].UncoveredCount != 1 || got[1].UniqueCrashCount != 1 || got[1].CrashReportCount != 1 || got[1].CorpusCount != 2 {
		t.Fatalf("snapshot 2 = %#v", got[1])
	}
}

func TestMultiSnapshotComparisonUsesStateCoverageCache(t *testing.T) {
	targetDir := t.TempDir()
	logsDir := filepath.Join(targetDir, "logs")
	fuzzingDir := filepath.Join(logsDir, "fuzzing")
	driverDir := filepath.Join(fuzzingDir, "driver-targets", "driver-0007")
	for _, dir := range []string{
		filepath.Join(driverDir, "v001", "corpus"),
		filepath.Join(driverDir, "v002", "corpus"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	statePath := filepath.Join(fuzzingDir, "multi-fuzzing-state.json")
	multiState := &fuzzing.MultiFuzzState{
		Targets: map[int]*fuzzing.TargetState{
			7: {
				DriverID:        7,
				Seq:             2,
				CurrentSnapshot: filepath.Join(driverDir, "v002"),
				LastCoverage: &fuzzing.CoverageSummaryPoint{
					ExecutedFunctions: 8,
					FullFunctions:     5,
					PartialFunctions:  3,
					UncoveredCount:    4,
				},
			},
		},
		Versions: map[string]*fuzzing.TargetState{
			"driver-0007-v001": {
				DriverID:        7,
				Seq:             1,
				CurrentSnapshot: filepath.Join(driverDir, "v001"),
				LastCoverage: &fuzzing.CoverageSummaryPoint{
					ExecutedFunctions: 5,
					FullFunctions:     3,
					PartialFunctions:  2,
					UncoveredCount:    7,
				},
			},
			"driver-0007-v002": {
				DriverID:        7,
				Seq:             2,
				CurrentSnapshot: filepath.Join(driverDir, "v002"),
				LastCoverage: &fuzzing.CoverageSummaryPoint{
					ExecutedFunctions: 8,
					FullFunctions:     5,
					PartialFunctions:  3,
					UncoveredCount:    4,
				},
			},
		},
	}
	if err := multiState.Save(statePath); err != nil {
		t.Fatal(err)
	}
	history := `{"driver_id":7,"seq":1,"regenerated":true,"analysis":{"analysis":"v2 的修改"}}` + "\n"
	if err := os.WriteFile(filepath.Join(fuzzingDir, "fuzzing-history.jsonl"), []byte(history), 0o644); err != nil {
		t.Fatal(err)
	}

	a := NewHistoricalAgent(targetDir, &state.RunState{SourceDir: "/src", BuildDir: "/build"}, logsDir)
	got, ok := a.SnapshotComparison().([]snapshotEntry)
	if !ok {
		t.Fatalf("SnapshotComparison type = %T", a.SnapshotComparison())
	}
	if len(got) != 2 {
		t.Fatalf("snapshot count = %d, want 2", len(got))
	}
	if got[0].DriverID != 7 || got[0].Seq != 1 || got[0].ExecutedFunctions != 5 || got[0].UncoveredCount != 7 {
		t.Fatalf("snapshot v1 = %#v", got[0])
	}
	if got[1].DriverID != 7 || got[1].Seq != 2 || got[1].ExecutedFunctions != 8 || got[1].UncoveredCount != 4 || got[1].Analysis != "v2 的修改" {
		t.Fatalf("snapshot v2 = %#v", got[1])
	}
}

func TestMultiSnapshotComparisonPrefersLiveCoverageCache(t *testing.T) {
	targetDir := t.TempDir()
	logsDir := filepath.Join(targetDir, "logs")
	fuzzingDir := filepath.Join(logsDir, "fuzzing")
	driverDir := filepath.Join(fuzzingDir, "driver-targets", "driver-0003", "v001")
	if err := os.MkdirAll(driverDir, 0o755); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(fuzzingDir, "multi-fuzzing-state.json")
	multiState := &fuzzing.MultiFuzzState{
		Targets: map[int]*fuzzing.TargetState{
			3: {
				DriverID:        3,
				Seq:             1,
				CurrentSnapshot: driverDir,
				LastCoverage: &fuzzing.CoverageSummaryPoint{
					ExecutedFunctions: 2,
					FullFunctions:     1,
					PartialFunctions:  1,
					UncoveredCount:    9,
				},
			},
		},
	}
	if err := multiState.Save(statePath); err != nil {
		t.Fatal(err)
	}
	a := &Agent{
		LogsDir: logsDir,
		State:   &state.RunState{SourceDir: "/src", BuildDir: "/build"},
		coverageData: fuzzing.MultiCoverageSnapshot{
			Targets: []fuzzing.TargetCoverageSnapshot{
				{
					DriverID: 3,
					Seq:      1,
					Summary: fuzzing.CoverageSummary{
						ExecutedFunctions: 11,
						FullFunctions:     6,
						PartialFunctions:  5,
					},
					UncoveredCount: 2,
				},
			},
		},
	}
	got, ok := a.SnapshotComparison().([]snapshotEntry)
	if !ok {
		t.Fatalf("SnapshotComparison type = %T", a.SnapshotComparison())
	}
	if len(got) != 1 {
		t.Fatalf("snapshot count = %d, want 1", len(got))
	}
	if got[0].ExecutedFunctions != 11 || got[0].UncoveredCount != 2 {
		t.Fatalf("live cache was not preferred: %#v", got[0])
	}
}
