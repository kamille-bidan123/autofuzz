package fuzzing

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCountCorpusSeedsCountsOnlyTopLevelFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "seed-a"), []byte("a"), 0o644); err != nil {
		t.Fatalf("write seed-a: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "seed-b"), []byte("b"), 0o644); err != nil {
		t.Fatalf("write seed-b: %v", err)
	}
	nested := filepath.Join(dir, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "seed-c"), []byte("c"), 0o644); err != nil {
		t.Fatalf("write nested seed: %v", err)
	}

	if got := countCorpusSeeds(dir); got != 2 {
		t.Fatalf("countCorpusSeeds() = %d, want 2", got)
	}
}

func TestCountCorpusSeedsMissingDir(t *testing.T) {
	if got := countCorpusSeeds(filepath.Join(t.TempDir(), "missing")); got != 0 {
		t.Fatalf("countCorpusSeeds(missing) = %d, want 0", got)
	}
}

func TestMergeableProfrawFilesSkipsEmptyProfiles(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "live-empty.profraw")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatalf("write empty profraw: %v", err)
	}
	nonEmpty := filepath.Join(dir, "live-complete.profraw")
	if err := os.WriteFile(nonEmpty, []byte("profile"), 0o644); err != nil {
		t.Fatalf("write non-empty profraw: %v", err)
	}
	ignored := filepath.Join(dir, "not-profile.txt")
	if err := os.WriteFile(ignored, []byte("profile"), 0o644); err != nil {
		t.Fatalf("write ignored file: %v", err)
	}

	got := mergeableProfrawFiles(dir)
	if len(got) != 1 || got[0] != nonEmpty {
		t.Fatalf("mergeableProfrawFiles() = %#v, want [%q]", got, nonEmpty)
	}
	if _, err := os.Stat(empty); err != nil {
		t.Fatalf("empty profraw should be retained: %v", err)
	}
}

func TestSafeCrashReportName(t *testing.T) {
	tests := map[string]string{
		"crash-abc":        "crash-abc",
		"oom:bad/input":    "input",
		"weird name!":      "weird_name_",
		"../../crash-file": "crash-file",
		"***":              "crash",
	}
	for input, want := range tests {
		if got := safeCrashReportName(input); got != want {
			t.Fatalf("safeCrashReportName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestShouldSkipCrashLLMAnalysisForTimeoutAndSlowUnit(t *testing.T) {
	tests := []CrashAnalysisEntry{
		{File: "crash-a", Type: "timeout"},
		{File: "crash-a", Type: "slowunit"},
		{File: "crash-a", Type: "slow-unit"},
		{File: "timeout-123", Type: "unknown"},
		{File: "slow-unit-123", Type: "unknown"},
		{File: "slowunit-123", Type: ""},
	}
	for _, entry := range tests {
		if !shouldSkipCrashLLMAnalysis(entry) {
			t.Fatalf("shouldSkipCrashLLMAnalysis(%#v) = false, want true", entry)
		}
	}
	if shouldSkipCrashLLMAnalysis(CrashAnalysisEntry{File: "crash-123", Type: "heap-buffer-overflow"}) {
		t.Fatal("heap-buffer-overflow crash should not be skipped")
	}
	if shouldSkipCrashLLMAnalysis(CrashAnalysisEntry{File: "leak-123", Type: "timeout"}) {
		t.Fatal("leak artifact should not be skipped even if a legacy replay stored timeout")
	}
}

func TestEnsureCrashEntryPathsMarksSkippedCrashTypes(t *testing.T) {
	snapDir := t.TempDir()
	monitor := NewCorpusMonitor(FuzzConfig{}, filepath.Join(snapDir, "monitor"))
	entry := CrashAnalysisEntry{File: "timeout-abc", Type: "unknown", ReportStatus: "pending"}

	monitor.ensureCrashEntryPaths(&entry)

	if entry.ReportStatus != "skipped" {
		t.Fatalf("ReportStatus = %q, want skipped", entry.ReportStatus)
	}
	if entry.ReportError == "" {
		t.Fatal("ReportError should explain skipped analysis")
	}
}

func TestEnsureCrashEntryPathsNormalizesLeakArtifactType(t *testing.T) {
	snapDir := t.TempDir()
	monitor := NewCorpusMonitor(FuzzConfig{}, filepath.Join(snapDir, "monitor"))
	entry := CrashAnalysisEntry{File: "leak-abc", Type: "timeout"}

	monitor.ensureCrashEntryPaths(&entry)

	if entry.Type != "leak" {
		t.Fatalf("Type = %q, want leak", entry.Type)
	}
	if entry.ReportStatus != "pending" {
		t.Fatalf("ReportStatus = %q, want pending", entry.ReportStatus)
	}
}

func TestRefreshCoverageCachePreservesExistingSnapshotOnError(t *testing.T) {
	snapDir := t.TempDir()
	workDir := filepath.Join(snapDir, "monitor")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("mkdir work dir: %v", err)
	}
	profdataPath := filepath.Join(workDir, "aggregate.profdata")
	if err := os.WriteFile(profdataPath, []byte("not-a-real-profdata"), 0o644); err != nil {
		t.Fatalf("write profdata: %v", err)
	}
	corpusDir := filepath.Join(snapDir, "corpus")
	if err := os.MkdirAll(corpusDir, 0o755); err != nil {
		t.Fatalf("mkdir corpus: %v", err)
	}
	if err := os.WriteFile(filepath.Join(corpusDir, "seed"), []byte("seed"), 0o644); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	monitor := NewCorpusMonitor(FuzzConfig{
		BinaryPath: "/nonexistent/cov_driver",
		CorpusDir:  corpusDir,
	}, workDir)
	want := CoverageStatus{Summary: CoverageSummary{
		ExecutedFunctions: 3,
		FullFunctions:     1,
		PartialFunctions:  2,
	}}
	monitor.covCache = CoverageSnapshot{
		Timestamp: time.Now(),
		Available: true,
		SeedCount: 7,
		Coverage:  want,
	}

	if err := monitor.RefreshCoverageCache(nil); err == nil {
		t.Fatal("RefreshCoverageCache() error = nil, want failure")
	}
	got := monitor.CoverageCache()
	if !got.Available {
		t.Fatal("coverage cache should keep the last successful snapshot")
	}
	if got.SeedCount != 7 {
		t.Fatalf("SeedCount = %d, want preserved value 7", got.SeedCount)
	}
	if got.Coverage.Summary != want.Summary {
		t.Fatalf("coverage summary = %#v, want %#v", got.Coverage.Summary, want.Summary)
	}
}

func TestScanAndAnalyzeCrashesUsesIsolatedReplayWorkspace(t *testing.T) {
	snapDir := t.TempDir()
	for _, dir := range []string{"monitor", "crashes", "unique_crashes"} {
		if err := os.MkdirAll(filepath.Join(snapDir, dir), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	binaryPath := filepath.Join(snapDir, "cov_driver")
	script := "#!/bin/sh\nset -eu\n[ -f ./resource.txt ]\nprintf replay > ./dummy_file\nexit 0\n"
	if err := os.WriteFile(binaryPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write replay script: %v", err)
	}
	if err := os.WriteFile(filepath.Join(snapDir, "resource.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatalf("write resource: %v", err)
	}
	crashName := "timeout-crash-1"
	crashPath := filepath.Join(snapDir, "crashes", crashName)
	if err := os.WriteFile(crashPath, []byte("boom"), 0o644); err != nil {
		t.Fatalf("write crash input: %v", err)
	}

	monitor := NewCorpusMonitor(FuzzConfig{BinaryPath: binaryPath}, filepath.Join(snapDir, "monitor"))
	monitor.scanAndAnalyzeCrashes(context.Background())

	if _, err := os.Stat(filepath.Join(snapDir, "dummy_file")); !os.IsNotExist(err) {
		t.Fatalf("snapshot root dummy_file should not exist, got err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(snapDir, "crashes", "dummy_file")); !os.IsNotExist(err) {
		t.Fatalf("crashes/dummy_file should not exist, got err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(snapDir, "unique_crashes", crashName)); err != nil {
		t.Fatalf("unique crash copy missing: %v", err)
	}
	if summary := monitor.CrashAnalysisData(); summary.Total != 1 || summary.Unique != 1 {
		t.Fatalf("CrashAnalysisData() = %#v, want total=1 unique=1", summary)
	}
	entry, ok := monitor.crashEntry(crashName)
	if !ok {
		t.Fatalf("crash entry for %s not found", crashName)
	}
	if entry.ReportStatus != "skipped" {
		t.Fatalf("ReportStatus = %q, want skipped", entry.ReportStatus)
	}
	entries, err := os.ReadDir(filepath.Join(snapDir, "crashes"))
	if err != nil {
		t.Fatalf("readdir crashes: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != crashName {
		t.Fatalf("crashes dir entries = %#v, want only %q", entries, crashName)
	}
}
