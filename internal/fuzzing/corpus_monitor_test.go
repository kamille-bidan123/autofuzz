package fuzzing

import (
	"os"
	"path/filepath"
	"testing"
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
