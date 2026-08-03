package webui

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"autofuzz/internal/state"
)

func TestReadFunctionSourceAllowsTaskLocalCoverageFiles(t *testing.T) {
	targetDir := t.TempDir()
	sourceDir := filepath.Join(targetDir, "source")
	buildDir := filepath.Join(targetDir, "build")
	extraDir := filepath.Join(targetDir, "freetype-2.13.3", "builds", "unix")
	for _, dir := range []string{sourceDir, buildDir, extraDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	runState := state.New("repo", "", "sample", sourceDir)
	runState.BuildDir = buildDir
	if err := runState.Save(filepath.Join(targetDir, "agent-state.json")); err != nil {
		t.Fatal(err)
	}

	sourcePath := filepath.Join(extraDir, "ftsystem.c")
	if err := os.WriteFile(sourcePath, []byte(strings.Join([]string{
		"int helper(void) {",
		"  return 0;",
		"}",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}

	roots := coverageSourceRoots(targetDir, 0)
	got, truncated, displayEndLine, readErr := readFunctionSource(sourcePath, 1, 3, roots, map[string][]string{})
	if readErr != "" {
		t.Fatalf("readFunctionSource() error = %q, want success", readErr)
	}
	if truncated {
		t.Fatal("readFunctionSource() unexpectedly truncated source")
	}
	if displayEndLine != 3 {
		t.Fatalf("displayEndLine = %d, want 3", displayEndLine)
	}
	if !strings.Contains(got, "return 0;") {
		t.Fatalf("source snippet = %q, want task-local file contents", got)
	}
}

func TestCoverageFunctionSourcesUsesPersistedRegionsFromCache(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	workspace := t.TempDir()
	targetDir := filepath.Join(workspace, "cached-lib")
	sourceDir := filepath.Join(targetDir, "pkg")
	snapshotDir := filepath.Join(targetDir, "logs", "fuzzing", "driver-targets", "driver-0001", "v001")
	if err := os.MkdirAll(filepath.Join(snapshotDir, "monitor"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatal(err)
	}

	sourcePath := filepath.Join(sourceDir, "sample.c")
	if err := os.WriteFile(sourcePath, []byte(strings.Join([]string{
		"if (flag)",
		"  return 1;",
		"return 0;",
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}

	cache := map[string]any{
		"timestamp":  time.Date(2026, 8, 2, 4, 5, 6, 0, time.UTC).Format(time.RFC3339),
		"available":  true,
		"seed_count": 1,
		"coverage": map[string]any{
			"summary": map[string]any{
				"executed_functions": 1,
				"full_functions":     0,
				"partial_functions":  1,
			},
			"full": []any{},
			"partial": []any{
				map[string]any{
					"function":    "sample",
					"file":        sourcePath,
					"start_line":  1,
					"end_line":    3,
					"entry_count": 5,
					"uncovered_branches": []any{
						map[string]any{
							"location":  []int{1, 5},
							"condition": "flag",
							"missing":   "true",
							"counts": map[string]int64{
								"true":  0,
								"false": 5,
							},
						},
					},
					"regions": []any{
						map[string]any{
							"StartLine":      1,
							"StartColumn":    1,
							"EndLine":        3,
							"EndColumn":      10,
							"Count":          5,
							"FileID":         0,
							"ExpandedFileID": 0,
							"Kind":           0,
						},
						map[string]any{
							"StartLine":      2,
							"StartColumn":    3,
							"EndLine":        2,
							"EndColumn":      12,
							"Count":          0,
							"FileID":         0,
							"ExpandedFileID": 0,
							"Kind":           0,
						},
					},
				},
			},
		},
	}
	cacheData, err := json.Marshal(cache)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapshotDir, "monitor", "coverage-cache.json"), cacheData, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := upsertTaskRegistry(registryEntry{
		ID:            "historical-region-cache",
		Workspace:     workspace,
		Name:          "cached-lib",
		RepositoryURL: "https://example.com/cached-lib.git",
		CreatedAt:     time.Date(2026, 8, 2, 4, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Status:        "completed",
	}); err != nil {
		t.Fatal(err)
	}

	manager := NewManager(context.Background())
	response, err := manager.CoverageFunctionSources("historical-region-cache", 1, 1)
	if err != nil {
		t.Fatalf("CoverageFunctionSources() error = %v", err)
	}
	if !response.Available || len(response.Functions) != 1 {
		t.Fatalf("unexpected coverage response: %#v", response)
	}
	lines := response.Functions[0].Lines
	if len(lines) != 3 {
		t.Fatalf("line coverage len = %d, want 3", len(lines))
	}
	if lines[0].Status != "uncovered" {
		t.Fatalf("branch line status = %q, want uncovered", lines[0].Status)
	}
	if lines[1].Status != "uncovered" || lines[1].Count != 0 {
		t.Fatalf("return line = %#v, want uncovered count=0", lines[1])
	}
}
