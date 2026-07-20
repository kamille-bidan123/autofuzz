package fuzzing

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func mustMarshalExport(t *testing.T, fns []exportFunc) []byte {
	t.Helper()
	root := exportRoot{Data: []exportData{{Functions: fns}}}
	b, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestParseExportJSONBuildDir locks in the out-of-tree build fix: when the
// library sources were copied into the build directory, llvm-cov reports
// functions under build/*.c rather than source/*.c. Without buildDir they are
// filtered out (the historical "0 executed functions" bug); with buildDir they
// are counted.
func TestParseExportJSONBuildDir(t *testing.T) {
	sourceDir := t.TempDir()
	buildDir := t.TempDir()
	driverDir := t.TempDir()

	fns := []exportFunc{
		{Name: "src_fn", Filenames: []string{filepath.Join(sourceDir, "lib.c")}, Count: 3},
		{Name: "build_fn", Filenames: []string{filepath.Join(buildDir, "lib.c")}, Count: 7},
		{Name: "driver_fn", Filenames: []string{filepath.Join(driverDir, "entry.c")}, Count: 2},
		{Name: "unrelated_fn", Filenames: []string{"/elsewhere/other.c"}, Count: 9},
	}
	data := mustMarshalExport(t, fns)

	t.Run("with_buildDir", func(t *testing.T) {
		got, err := parseExportJSON(data, sourceDir, buildDir, driverDir)
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]bool{}
		for _, f := range got {
			names[f.name] = true
		}
		if len(got) != 3 || !names["src_fn"] || !names["build_fn"] || !names["driver_fn"] {
			t.Fatalf("expected src_fn+build_fn+driver_fn (3), got %d: %v", len(got), names)
		}
		if names["unrelated_fn"] {
			t.Fatal("unrelated_fn should have been filtered out")
		}
	})

	t.Run("without_buildDir", func(t *testing.T) {
		// Regression guard: build_fn must be filtered out when buildDir is
		// empty, matching the pre-fix behavior that caused 0 executed
		// functions for out-of-tree builds.
		got, err := parseExportJSON(data, sourceDir, "", driverDir)
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]bool{}
		for _, f := range got {
			names[f.name] = true
		}
		if names["build_fn"] {
			t.Fatal("build_fn must be filtered out when buildDir is empty")
		}
		if len(got) != 2 || !names["src_fn"] || !names["driver_fn"] {
			t.Fatalf("expected src_fn+driver_fn (2), got %d: %v", len(got), names)
		}
	})
}

// TestParseBranchReachBuildDir mirrors the buildDir filter for the per-seed
// branch-reach path used by the corpus monitor's incremental replay.
func TestParseBranchReachBuildDir(t *testing.T) {
	sourceDir := t.TempDir()
	buildDir := t.TempDir()
	// Branch row: [line, col, endLine, endCol, trueCount, falseCount].
	fns := []exportFunc{
		{Name: "src_fn", Filenames: []string{filepath.Join(sourceDir, "lib.c")}, Count: 1, Branches: [][]int64{{10, 0, 11, 0, 1, 0}}},
		{Name: "build_fn", Filenames: []string{filepath.Join(buildDir, "lib.c")}, Count: 1, Branches: [][]int64{{20, 0, 21, 0, 0, 1}}},
	}
	data := mustMarshalExport(t, fns)

	withBuild, err := parseBranchReach(data, sourceDir, buildDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := withBuild["build_fn"]; !ok {
		t.Fatalf("build_fn should be reached when buildDir is set, got %v", withBuild)
	}
	if _, ok := withBuild["src_fn"]; !ok {
		t.Fatalf("src_fn should be reached, got %v", withBuild)
	}

	withoutBuild, err := parseBranchReach(data, sourceDir, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := withoutBuild["build_fn"]; ok {
		t.Fatal("build_fn must be filtered out when buildDir is empty")
	}
	if _, ok := withoutBuild["src_fn"]; !ok {
		t.Fatalf("src_fn should still be reached, got %v", withoutBuild)
	}
}
