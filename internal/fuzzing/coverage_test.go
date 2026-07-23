package fuzzing

import (
	"encoding/json"
	"os"
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

func TestParseExportJSONFunctionLineRange(t *testing.T) {
	sourceDir := t.TempDir()
	sourceFile := filepath.Join(sourceDir, "lib.c")
	if err := os.WriteFile(sourceFile, []byte("int foo(void) {\n  if (1) return 1;\n  return 0;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	data := mustMarshalExport(t, []exportFunc{{
		Name:      "foo",
		Filenames: []string{sourceFile},
		Count:     1,
		Regions: [][]int64{
			{1, 1, 4, 2, 1},
			{2, 3, 2, 18, 1},
		},
	}})
	got, err := parseExportJSON(data, sourceDir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("function count = %d, want 1", len(got))
	}
	if got[0].startLine != 1 || got[0].endLine != 4 {
		t.Fatalf("line range = %d-%d, want 1-4", got[0].startLine, got[0].endLine)
	}
	if len(got[0].regions) != 2 || got[0].regions[0].Count != 1 || got[0].regions[0].StartLine != 1 {
		t.Fatalf("regions were not preserved: %#v", got[0].regions)
	}
}

func TestParseExportJSONMacroExpansionKeepsFunctionRangeInMainFile(t *testing.T) {
	sourceDir := t.TempDir()
	sourceFile := filepath.Join(sourceDir, "test.c")
	macroFile := filepath.Join(sourceDir, "macro.h")
	if err := os.WriteFile(sourceFile, []byte("#include \"macro.h\"\nint target(int *p) {\n  CHECK_NULL_OR_RETURN(p);\n  return 1;\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(macroFile, []byte("#define CHECK_NULL_OR_RETURN(p) \\\n  do { \\\n    if (!(p)) return 0; \\\n  } while (0)\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	data := mustMarshalExport(t, []exportFunc{{
		Name:      "target",
		Filenames: []string{sourceFile, macroFile},
		Count:     1,
		Regions: [][]int64{
			{2, 20, 5, 2, 1, 0, 0, 0},
			{3, 3, 3, 23, 1, 0, 1, 1},    // macro expansion site in test.c
			{50, 3, 52, 14, 1, 1, 0, 0},  // macro body in macro.h; must not expand function block range
			{51, 15, 51, 23, 0, 1, 0, 0}, // uncovered macro return region
		},
		Branches: [][]int64{
			{51, 9, 51, 13, 0, 1, 1, 0, 4}, // branch in macro.h mapped to test.c line 3
		},
	}})
	got, err := parseExportJSON(data, sourceDir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("function count = %d, want 1", len(got))
	}
	if got[0].startLine != 2 || got[0].endLine != 5 {
		t.Fatalf("function range = %d-%d, want main-file range 2-5", got[0].startLine, got[0].endLine)
	}
	if len(got[0].uncovered) != 1 {
		t.Fatalf("uncovered branches = %#v, want 1", got[0].uncovered)
	}
	branch := got[0].uncovered[0]
	if branch.File != macroFile || branch.Location != [2]int{51, 9} {
		t.Fatalf("macro branch source = file %q loc %#v, want macro.h L51:9", branch.File, branch.Location)
	}
	if branch.ExpansionFile != sourceFile || branch.ExpansionLine != 3 || branch.ExpansionColumn != 3 {
		t.Fatalf("macro branch expansion = %q L%d:%d, want test.c L3:3", branch.ExpansionFile, branch.ExpansionLine, branch.ExpansionColumn)
	}
}

// TestParseBranchReachBuildDir mirrors the buildDir filter for proof-seed
// branch-site reach validation.
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

// TestParseExportJSONSymlinkedSourcePath covers GN source-root mappings such
// as third_party/libexif -> source. Clang records the symlinked spelling in the
// coverage mapping, while the task state retains the physical source path.
func TestParseExportJSONSymlinkedSourcePath(t *testing.T) {
	root := t.TempDir()
	sourceDir := filepath.Join(root, "source")
	if err := os.MkdirAll(filepath.Join(sourceDir, "libexif"), 0o755); err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(sourceDir, "libexif", "exif-data.c")
	if err := os.WriteFile(realFile, []byte("int exif_data(void) { return 1; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	thirdPartyDir := filepath.Join(root, "third_party")
	if err := os.MkdirAll(thirdPartyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	aliasDir := filepath.Join(thirdPartyDir, "libexif")
	if err := os.Symlink(sourceDir, aliasDir); err != nil {
		t.Fatal(err)
	}
	aliasedFile := filepath.Join(aliasDir, "libexif", "exif-data.c")

	data := mustMarshalExport(t, []exportFunc{{
		Name:      "exif_data",
		Filenames: []string{aliasedFile},
		Count:     1,
	}})
	got, err := parseExportJSON(data, sourceDir, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].name != "exif_data" {
		t.Fatalf("expected symlinked source function to be retained, got %#v", got)
	}
	if !isPathUnder(aliasedFile, sourceDir) {
		t.Fatal("symlinked source file should be recognized under the physical source directory")
	}
}
