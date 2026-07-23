package webui

import (
	"testing"

	"autofuzz/internal/fuzzing"
)

func TestFunctionLineCoveragePrefersSpecificZeroRegion(t *testing.T) {
	regions := []fuzzing.CoverageRegion{
		{StartLine: 274, StartColumn: 1, EndLine: 282, EndColumn: 2, Count: 4362, FileID: 0},
		{StartLine: 278, StartColumn: 3, EndLine: 278, EndColumn: 10, Count: 0, FileID: 0},
		{StartLine: 279, StartColumn: 1, EndLine: 279, EndColumn: 20, Count: 0, FileID: 1},
	}
	branches := []fuzzing.UncoveredBranch{
		{Location: [2]int{277, 6}, Missing: "true"},
		{Location: [2]int{277, 18}, Missing: "true"},
	}

	lines := functionLineCoverage(regions, branches, 274, 282)
	statusByLine := map[int]string{}
	for _, line := range lines {
		statusByLine[line.Line] = line.Status
	}

	if statusByLine[277] != "uncovered" {
		t.Fatalf("branch condition line status = %q, want uncovered", statusByLine[277])
	}
	if statusByLine[278] != "uncovered" {
		t.Fatalf("specific zero-count return line status = %q, want uncovered", statusByLine[278])
	}
	if statusByLine[279] != "covered" {
		t.Fatalf("outer covered line status = %q, want covered", statusByLine[279])
	}
}

func TestFunctionLineCoverageMapsMacroBranchToExpansionLine(t *testing.T) {
	regions := []fuzzing.CoverageRegion{
		{StartLine: 10, StartColumn: 1, EndLine: 14, EndColumn: 2, Count: 10, FileID: 0},
		{StartLine: 12, StartColumn: 3, EndLine: 12, EndColumn: 20, Count: 10, FileID: 0, ExpandedFileID: 1, Kind: 1},
		{StartLine: 100, StartColumn: 1, EndLine: 101, EndColumn: 2, Count: 0, FileID: 1},
	}
	branches := []fuzzing.UncoveredBranch{{
		Location:        [2]int{100, 5},
		ExpansionLine:   12,
		ExpansionColumn: 3,
		Missing:         "true",
	}}

	lines := functionLineCoverage(regions, branches, 10, 14)
	statusByLine := map[int]string{}
	for _, line := range lines {
		statusByLine[line.Line] = line.Status
	}

	if statusByLine[12] != "uncovered" {
		t.Fatalf("macro expansion line status = %q, want uncovered", statusByLine[12])
	}
	if _, ok := statusByLine[100]; ok {
		t.Fatal("macro definition line must not appear in function source line coverage")
	}
}
