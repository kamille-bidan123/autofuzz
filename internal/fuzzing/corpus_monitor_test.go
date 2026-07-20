package fuzzing

import (
	"path/filepath"
	"testing"
)

func TestReachFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reach", "seed-abc")
	original := map[string]map[[2]int]bool{
		"BZ2_compress":  {[2]int{12, 5}: true, [2]int{18, 9}: true},
		"BZ2_decompress": {[2]int{40, 7}: true},
	}
	if err := writeReachFile(path, original); err != nil {
		t.Fatalf("writeReachFile: %v", err)
	}

	got, err := loadReachFile(path)
	if err != nil {
		t.Fatalf("loadReachFile: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("function count: got %d, want 2", len(got))
	}
	if !got["BZ2_compress"][[2]int{12, 5}] || !got["BZ2_compress"][[2]int{18, 9}] {
		t.Fatalf("BZ2_compress locations mismatch: %#v", got["BZ2_compress"])
	}
	if !got["BZ2_decompress"][[2]int{40, 7}] {
		t.Fatalf("BZ2_decompress location missing")
	}
}

func TestReachFileMissing(t *testing.T) {
	if _, err := loadReachFile(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestBuildUncoveredSites(t *testing.T) {
	cs := CoverageStatus{
		Partial: []PartialFunctionCoverage{
			{
				Function: "foo",
				UncoveredBranches: []UncoveredBranch{
					{Location: [2]int{10, 3}},
					{Location: [2]int{20, 7}},
				},
			},
			{
				Function: "bar",
				UncoveredBranches: []UncoveredBranch{
					{Location: [2]int{5, 1}},
				},
			},
		},
	}
	sites := buildUncoveredSites(cs)
	if !sites["foo"][[2]int{10, 3}] || !sites["foo"][[2]int{20, 7}] {
		t.Fatalf("foo sites wrong: %#v", sites["foo"])
	}
	if !sites["bar"][[2]int{5, 1}] {
		t.Fatal("bar site missing")
	}

	// empty CoverageStatus → nil
	if got := buildUncoveredSites(CoverageStatus{}); got != nil {
		t.Fatalf("expected nil for empty status, got %v", got)
	}
}
