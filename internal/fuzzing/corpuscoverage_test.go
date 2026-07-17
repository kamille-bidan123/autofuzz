package fuzzing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func mkSeed(path string, size int64) seedFile {
	return seedFile{path: path, size: size}
}

type fnLoc struct {
	fn  string
	loc [2]int
}

// mkReach builds a per-seed branch-site reach map: for each entry, the branch
// at loc in function fn was evaluated (trueCount+falseCount > 0). A function
// entered but whose branch loc is absent means the seed returned before that
// branch site — the key case the attribution must exclude.
func mkReach(entries ...fnLoc) map[string]map[[2]int]bool {
	m := map[string]map[[2]int]bool{}
	for _, e := range entries {
		if m[e.fn] == nil {
			m[e.fn] = map[[2]int]bool{}
		}
		m[e.fn][e.loc] = true
	}
	return m
}

// coverageWith builds a CoverageStatus whose Full list contains the given
// function names (entry_count 1) and whose Partial list carries the given
// uncovered branches for the listed functions.
func coverageWith(fullNames []string, partial ...partialSpec) CoverageStatus {
	cs := CoverageStatus{
		Full:    []FunctionCoverage{},
		Partial: []PartialFunctionCoverage{},
	}
	for _, n := range fullNames {
		cs.Full = append(cs.Full, FunctionCoverage{Function: n, File: "x.c", EntryCount: 1})
	}
	for _, p := range partial {
		cs.Partial = append(cs.Partial, PartialFunctionCoverage{
			Function: p.fn, File: "x.c", EntryCount: 1,
			UncoveredBranches: p.branches,
		})
	}
	cs.Summary = CoverageSummary{
		ExecutedFunctions: len(fullNames) + len(partial),
		FullFunctions:     len(fullNames),
		PartialFunctions:  len(partial),
	}
	return cs
}

type partialSpec struct {
	fn       string
	branches []UncoveredBranch
}

func ub(loc [2]int, cond string) UncoveredBranch {
	return UncoveredBranch{Location: loc, Condition: cond, Missing: "true", Counts: map[string]int64{"true": 0, "false": 1}}
}

func TestBuildCorpusCoverageAttributionAndSorting(t *testing.T) {
	// Per-seed branch-site reach (drives attribution):
	//   seedA -> reached f1@[10,1] and f2@[20,1]
	//   seedB -> reached f2@[20,1]
	//   seedC -> reached nothing relevant (f3 is full in aggregate)
	seeds := []seedFile{
		mkSeed("/corpus/seedA", 100),
		mkSeed("/corpus/seedB", 50),
		mkSeed("/corpus/seedC", 30),
	}
	perSeed := []map[string]map[[2]int]bool{
		mkReach(fnLoc{"f1", [2]int{10, 1}}, fnLoc{"f2", [2]int{20, 1}}),
		mkReach(fnLoc{"f2", [2]int{20, 1}}),
		mkReach(),
	}

	// Aggregate: f1 partial (uncovered b1), f2 partial (uncovered b2), f4 partial
	// (uncovered b3, no seed reaches f4), f3 full.
	aggregate := coverageWith(
		[]string{"f3"},
		partialSpec{"f1", []UncoveredBranch{ub([2]int{10, 1}, "x==1")}},
		partialSpec{"f2", []UncoveredBranch{ub([2]int{20, 1}, "y==2")}},
		partialSpec{"f4", []UncoveredBranch{ub([2]int{40, 1}, "z==3")}},
	)

	got := buildCorpusCoverage(seeds, perSeed, aggregate, true, "/corpus")

	if got.SeedCount != 3 {
		t.Fatalf("SeedCount: got %d want 3", got.SeedCount)
	}
	if !got.Sampled {
		t.Errorf("Sampled: got false want true")
	}
	if got.Summary.ExecutedFunctions != 4 {
		t.Errorf("summary executed: got %d want 4", got.Summary.ExecutedFunctions)
	}

	// Uncovered: 3 branches. Expect ordering by reach count descending:
	//   b2 (f2) reach=[seedA,seedB] -> 2
	//   b1 (f1) reach=[seedA]       -> 1
	//   b3 (f4) reach=[]            -> 0
	if len(got.Uncovered) != 3 {
		t.Fatalf("uncovered len: got %d want 3", len(got.Uncovered))
	}
	wantOrder := []struct {
		fn    string
		reach int
	}{
		{"f2", 2},
		{"f1", 1},
		{"f4", 0},
	}
	for i, w := range wantOrder {
		u := got.Uncovered[i]
		if u.Function != w.fn || u.ReachCount != w.reach {
			t.Errorf("uncovered[%d]: got fn=%s reach=%d; want fn=%s reach=%d",
				i, u.Function, u.ReachCount, w.fn, w.reach)
		}
	}
	// Reaching seeds for b2 should list both, in seed order.
	if !reflect.DeepEqual(got.Uncovered[0].ReachingSeeds, []string{"seedA", "seedB"}) {
		t.Errorf("b2 reaching: got %v want [seedA seedB]", got.Uncovered[0].ReachingSeeds)
	}
}

// TestBuildCorpusCoverageBranchSiteNotFunctionReach is the key correctness
// case: a seed that ENTERED the function (and even reached an earlier branch
// in it) but did NOT reach the stuck branch site must be EXCLUDED from
// reaching_seeds. Function-level reach would wrongly include it.
func TestBuildCorpusCoverageBranchSiteNotFunctionReach(t *testing.T) {
	seeds := []seedFile{
		mkSeed("/corpus/earlyReturn", 10), // entered f1, reached [5,1], NOT [10,1]
		mkSeed("/corpus/hitsSite", 20),    // entered f1, reached [10,1]
	}
	perSeed := []map[string]map[[2]int]bool{
		mkReach(fnLoc{"f1", [2]int{5, 1}}), // early return before [10,1]
		mkReach(fnLoc{"f1", [2]int{10, 1}}),
	}
	// Aggregate: f1 uncovered at [10,1] (the missing direction never taken
	// across all seeds). [5,1] is covered (both seeds reached it) so not listed.
	aggregate := coverageWith(nil, partialSpec{"f1", []UncoveredBranch{ub([2]int{10, 1}, "x==1")}})

	got := buildCorpusCoverage(seeds, perSeed, aggregate, false, "/corpus")

	if len(got.Uncovered) != 1 {
		t.Fatalf("uncovered len: got %d want 1", len(got.Uncovered))
	}
	u := got.Uncovered[0]
	if u.ReachCount != 1 {
		t.Errorf("ReachCount: got %d want 1 (only hitsSite reached the branch site)", u.ReachCount)
	}
	if !reflect.DeepEqual(u.ReachingSeeds, []string{"hitsSite"}) {
		t.Errorf("ReachingSeeds: got %v want [hitsSite]; earlyReturn must be excluded", u.ReachingSeeds)
	}
}

func TestBuildCorpusCoverageCrashedSeedSkipped(t *testing.T) {
	seeds := []seedFile{mkSeed("/corpus/s1", 10), mkSeed("/corpus/s2", 5)}
	// s2 crashed -> nil reach map (runSeedCoverage returns nil on crash).
	perSeed := []map[string]map[[2]int]bool{
		mkReach(fnLoc{"f1", [2]int{1, 1}}),
		nil, // crashed -> no reach data
	}
	aggregate := coverageWith(nil, partialSpec{"f1", []UncoveredBranch{ub([2]int{1, 1}, "c")}})

	got := buildCorpusCoverage(seeds, perSeed, aggregate, false, "/corpus")

	// f1 branch site reached only by s1 (crashed s2 contributes nothing) -> [s1].
	if len(got.Uncovered) != 1 || got.Uncovered[0].ReachCount != 1 {
		t.Errorf("expected one uncovered branch with reach count 1, got %+v", got.Uncovered)
	}
	if !reflect.DeepEqual(got.Uncovered[0].ReachingSeeds, []string{"s1"}) {
		t.Errorf("reaching: got %v want [s1]", got.Uncovered[0].ReachingSeeds)
	}
}

func TestListSeedFilesAndSizeSort(t *testing.T) {
	dir := t.TempDir()
	for _, s := range []struct {
		name string
		size int
	}{
		{"a", 10}, {"b", 50}, {"c", 30},
	} {
		if err := os.WriteFile(filepath.Join(dir, s.name), make([]byte, s.size), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Add a subdirectory, which must be ignored.
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := listSeedFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d seeds, want 3", len(got))
	}
	// listSeedFiles returns ReadDir order; CollectCorpusCoverage sorts by size
	// descending. Apply the same comparator and verify the ordering.
	sort.Slice(got, func(i, j int) bool { return got[i].size > got[j].size })
	var sizes []int64
	for _, s := range got {
		sizes = append(sizes, s.size)
	}
	if !reflect.DeepEqual(sizes, []int64{50, 30, 10}) {
		t.Errorf("sizes after sort: got %v want [50 30 10]", sizes)
	}
}

func TestCapStrings(t *testing.T) {
	in := []string{"a", "b", "c"}
	if got := capStrings(in, 5); !reflect.DeepEqual(got, in) {
		t.Errorf("capStrings(3,5): got %v want %v", got, in)
	}
	if got := capStrings(in, 2); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("capStrings(3,2): got %v want [a b]", got)
	}
}

func TestUncoveredBranchWithReachJSON(t *testing.T) {
	u := UncoveredBranchWithReach{
		Function:      "parse",
		File:          "p.c",
		Line:          12,
		Condition:     "x==1",
		Missing:       "true",
		Counts:        map[string]int64{"true": 0, "false": 9},
		ReachingSeeds: []string{"s1"},
		ReachCount:    1,
	}
	data, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	// Line is surfaced (not [line,col]); condition/missing/counts present.
	for _, k := range []string{"line", "condition", "missing", "counts", "function", "file", "reaching_seeds", "reach_count"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing json key %q in %s", k, string(data))
		}
	}
	if _, ok := m["location"]; ok {
		t.Errorf("location must not be present (line-only): %s", string(data))
	}
	if line, _ := m["line"].(float64); int(line) != 12 {
		t.Errorf("line: got %v want 12", m["line"])
	}
}
