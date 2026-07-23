package fuzzing

import (
	"encoding/json"
	"testing"
)

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
			Function: p.fn, File: p.file, EntryCount: 1,
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
	file     string
	branches []UncoveredBranch
}

func ub(loc [2]int, cond string) UncoveredBranch {
	return UncoveredBranch{Location: loc, Condition: cond, Missing: "true", Counts: map[string]int64{"true": 0, "false": 1}}
}

func TestCoverageStatusToCorpusCoverageAggregateOnly(t *testing.T) {
	aggregate := coverageWith(
		[]string{"f3"},
		partialSpec{"f2", "b.c", []UncoveredBranch{ub([2]int{20, 3}, "y==2")}},
		partialSpec{"f1", "a.c", []UncoveredBranch{ub([2]int{10, 1}, "x==1")}},
	)

	got := CoverageStatusToCorpusCoverage(aggregate, 42, false, "/corpus")
	if got.SeedCount != 42 || got.Sampled {
		t.Fatalf("seed metadata = count %d sampled %v, want 42 false", got.SeedCount, got.Sampled)
	}
	if got.Summary.ExecutedFunctions != 3 || got.Summary.FullFunctions != 1 || got.Summary.PartialFunctions != 2 {
		t.Fatalf("summary = %#v", got.Summary)
	}
	if len(got.Uncovered) != 2 {
		t.Fatalf("uncovered len = %d, want 2", len(got.Uncovered))
	}
	if got.Uncovered[0].Function != "f1" || got.Uncovered[0].File != "a.c" ||
		got.Uncovered[0].Line != 10 || got.Uncovered[0].Column != 1 {
		t.Fatalf("first uncovered branch not sorted/exposed as expected: %#v", got.Uncovered[0])
	}
	if got.Uncovered[1].Function != "f2" || got.Uncovered[1].Column != 3 {
		t.Fatalf("second uncovered branch not exposed as expected: %#v", got.Uncovered[1])
	}
}

func TestCoverageStatusToCorpusCoverageCapsUncoveredBranches(t *testing.T) {
	var branches []UncoveredBranch
	for i := 0; i < DefaultMaxUncoveredBranches+5; i++ {
		branches = append(branches, ub([2]int{i + 1, 1}, "x"))
	}
	got := CoverageStatusToCorpusCoverage(
		coverageWith(nil, partialSpec{"f", "x.c", branches}),
		1,
		false,
		"/corpus",
	)
	if len(got.Uncovered) != DefaultMaxUncoveredBranches {
		t.Fatalf("uncovered len = %d, want cap %d", len(got.Uncovered), DefaultMaxUncoveredBranches)
	}
}

func TestCoverageStatusToCorpusCoverageClonesBranchCounts(t *testing.T) {
	branch := ub([2]int{10, 1}, "x==1")
	aggregate := coverageWith(nil, partialSpec{"f", "x.c", []UncoveredBranch{branch}})
	got := CoverageStatusToCorpusCoverage(aggregate, 1, false, "/corpus")
	got.Uncovered[0].Counts["false"] = 99
	if aggregate.Partial[0].UncoveredBranches[0].Counts["false"] == 99 {
		t.Fatal("corpus coverage status aliased source uncovered branch counts")
	}
}

func TestUncoveredBranchStatusJSONHasNoSeedReach(t *testing.T) {
	u := UncoveredBranchStatus{
		Function:  "parse",
		File:      "p.c",
		Line:      12,
		Column:    4,
		Condition: "x==1",
		Missing:   "true",
		Counts:    map[string]int64{"true": 0, "false": 9},
	}
	data, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"line", "column", "condition", "missing", "counts", "function", "file"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing json key %q in %s", k, string(data))
		}
	}
	for _, k := range []string{"location", "reaching_seeds", "reach_count"} {
		if _, ok := m[k]; ok {
			t.Errorf("json key %q must not be present: %s", k, string(data))
		}
	}
	if line, _ := m["line"].(float64); int(line) != 12 {
		t.Errorf("line: got %v want 12", m["line"])
	}
	if column, _ := m["column"].(float64); int(column) != 4 {
		t.Errorf("column: got %v want 4", m["column"])
	}
}
