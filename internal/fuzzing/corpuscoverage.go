package fuzzing

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"
)

const (
	DefaultMaxUncoveredBranches = 60
	defaultPerSeedTimeout       = 10 * time.Second
)

// CorpusCoverageStatus describes aggregate source-level coverage for one
// fuzz driver. It intentionally does not include per-seed reach attribution:
// the LLM receives function/branch coverage status only.
type CorpusCoverageStatus struct {
	Summary   CoverageSummary         `json:"summary"`
	SeedCount int                     `json:"seed_count"`
	Sampled   bool                    `json:"sampled"`
	CorpusDir string                  `json:"corpus_dir"`
	Uncovered []UncoveredBranchStatus `json:"uncovered"`
}

// UncoveredBranchStatus is one aggregate uncovered source branch exposed to
// the LLM. Line+column identify the branch site; missing describes the branch
// direction whose count is still zero.
type UncoveredBranchStatus struct {
	Function  string           `json:"function"`
	File      string           `json:"file"`
	Line      int              `json:"line"`
	Column    int              `json:"column"`
	Condition string           `json:"condition"`
	Missing   string           `json:"missing"`
	Counts    map[string]int64 `json:"counts"`
}

// CoverageStatusToCorpusCoverage converts llvm-cov aggregate output into the
// compact status passed to the LLM.
func CoverageStatusToCorpusCoverage(aggregate CoverageStatus, seedCount int, sampled bool, corpusDir string) CorpusCoverageStatus {
	status := CorpusCoverageStatus{
		Summary:   aggregate.Summary,
		SeedCount: seedCount,
		Sampled:   sampled,
		CorpusDir: corpusDir,
		Uncovered: []UncoveredBranchStatus{},
	}

	for _, pf := range aggregate.Partial {
		for _, br := range pf.UncoveredBranches {
			status.Uncovered = append(status.Uncovered, UncoveredBranchStatus{
				Function:  pf.Function,
				File:      pf.File,
				Line:      br.Location[0],
				Column:    br.Location[1],
				Condition: br.Condition,
				Missing:   br.Missing,
				Counts:    cloneCounts(br.Counts),
			})
		}
	}

	sort.SliceStable(status.Uncovered, func(i, j int) bool {
		if status.Uncovered[i].File != status.Uncovered[j].File {
			return status.Uncovered[i].File < status.Uncovered[j].File
		}
		if status.Uncovered[i].Function != status.Uncovered[j].Function {
			return status.Uncovered[i].Function < status.Uncovered[j].Function
		}
		if status.Uncovered[i].Line != status.Uncovered[j].Line {
			return status.Uncovered[i].Line < status.Uncovered[j].Line
		}
		return status.Uncovered[i].Column < status.Uncovered[j].Column
	})
	if len(status.Uncovered) > DefaultMaxUncoveredBranches {
		status.Uncovered = status.Uncovered[:DefaultMaxUncoveredBranches]
	}

	return status
}

// runSeedCoverage runs the coverage-instrumented driver on one proof seed with
// -runs=1 and returns the set of branch locations each function reached
// (trueCount+falseCount > 0). ok=false means no usable profile was produced
// (e.g. ASan abort). This is used only to verify an LLM-provided proof seed,
// not to replay the corpus for analysis.
func runSeedCoverage(ctx context.Context, binaryPath, sourceDir, buildDir, taskDir, driverDir, seedPath, logDir string, idx int) (map[string]map[[2]int]bool, bool) {
	profrawPath := filepath.Join(logDir, fmt.Sprintf("seed-%d.profraw", idx))
	profdataPath := filepath.Join(logDir, fmt.Sprintf("seed-%d.profdata", idx))
	seedCtx, cancel := context.WithTimeout(ctx, defaultPerSeedTimeout)
	defer cancel()

	cmd := exec.CommandContext(seedCtx, binaryPath, "-runs=1", seedPath)
	cmd.Dir = driverDir
	cmd.Env = withAsanSymbolizeDisabled(append(os.Environ(), "LLVM_PROFILE_FILE="+profrawPath))
	// Stdout/stderr left nil: output is discarded to avoid proof-run noise;
	// crashing proof inputs are simply skipped (no usable profile produced).
	_ = cmd.Run()

	if !fileExists(profrawPath) {
		return nil, false
	}
	// llvm-cov export requires an indexed profdata; raw profraw is rejected
	// ("bad magic"), so merge each seed's profraw into its own profdata first.
	profrawBin := findTool("llvm-profdata")
	if profrawBin == "" {
		return nil, false
	}
	mergeCmd := exec.Command(profrawBin, "merge", "-o", profdataPath, profrawPath)
	if out, err := mergeCmd.CombinedOutput(); err != nil {
		_ = out
		return nil, false
	}
	if !fileExists(profdataPath) {
		return nil, false
	}
	reach, err := collectBranchReachContext(ctx, profdataPath, binaryPath, sourceDir, buildDir, taskDir)
	if err != nil {
		return nil, false
	}
	return reach, true
}

func (s CorpusCoverageStatus) String() string {
	return fmt.Sprintf("seeds=%d (sampled=%v) executed=%d full=%d partial=%d uncovered=%d",
		s.SeedCount, s.Sampled, s.Summary.ExecutedFunctions, s.Summary.FullFunctions,
		s.Summary.PartialFunctions, len(s.Uncovered))
}
