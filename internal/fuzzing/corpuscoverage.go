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
	DefaultMaxCorpusSeeds            = 200
	DefaultMaxUncoveredBranches      = 60
	DefaultMaxReachingSeedsPerBranch = 15
	defaultPerSeedTimeout            = 10 * time.Second
)

// CorpusCoverageStatus describes per-seed (per-corpus-input) coverage obtained
// by replaying each saved corpus input one-by-one through the
// coverage-instrumented driver, plus an aggregate baseline and per-branch reach
// attribution. The live fuzzer is not involved, so it can keep running.
type CorpusCoverageStatus struct {
	Summary   CoverageSummary            `json:"summary"`
	SeedCount int                        `json:"seed_count"`
	Sampled   bool                       `json:"sampled"`
	CorpusDir string                     `json:"corpus_dir"`
	Uncovered []UncoveredBranchWithReach `json:"uncovered"`
}

// UncoveredBranchWithReach is one uncovered branch enriched for the LLM: the
// line it lives on (the LLM reads the source for the exact column), the
// condition text / missing direction / counts, and the seeds that reached the
// branch site. Attribution still keys internally on [line,col] to distinguish
// same-line branches; only the line is surfaced.
type UncoveredBranchWithReach struct {
	Function      string           `json:"function"`
	File          string           `json:"file"`
	Line          int              `json:"line"`
	Condition     string           `json:"condition"`
	Missing       string           `json:"missing"`
	Counts        map[string]int64 `json:"counts"`
	ReachingSeeds []string         `json:"reaching_seeds"`
	ReachCount    int              `json:"reach_count"`
}

// CollectCorpusCoverage replays each corpus seed in corpusSnapshotDir through the
// coverage-instrumented driver (one run per seed), collects per-seed coverage,
// merges per-seed profiles into an aggregate baseline, and attributes each
// aggregate uncovered branch to the seeds that reach its containing function.
//
// If maxSeeds <= 0, DefaultMaxCorpusSeeds is used. Seeds are sorted by size
// descending and the largest maxSeeds are kept (the rest are sampled out).
func CollectCorpusCoverage(
	ctx context.Context,
	binaryPath, sourceDir, driverDir, corpusSnapshotDir, logDir string,
	maxSeeds int,
	logf func(string, ...any),
) (CorpusCoverageStatus, error) {
	if maxSeeds <= 0 {
		maxSeeds = DefaultMaxCorpusSeeds
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return CorpusCoverageStatus{CorpusDir: corpusSnapshotDir}, err
	}

	seeds, err := listSeedFiles(corpusSnapshotDir)
	if err != nil {
		return CorpusCoverageStatus{CorpusDir: corpusSnapshotDir}, fmt.Errorf("list corpus seeds: %w", err)
	}
	if len(seeds) == 0 {
		logf("[corpus-cov] no seeds in %s\n", corpusSnapshotDir)
		return CorpusCoverageStatus{CorpusDir: corpusSnapshotDir}, nil
	}

	sort.Slice(seeds, func(i, j int) bool { return seeds[i].size > seeds[j].size })
	sampled := false
	if len(seeds) > maxSeeds {
		logf("[corpus-cov] sampling %d largest seeds out of %d\n", maxSeeds, len(seeds))
		seeds = seeds[:maxSeeds]
		sampled = true
	}
	logf("[corpus-cov] replaying %d seeds (sampled=%v)\n", len(seeds), sampled)

	// Per-seed branch-site reach is collected only to attribute each uncovered
	// branch to the seeds that reached its branch site; the per-seed detail is
	// not surfaced.
	perSeedReach := make([]map[string]map[[2]int]bool, len(seeds))
	for i, sd := range seeds {
		if err := ctx.Err(); err != nil {
			return CorpusCoverageStatus{CorpusDir: corpusSnapshotDir}, err
		}
		reach, _ := runSeedCoverage(ctx, binaryPath, sourceDir, driverDir, sd.path, logDir, i)
		perSeedReach[i] = reach
	}

	// Aggregate baseline from all per-seed profiles.
	aggregate := aggregateSeedProfiles(logDir, binaryPath, sourceDir, logf)

	status := buildCorpusCoverage(seeds, perSeedReach, aggregate, sampled, corpusSnapshotDir)
	logf("[corpus-cov] summary: executed=%d full=%d partial=%d uncovered_branches=%d\n",
		status.Summary.ExecutedFunctions, status.Summary.FullFunctions,
		status.Summary.PartialFunctions, len(status.Uncovered))
	return status, nil
}

// buildCorpusCoverage assembles a CorpusCoverageStatus from per-seed branch-site
// reach data and the aggregate baseline: it attributes each aggregate
// uncovered branch to the seeds that actually reached the branch SITE (the
// branch instruction was evaluated at least once in that seed's replay), and
// sorts/caps the uncovered list by reach count. It is pure and does not touch
// the filesystem, so it can be unit-tested with synthetic data.
func buildCorpusCoverage(
	seeds []seedFile,
	perSeedReach []map[string]map[[2]int]bool,
	aggregate CoverageStatus,
	sampled bool,
	corpusDir string,
) CorpusCoverageStatus {
	status := CorpusCoverageStatus{
		Summary:   aggregate.Summary,
		SeedCount: len(seeds),
		Sampled:   sampled,
		CorpusDir: corpusDir,
		Uncovered: []UncoveredBranchWithReach{},
	}

	// Attribute each aggregate uncovered branch to the seeds whose replay
	// evaluated that exact branch site (trueCount+falseCount > 0 at that
	// [line,col] in that function). This excludes seeds that entered the
	// function but returned before reaching the branch. API coverage breadth
	// is PromeFuzz's concern (generation phase), not surfaced here.
	for _, pf := range aggregate.Partial {
		for _, br := range pf.UncoveredBranches {
			loc := br.Location
			var reach []string
			for i, rb := range perSeedReach {
				if rb == nil {
					continue
				}
				if reached, ok := rb[pf.Function][loc]; ok && reached {
					reach = append(reach, filepath.Base(seeds[i].path))
				}
			}
			status.Uncovered = append(status.Uncovered, UncoveredBranchWithReach{
				Function:      pf.Function,
				File:          pf.File,
				Line:          br.Location[0],
				Condition:     br.Condition,
				Missing:       br.Missing,
				Counts:        br.Counts,
				ReachingSeeds: capStrings(reach, DefaultMaxReachingSeedsPerBranch),
				ReachCount:    len(reach),
			})
		}
	}

	// Sort by reach count descending (most-approached bottlenecks first); cap total.
	sort.SliceStable(status.Uncovered, func(i, j int) bool {
		return status.Uncovered[i].ReachCount > status.Uncovered[j].ReachCount
	})
	if len(status.Uncovered) > DefaultMaxUncoveredBranches {
		status.Uncovered = status.Uncovered[:DefaultMaxUncoveredBranches]
	}

	return status
}

type seedFile struct {
	path string
	size int64
}

func listSeedFiles(dir string) ([]seedFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []seedFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, seedFile{path: filepath.Join(dir, e.Name()), size: info.Size()})
	}
	return out, nil
}

// runSeedCoverage runs the coverage-instrumented driver on a single seed file
// with -runs=1 and returns the set of branch locations each function reached
// (trueCount+falseCount > 0). ok=false means no usable profile was produced
// (e.g. ASan abort). The branch-site reach is what makes reaching_seeds
// accurate: a seed that entered a function but returned before the branch is
// not counted as reaching that branch.
func runSeedCoverage(ctx context.Context, binaryPath, sourceDir, driverDir, seedPath, logDir string, idx int) (map[string]map[[2]int]bool, bool) {
	profrawPath := filepath.Join(logDir, fmt.Sprintf("seed-%d.profraw", idx))
	profdataPath := filepath.Join(logDir, fmt.Sprintf("seed-%d.profdata", idx))
	seedCtx, cancel := context.WithTimeout(ctx, defaultPerSeedTimeout)
	defer cancel()

	cmd := exec.CommandContext(seedCtx, binaryPath, "-runs=1", seedPath)
	cmd.Dir = driverDir
	cmd.Env = append(os.Environ(), "LLVM_PROFILE_FILE="+profrawPath)
	// Stdout/stderr left nil: output is discarded to avoid per-seed noise;
	// crashing seeds are simply skipped (no usable profile produced).
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
	reach, err := CollectBranchReach(profdataPath, binaryPath, sourceDir)
	if err != nil {
		return nil, false
	}
	return reach, true
}

// aggregateSeedProfiles merges all seed-*.profraw into cov.profdata and runs
// llvm-cov export once to obtain the aggregate CoverageStatus baseline.
func aggregateSeedProfiles(logDir, binaryPath, sourceDir string, logf func(string, ...any)) CoverageStatus {
	profrawBin := findTool("llvm-profdata")
	if profrawBin == "" {
		logf("[corpus-cov] llvm-profdata not found, skipping aggregate\n")
		return CoverageStatus{}
	}
	profraws, _ := filepath.Glob(filepath.Join(logDir, "seed-*.profraw"))
	if len(profraws) == 0 {
		return CoverageStatus{}
	}
	profdataPath := filepath.Join(logDir, "cov.profdata")
	mergeArgs := []string{"merge", "-o", profdataPath}
	mergeArgs = append(mergeArgs, profraws...)
	mergeCmd := exec.Command(profrawBin, mergeArgs...)
	if out, err := mergeCmd.CombinedOutput(); err != nil {
		logf("[corpus-cov] llvm-profdata merge: %v: %s\n", err, string(out))
		return CoverageStatus{}
	}
	if !fileExists(profdataPath) {
		return CoverageStatus{}
	}
	cs, err := CollectCoverageStatus(profdataPath, binaryPath, sourceDir)
	if err != nil {
		logf("[corpus-cov] aggregate llvm-cov export: %v\n", err)
		return CoverageStatus{}
	}
	return cs
}

func capStrings(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func (s CorpusCoverageStatus) String() string {
	return fmt.Sprintf("seeds=%d (sampled=%v) executed=%d full=%d partial=%d uncovered=%d",
		s.SeedCount, s.Sampled, s.Summary.ExecutedFunctions, s.Summary.FullFunctions,
		s.Summary.PartialFunctions, len(s.Uncovered))
}
