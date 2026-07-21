package fuzzing

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// CoverageStatus describes the function-level coverage of a fuzz run.
type CoverageStatus struct {
	Summary CoverageSummary           `json:"summary"`
	Full    []FunctionCoverage        `json:"full"`
	Partial []PartialFunctionCoverage `json:"partial"`
}

type CoverageSummary struct {
	ExecutedFunctions int `json:"executed_functions"`
	FullFunctions     int `json:"full_functions"`
	PartialFunctions  int `json:"partial_functions"`
}

type FunctionCoverage struct {
	Function   string `json:"function"`
	File       string `json:"file"`
	EntryCount int64  `json:"entry_count"`
}

type PartialFunctionCoverage struct {
	Function          string            `json:"function"`
	File              string            `json:"file"`
	EntryCount        int64             `json:"entry_count"`
	UncoveredBranches []UncoveredBranch `json:"uncovered_branches"`
}

type UncoveredBranch struct {
	Location  [2]int           `json:"location"`
	Condition string           `json:"condition"`
	Missing   string           `json:"missing"`
	Counts    map[string]int64 `json:"counts"`
}

// CollectCoverageStatus runs llvm-cov export on the given profdata file
// produced by the coverage-instrumented synthesized driver and parses
// the results into a CoverageStatus. buildDir covers out-of-tree builds
// where the library sources were copied into the build directory (so
// llvm-cov reports them under build/ rather than source/).
func CollectCoverageStatus(profdataPath, binaryPath, sourceDir, buildDir string) (CoverageStatus, error) {
	return collectCoverageStatus(profdataPath, binaryPath, sourceDir, buildDir, "")
}

// CollectCoverageStatusWithDriverDir is like CollectCoverageStatus but also
// accepts the fuzz driver directory so that driver-source functions are
// not filtered out.
func CollectCoverageStatusWithDriverDir(profdataPath, binaryPath, sourceDir, buildDir, driverDir string) (CoverageStatus, error) {
	return collectCoverageStatus(profdataPath, binaryPath, sourceDir, buildDir, driverDir)
}

// CollectBranchReach runs llvm-cov export and returns, per function name
// (restricted to sourceDir, entry_count > 0), the set of branch locations
// [line, col] that were actually evaluated at least once (trueCount +
// falseCount > 0). This is used to attribute each aggregate uncovered branch
// to the seeds that reached the branch SITE (not merely entered its function):
// a seed that entered the function but returned before the branch is excluded.
// Unlike CollectCoverageStatus it does not extract condition text, so it is
// cheaper per seed; branch detail (condition/counts) still comes from the one
// aggregate CollectCoverageStatus call.
func CollectBranchReach(profdataPath, binaryPath, sourceDir, buildDir string) (map[string]map[[2]int]bool, error) {
	covBin := findCovTool()
	if covBin == "" {
		return nil, fmt.Errorf("llvm-cov not found")
	}
	// Use a timeout so a stuck llvm-cov export (e.g. under CPU contention)
	// does not block the monitor's goroutine indefinitely, preventing
	// monitor.Stop() from returning on cancel.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	exportCmd := exec.CommandContext(ctx, covBin, "export", "-instr-profile="+profdataPath,
		binaryPath, "--format=text")
	exportOutput, err := exportCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("llvm-cov export failed: %w\nstdout/stderr: %s", err, string(exportOutput))
	}
	return parseBranchReach(exportOutput, sourceDir, buildDir)
}

func parseBranchReach(data []byte, sourceDir, buildDir string) (map[string]map[[2]int]bool, error) {
	var root exportRoot
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse llvm-cov export JSON: %w", err)
	}
	out := map[string]map[[2]int]bool{}
	if len(root.Data) == 0 {
		return out, nil
	}
	for _, fn := range root.Data[0].Functions {
		fnFile := ""
		if len(fn.Filenames) > 0 {
			fnFile = fn.Filenames[0]
		}
		// buildDir is guarded against "" because isPathUnder falls back to
		// the process CWD for an empty base, which would silently accept
		// unrelated files.
		if !isPathUnder(fnFile, sourceDir) && !(buildDir != "" && isPathUnder(fnFile, buildDir)) {
			continue
		}
		if fn.Count == 0 {
			continue
		}
		for _, br := range fn.Branches {
			if len(br) < 6 {
				continue
			}
			if br[4]+br[5] == 0 {
				continue
			}
			loc := [2]int{int(br[0]), int(br[1])}
			if out[fn.Name] == nil {
				out[fn.Name] = map[[2]int]bool{}
			}
			out[fn.Name][loc] = true
		}
	}
	return out, nil
}

func collectCoverageStatus(profdataPath, binaryPath, sourceDir, buildDir, driverDir string) (CoverageStatus, error) {
	status := CoverageStatus{
		Full:    []FunctionCoverage{},
		Partial: []PartialFunctionCoverage{},
	}

	covBin := findCovTool()
	if covBin == "" {
		return status, fmt.Errorf("llvm-cov not found")
	}
	// Use a timeout so a stuck llvm-cov export does not block the monitor's
	// coverageLoop goroutine indefinitely, preventing monitor.Stop() on cancel.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	exportCmd := exec.CommandContext(ctx, covBin, "export", "-instr-profile="+profdataPath,
		binaryPath, "--format=text")
	exportOutput, err := exportCmd.CombinedOutput()
	if err != nil {
		return status, fmt.Errorf("llvm-cov export failed: %w\nstdout/stderr: %s", err, string(exportOutput))
	}

	funcs, err := parseExportJSON(exportOutput, sourceDir, buildDir, driverDir)
	if err != nil {
		return status, err
	}

	for _, fc := range funcs {
		if fc.full {
			status.Full = append(status.Full, FunctionCoverage{
				Function:   fc.name,
				File:       fc.file,
				EntryCount: fc.entryCount,
			})
		} else {
			status.Partial = append(status.Partial, PartialFunctionCoverage{
				Function:          fc.name,
				File:              fc.file,
				EntryCount:        fc.entryCount,
				UncoveredBranches: fc.uncovered,
			})
		}
	}

	status.Summary = CoverageSummary{
		ExecutedFunctions: len(status.Full) + len(status.Partial),
		FullFunctions:     len(status.Full),
		PartialFunctions:  len(status.Partial),
	}

	return status, nil
}

type funcCoverageData struct {
	name       string
	file       string
	entryCount int64
	full       bool
	uncovered  []UncoveredBranch
}

type exportFunc struct {
	Name      string    `json:"name"`
	Filenames []string  `json:"filenames"`
	Count     int64     `json:"count"`
	Regions   [][]int64 `json:"regions"`
	Branches  [][]int64 `json:"branches"`
}

type exportData struct {
	Functions []exportFunc `json:"functions"`
	Files     []struct {
		Name string `json:"name"`
	} `json:"files"`
}

type exportRoot struct {
	Data []exportData `json:"data"`
}

func parseExportJSON(data []byte, sourceDir, buildDir, driverDir string) ([]funcCoverageData, error) {
	var root exportRoot
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse llvm-cov export JSON: %w", err)
	}

	result := []funcCoverageData{}
	if len(root.Data) == 0 {
		return result, nil
	}

	for _, fn := range root.Data[0].Functions {
		fnFile := ""
		if len(fn.Filenames) > 0 {
			fnFile = fn.Filenames[0]
		}
		// Accept functions whose source lives under the library source dir,
		// the out-of-tree build dir (sources copied into build/), or the
		// driver dir. buildDir is guarded against "" because isPathUnder
		// falls back to the process CWD for an empty base.
		if !isPathUnder(fnFile, sourceDir) &&
			!(buildDir != "" && isPathUnder(fnFile, buildDir)) &&
			!isPathUnder(fnFile, driverDir) {
			continue
		}

		entryCount := fn.Count
		if entryCount == 0 {
			continue
		}

		var uncovered []UncoveredBranch
		// Use branches: [line, col, endLine, endCol, trueCount, falseCount, ...]
		for _, br := range fn.Branches {
			if len(br) < 6 {
				continue
			}
			line := int(br[0])
			col := int(br[1])
			endLine := int(br[2])
			endCol := int(br[3])
			trueCount := br[4]
			falseCount := br[5]

			cond := extractCondition(fnFile, line, col, endLine, endCol)

			if trueCount == 0 {
				uncovered = append(uncovered, UncoveredBranch{
					Location:  [2]int{line, col},
					Condition: cond,
					Missing:   "true",
					Counts: map[string]int64{
						"true":  0,
						"false": falseCount,
					},
				})
			}
			if falseCount == 0 {
				uncovered = append(uncovered, UncoveredBranch{
					Location:  [2]int{line, col},
					Condition: cond,
					Missing:   "false",
					Counts: map[string]int64{
						"true":  trueCount,
						"false": 0,
					},
				})
			}
		}

		result = append(result, funcCoverageData{
			name:       fn.Name,
			file:       fnFile,
			entryCount: entryCount,
			full:       len(uncovered) == 0,
			uncovered:  uncovered,
		})
	}

	return result, nil
}

// extractCondition reads the source file and extracts the code text
// at the given [line, col] to [endLine, endCol] range (1-based).
func extractCondition(filePath string, line, col, endLine, endCol int) string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(data), "\n")
	if line < 1 || line > len(lines) {
		return ""
	}

	if line == endLine {
		// Single line: extract from col to endCol
		src := lines[line-1]
		start := col - 1
		if start < 0 {
			start = 0
		}
		end := endCol
		if end > len(src) {
			end = len(src)
		}
		if start >= len(src) {
			return ""
		}
		return strings.TrimSpace(src[start:end])
	}

	// Multi-line: join from line to endLine
	var parts []string
	for i := line; i <= endLine && i <= len(lines); i++ {
		src := lines[i-1]
		if i == line {
			start := col - 1
			if start < 0 {
				start = 0
			}
			if start < len(src) {
				parts = append(parts, src[start:])
			}
		} else if i == endLine {
			end := endCol
			if end > len(src) {
				end = len(src)
			}
			if end > 0 {
				parts = append(parts, src[:end])
			}
		} else {
			parts = append(parts, src)
		}
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

func isPathUnder(path, base string) bool {
	if path == "" || base == "" {
		return false
	}
	abs, err := canonicalCoveragePath(path)
	if err != nil {
		return false
	}
	absBase, err := canonicalCoveragePath(base)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(absBase, abs)
	if err != nil {
		return false
	}
	return !strings.HasPrefix(rel, "..")
}

// canonicalCoveragePath returns a physical absolute path when the path exists.
// LLVM records the source spelling passed by the build system in its coverage
// mapping. GN source-root layouts commonly reach the task source directory
// through an intermediate symlink (for example third_party/libexif -> source),
// so a lexical filepath.Rel comparison would otherwise discard valid coverage.
func canonicalCoveragePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return filepath.Clean(resolved), nil
	}
	// Preserve the previous lexical behavior for paths which no longer exist,
	// such as historical coverage whose source tree has been moved or removed.
	return filepath.Clean(abs), nil
}
