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
	Function   string           `json:"function"`
	File       string           `json:"file"`
	StartLine  int              `json:"start_line,omitempty"`
	EndLine    int              `json:"end_line,omitempty"`
	EntryCount int64            `json:"entry_count"`
	Regions    []CoverageRegion `json:"-"`
}

type PartialFunctionCoverage struct {
	Function          string            `json:"function"`
	File              string            `json:"file"`
	StartLine         int               `json:"start_line,omitempty"`
	EndLine           int               `json:"end_line,omitempty"`
	EntryCount        int64             `json:"entry_count"`
	UncoveredBranches []UncoveredBranch `json:"uncovered_branches"`
	Regions           []CoverageRegion  `json:"-"`
}

type CoverageRegion struct {
	StartLine      int
	StartColumn    int
	EndLine        int
	EndColumn      int
	Count          int64
	FileID         int
	ExpandedFileID int
	Kind           int64
}

type UncoveredBranch struct {
	Location        [2]int           `json:"location"`
	File            string           `json:"file,omitempty"`
	ExpansionFile   string           `json:"expansion_file,omitempty"`
	ExpansionLine   int              `json:"expansion_line,omitempty"`
	ExpansionColumn int              `json:"expansion_column,omitempty"`
	Condition       string           `json:"condition"`
	Missing         string           `json:"missing"`
	Counts          map[string]int64 `json:"counts"`
}

func CloneCoverageSnapshot(snapshot CoverageSnapshot) CoverageSnapshot {
	snapshot.Coverage = CloneCoverageStatus(snapshot.Coverage)
	return snapshot
}

func CloneMultiCoverageSnapshot(snapshot MultiCoverageSnapshot) MultiCoverageSnapshot {
	snapshot.RunningTargets = append([]int(nil), snapshot.RunningTargets...)
	snapshot.QueuedTargets = append([]int(nil), snapshot.QueuedTargets...)
	snapshot.NextTargets = append([]int(nil), snapshot.NextTargets...)
	snapshot.RunningVersions = append([]TargetVersionRef(nil), snapshot.RunningVersions...)
	snapshot.QueuedVersions = append([]TargetVersionRef(nil), snapshot.QueuedVersions...)
	snapshot.NextVersions = append([]TargetVersionRef(nil), snapshot.NextVersions...)
	if snapshot.NextAnalysisAt != nil {
		next := *snapshot.NextAnalysisAt
		snapshot.NextAnalysisAt = &next
	}
	snapshot.Coverage = CloneCoverageStatus(snapshot.Coverage)
	snapshot.Targets = append([]TargetCoverageSnapshot(nil), snapshot.Targets...)
	for index := range snapshot.Targets {
		snapshot.Targets[index].Coverage = CloneCoverageStatus(snapshot.Targets[index].Coverage)
	}
	return snapshot
}

func CloneCoverageStatus(status CoverageStatus) CoverageStatus {
	status.Full = append([]FunctionCoverage(nil), status.Full...)
	for index := range status.Full {
		status.Full[index].Regions = append([]CoverageRegion(nil), status.Full[index].Regions...)
	}
	status.Partial = append([]PartialFunctionCoverage(nil), status.Partial...)
	for index := range status.Partial {
		status.Partial[index].UncoveredBranches = cloneUncoveredBranches(status.Partial[index].UncoveredBranches)
		status.Partial[index].Regions = append([]CoverageRegion(nil), status.Partial[index].Regions...)
	}
	return status
}

func CloneCoverageData(data any) any {
	switch value := data.(type) {
	case CoverageSnapshot:
		return CloneCoverageSnapshot(value)
	case *CoverageSnapshot:
		if value == nil {
			return data
		}
		cloned := CloneCoverageSnapshot(*value)
		return &cloned
	case MultiCoverageSnapshot:
		return CloneMultiCoverageSnapshot(value)
	case *MultiCoverageSnapshot:
		if value == nil {
			return data
		}
		cloned := CloneMultiCoverageSnapshot(*value)
		return &cloned
	default:
		return data
	}
}

func cloneUncoveredBranches(branches []UncoveredBranch) []UncoveredBranch {
	if branches == nil {
		return nil
	}
	out := append([]UncoveredBranch(nil), branches...)
	for index := range out {
		out[index].Counts = cloneCounts(out[index].Counts)
	}
	return out
}

func cloneCounts(counts map[string]int64) map[string]int64 {
	if counts == nil {
		return nil
	}
	out := make(map[string]int64, len(counts))
	for key, value := range counts {
		out[key] = value
	}
	return out
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
// falseCount > 0). This is used by proof-seed validation to ensure the target
// branch site was actually reached before checking whether the missing branch
// direction became covered.
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
				StartLine:  fc.startLine,
				EndLine:    fc.endLine,
				EntryCount: fc.entryCount,
				Regions:    fc.regions,
			})
		} else {
			status.Partial = append(status.Partial, PartialFunctionCoverage{
				Function:          fc.name,
				File:              fc.file,
				StartLine:         fc.startLine,
				EndLine:           fc.endLine,
				EntryCount:        fc.entryCount,
				UncoveredBranches: fc.uncovered,
				Regions:           fc.regions,
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
	startLine  int
	endLine    int
	entryCount int64
	full       bool
	uncovered  []UncoveredBranch
	regions    []CoverageRegion
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
		regions := coverageRegionsFromExport(fn)
		expansions := expansionRegionsByFileID(regions)
		startLine, endLine := functionLineRange(fn)

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
			fileID := 0
			if len(br) >= 7 {
				fileID = int(br[6])
			}
			branchFile := filenameForID(fn.Filenames, fileID)
			expansionFile := ""
			expansionLine := 0
			expansionColumn := 0
			if fileID != 0 {
				if expansion, ok := expansions[fileID]; ok {
					expansionFile = filenameForID(fn.Filenames, expansion.FileID)
					expansionLine = expansion.StartLine
					expansionColumn = expansion.StartColumn
				}
			}

			cond := extractCondition(branchFile, line, col, endLine, endCol)

			if trueCount == 0 {
				uncovered = append(uncovered, UncoveredBranch{
					Location:        [2]int{line, col},
					File:            branchFile,
					ExpansionFile:   expansionFile,
					ExpansionLine:   expansionLine,
					ExpansionColumn: expansionColumn,
					Condition:       cond,
					Missing:         "true",
					Counts: map[string]int64{
						"true":  0,
						"false": falseCount,
					},
				})
			}
			if falseCount == 0 {
				uncovered = append(uncovered, UncoveredBranch{
					Location:        [2]int{line, col},
					File:            branchFile,
					ExpansionFile:   expansionFile,
					ExpansionLine:   expansionLine,
					ExpansionColumn: expansionColumn,
					Condition:       cond,
					Missing:         "false",
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
			startLine:  startLine,
			endLine:    endLine,
			entryCount: entryCount,
			full:       len(uncovered) == 0,
			uncovered:  uncovered,
			regions:    regions,
		})
	}

	return result, nil
}

func coverageRegionsFromExport(fn exportFunc) []CoverageRegion {
	regions := make([]CoverageRegion, 0, len(fn.Regions))
	for _, raw := range fn.Regions {
		if len(raw) < 5 {
			continue
		}
		region := CoverageRegion{
			StartLine:   int(raw[0]),
			StartColumn: int(raw[1]),
			EndLine:     int(raw[2]),
			EndColumn:   int(raw[3]),
			Count:       raw[4],
		}
		if len(raw) >= 7 {
			region.FileID = int(raw[5])
			region.ExpandedFileID = int(raw[6])
		}
		if len(raw) >= 8 {
			region.Kind = raw[7]
		}
		if region.StartLine <= 0 || region.EndLine <= 0 {
			continue
		}
		regions = append(regions, region)
	}
	return regions
}

func expansionRegionsByFileID(regions []CoverageRegion) map[int]CoverageRegion {
	out := map[int]CoverageRegion{}
	for _, region := range regions {
		if region.Kind != 1 || region.ExpandedFileID <= 0 {
			continue
		}
		if _, exists := out[region.ExpandedFileID]; !exists {
			out[region.ExpandedFileID] = region
		}
	}
	return out
}

func filenameForID(filenames []string, id int) string {
	if id >= 0 && id < len(filenames) {
		return filenames[id]
	}
	if len(filenames) > 0 {
		return filenames[0]
	}
	return ""
}

func functionLineRange(fn exportFunc) (int, int) {
	startLine := 0
	endLine := 0
	for _, region := range coverageRegionsFromExport(fn) {
		if region.FileID != 0 || region.Kind == 3 {
			continue
		}
		start := region.StartLine
		end := region.EndLine
		if start <= 0 || end <= 0 {
			continue
		}
		if startLine == 0 || start < startLine {
			startLine = start
		}
		if end > endLine {
			endLine = end
		}
	}
	if startLine == 0 {
		for _, branch := range fn.Branches {
			if len(branch) < 4 {
				continue
			}
			fileID := 0
			if len(branch) >= 7 {
				fileID = int(branch[6])
			}
			if fileID != 0 {
				continue
			}
			start := int(branch[0])
			end := int(branch[2])
			if start <= 0 || end <= 0 {
				continue
			}
			if startLine == 0 || start < startLine {
				startLine = start
			}
			if end > endLine {
				endLine = end
			}
		}
	}
	return startLine, endLine
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
