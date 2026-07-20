package fuzzing

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	monitorPollInterval = 5 * time.Second
	monitorMaxPerScan   = 20
	monitorCovInterval  = 60 * time.Second
)

// CoverageSnapshot is a cached llvm-cov export result, updated periodically by
// the monitor's coverage loop for the web UI.
type CoverageSnapshot struct {
	Timestamp time.Time      `json:"timestamp"`
	Available bool           `json:"available"`
	SeedCount int            `json:"seed_count"`
	Coverage  CoverageStatus `json:"coverage"`
}

// CorpusMonitor watches the corpus directory in the background. When new
// corpus seeds appear, it replays them through the coverage-instrumented
// driver and merges the profraw into a running aggregate profdata. Per-seed
// branch-site reach is persisted to disk (one file per seed, 1:1 with a
// corpus copy in the snapshot) so it survives restart. An in-memory reverse
// index (branch site → reaching seed names) is maintained for fast
// reaching_seeds attribution and pruned to uncovered branches to bound
// memory. When the LLM analysis is triggered, Snapshot returns the current
// coverage status instantly — no replay is needed.
type CorpusMonitor struct {
	cfg           FuzzConfig
	workDir       string
	profdataPath  string // running aggregate (incrementally merged)
	reachDir      string // persisted per-seed reach (1:1 with corpus copy)
	corpusSnapDir string // corpus copy in the snapshot (self-containment)

	mu              sync.RWMutex
	seenSeeds       map[string]bool
	totalSeeds      int
	branchReachIndex map[string]map[[2]int][]string // reverse: branch site → reaching seed names
	uncoveredSites  map[string]map[[2]int]bool      // current uncovered branch sites (for pruning)

	covMu    sync.RWMutex
	covCache CoverageSnapshot

	// Per-snapshot real-time crash analysis: replays each new crash on the
	// snapshot's own binary, extracts the symbolized ASan stack for dedup,
	// and persists the result (total + unique count + unique list) to
	// crash-analysis.json in the snapshot dir.
	crashMu           sync.Mutex
	seenCrashes       map[string]bool
	crashSigs         map[string]bool
	uniqueCrashList   []CrashAnalysisEntry
	totalCrashCount   int
	uniqueCrashCount  int
	crashAnalysisPath string
	snapshotBinaryPath string
	crashesDir        string
	uniqueCrashesDir  string

	stop chan struct{}
	wg   sync.WaitGroup
}

func NewCorpusMonitor(cfg FuzzConfig, workDir string) *CorpusMonitor {
	snapDir := filepath.Dir(workDir) // fuzz-NNN/ (parent of monitor/)
	return &CorpusMonitor{
		cfg:               cfg,
		workDir:           workDir,
		profdataPath:      filepath.Join(workDir, "aggregate.profdata"),
		reachDir:          filepath.Join(workDir, "reach"),
		corpusSnapDir:     filepath.Join(workDir, "corpus"),
		seenSeeds:         map[string]bool{},
		branchReachIndex:  map[string]map[[2]int][]string{},
		seenCrashes:       map[string]bool{},
		crashSigs:         map[string]bool{},
		crashAnalysisPath:  filepath.Join(snapDir, "crash-analysis.json"),
		snapshotBinaryPath: filepath.Join(snapDir, "cov_synthesized_driver"),
		crashesDir:         filepath.Join(snapDir, "crashes"),
		uniqueCrashesDir:   filepath.Join(snapDir, "unique_crashes"),
		stop:              make(chan struct{}),
	}
}

func (m *CorpusMonitor) Start(ctx context.Context) {
	_ = os.MkdirAll(m.workDir, 0o755)
	_ = os.MkdirAll(m.reachDir, 0o755)
	_ = os.MkdirAll(m.corpusSnapDir, 0o755)
	_ = os.MkdirAll(m.uniqueCrashesDir, 0o755)
	// Load persisted reach on startup (resume case): rebuild the in-memory
	// reverse index + mark those seeds as seen so we don't re-replay them.
	m.loadPersistedReach()
	// Load existing crash analysis (resume): rebuild dedup state + mark
	// existing crash files as seen so we only analyze new ones.
	m.loadCrashAnalysis()
	m.wg.Add(3)
	go func() { defer m.wg.Done(); m.loop(ctx) }()
	go func() { defer m.wg.Done(); m.coverageLoop(ctx) }()
	go func() { defer m.wg.Done(); m.crashLoop(ctx) }()
}

// loadPersistedReach reads all reach files from reachDir and rebuilds the
// in-memory reverse index + seenSeeds. This enables fast same-driver resume:
// the monitor loads existing reach data instead of re-replaying the corpus.
func (m *CorpusMonitor) loadPersistedReach() {
	entries, err := os.ReadDir(m.reachDir)
	if err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		seedName := e.Name()
		seedPath := filepath.Join(m.cfg.CorpusDir, seedName)
		reach, err := loadReachFile(filepath.Join(m.reachDir, seedName))
		if err != nil || len(reach) == 0 {
			continue
		}
		m.seenSeeds[seedPath] = true
		m.totalSeeds++
		m.addSeedToIndex(seedName, reach)
	}
}

// addSeedToIndex appends seedName to the reaching list of every branch site
// the seed evaluated. After the first coverage refresh (uncoveredSites set),
// only uncovered branches are updated — covered branches' lists were pruned
// and are never queried. Before the first refresh (uncoveredSites nil), all
// evaluated branches are added (the first prune will filter). Called under m.mu.
func (m *CorpusMonitor) addSeedToIndex(seedName string, reach map[string]map[[2]int]bool) {
	for fn, locs := range reach {
		var unc map[[2]int]bool
		if m.uncoveredSites != nil {
			unc = m.uncoveredSites[fn]
			if unc == nil {
				continue // no uncovered branches in this function
			}
		}
		if m.branchReachIndex[fn] == nil {
			m.branchReachIndex[fn] = map[[2]int][]string{}
		}
		for loc := range locs {
			if m.uncoveredSites != nil && !unc[loc] {
				continue // this branch is covered, skip
			}
			m.branchReachIndex[fn][loc] = append(m.branchReachIndex[fn][loc], seedName)
		}
	}
}

// pruneIndexToUncovered drops index entries for branches NOT in the uncovered
// set. Coverage is monotonic (covered branches stay covered), so pruned entries
// are never needed again. Called under m.mu.
func (m *CorpusMonitor) pruneIndexToUncovered() {
	if m.uncoveredSites == nil {
		return
	}
	for fn := range m.branchReachIndex {
		unc, keep := m.uncoveredSites[fn]
		if !keep {
			delete(m.branchReachIndex, fn)
			continue
		}
		for loc := range m.branchReachIndex[fn] {
			if !unc[loc] {
				delete(m.branchReachIndex[fn], loc)
			}
		}
		if len(m.branchReachIndex[fn]) == 0 {
			delete(m.branchReachIndex, fn)
		}
	}
}

func (m *CorpusMonitor) loop(ctx context.Context) {
	ticker := time.NewTicker(monitorPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stop:
			return
		case <-ticker.C:
			m.scanAndReplay(ctx)
		}
	}
}

// coverageLoop runs llvm-cov export on the aggregate profdata every minute,
// caches the result for the web UI, and prunes the reverse index to the
// current uncovered-branch set. The export is NOT under the main mutex.
func (m *CorpusMonitor) coverageLoop(ctx context.Context) {
	m.updateCoverageCache()
	ticker := time.NewTicker(monitorCovInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stop:
			return
		case <-ticker.C:
			m.updateCoverageCache()
		}
	}
}

func (m *CorpusMonitor) updateCoverageCache() {
	snap := CoverageSnapshot{Timestamp: time.Now()}
	var cs CoverageStatus
	if fileExists(m.profdataPath) {
		var err error
		cs, err = CollectCoverageStatus(m.profdataPath, m.cfg.BinaryPath, m.cfg.SourceDir, m.cfg.BuildDir)
		if err == nil {
			snap.Available = true
			snap.Coverage = cs
		}
	}
	m.mu.RLock()
	snap.SeedCount = m.totalSeeds
	m.mu.RUnlock()
	m.covMu.Lock()
	m.covCache = snap
	m.covMu.Unlock()

	// Build the current uncovered-branch set from the coverage status and
	// prune the reverse index to only those branches (drop covered ones).
	m.mu.Lock()
	m.uncoveredSites = buildUncoveredSites(cs)
	m.pruneIndexToUncovered()
	m.mu.Unlock()
}

// buildUncoveredSites extracts the set of uncovered branch sites (function →
// {[line,col]}) from a CoverageStatus. Returns nil if cs is zero (no export).
func buildUncoveredSites(cs CoverageStatus) map[string]map[[2]int]bool {
	if len(cs.Partial) == 0 {
		return nil
	}
	out := map[string]map[[2]int]bool{}
	for _, pf := range cs.Partial {
		if len(pf.UncoveredBranches) == 0 {
			continue
		}
		locs, ok := out[pf.Function]
		if !ok {
			locs = map[[2]int]bool{}
			out[pf.Function] = locs
		}
		for _, br := range pf.UncoveredBranches {
			locs[br.Location] = true
		}
	}
	return out
}

func (m *CorpusMonitor) CoverageCache() CoverageSnapshot {
	m.covMu.RLock()
	defer m.covMu.RUnlock()
	return m.covCache
}

func (m *CorpusMonitor) Stop() {
	select {
	case <-m.stop:
	default:
		close(m.stop)
	}
	m.wg.Wait()
}

func (m *CorpusMonitor) scanAndReplay(ctx context.Context) {
	entries, err := os.ReadDir(m.cfg.CorpusDir)
	if err != nil {
		return
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	replayed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if ctx.Err() != nil || replayed >= monitorMaxPerScan {
			return
		}
		path := filepath.Join(m.cfg.CorpusDir, e.Name())

		m.mu.RLock()
		seen := m.seenSeeds[path]
		m.mu.RUnlock()
		if seen {
			continue
		}

		m.replaySeed(ctx, path, e.Name())
		replayed++
	}
}

func (m *CorpusMonitor) replaySeed(ctx context.Context, seedPath, seedName string) {
	idx := m.totalSeeds

	profrawPath := filepath.Join(m.workDir, fmt.Sprintf("seed-%d.profraw", idx))
	seedCtx, cancel := context.WithTimeout(ctx, defaultPerSeedTimeout)
	defer cancel()

	cmd := exec.CommandContext(seedCtx, m.cfg.BinaryPath, "-runs=1", seedPath)
	cmd.Dir = m.cfg.DriverDir
	cmd.Env = withAsanSymbolizeDisabled(append(os.Environ(), "LLVM_PROFILE_FILE="+profrawPath))
	_ = cmd.Run()

	if !fileExists(profrawPath) {
		m.mu.Lock()
		m.seenSeeds[seedPath] = true
		m.totalSeeds++
		m.mu.Unlock()
		return
	}

	profrawBin := findTool("llvm-profdata")
	if profrawBin == "" {
		_ = os.Remove(profrawPath)
		m.mu.Lock()
		m.seenSeeds[seedPath] = true
		m.totalSeeds++
		m.mu.Unlock()
		return
	}

	// Merge profraw → seed-specific profdata (for per-seed branch reach).
	seedProfdata := filepath.Join(m.workDir, fmt.Sprintf("seed-%d.profdata", idx))
	mergeCmd := exec.Command(profrawBin, "merge", "-o", seedProfdata, profrawPath)
	if out, err := mergeCmd.CombinedOutput(); err != nil {
		_ = out
		_ = os.Remove(profrawPath)
		m.mu.Lock()
		m.seenSeeds[seedPath] = true
		m.totalSeeds++
		m.mu.Unlock()
		return
	}

	// Collect per-seed branch reach (no lock held — this is the slow part).
	var reach map[string]map[[2]int]bool
	if r, err := CollectBranchReach(seedProfdata, m.cfg.BinaryPath, m.cfg.SourceDir, m.cfg.BuildDir); err == nil {
		reach = r
	}
	_ = os.Remove(seedProfdata)

	// Merge profraw into the running aggregate.
	m.mergeIntoAggregate(profrawPath, profrawBin)
	_ = os.Remove(profrawPath)

	// Persist the per-seed reach to disk (1:1 with the corpus copy) and copy
	// the corpus input into the snapshot for self-containment. Real-time so
	// the persisted state stays current with the aggregate.
	if reach != nil {
		_ = writeReachFile(filepath.Join(m.reachDir, seedName), reach)
	}
	_ = copyFile(seedPath, filepath.Join(m.corpusSnapDir, seedName))

	m.mu.Lock()
	m.seenSeeds[seedPath] = true
	m.totalSeeds++
	if reach != nil {
		m.addSeedToIndex(seedName, reach)
	}
	reachEntries := 0
	for _, locs := range m.branchReachIndex {
		reachEntries += len(locs)
	}
	m.mu.Unlock()

	m.cfg.logf("[corpus-monitor] replayed %s (total=%d, index_branches=%d)\n", seedName, m.totalSeeds, reachEntries)
}

func (m *CorpusMonitor) mergeIntoAggregate(profrawPath, profrawBin string) {
	tmpPath := m.profdataPath + ".tmp"
	var cmd *exec.Cmd
	if fileExists(m.profdataPath) {
		cmd = exec.Command(profrawBin, "merge", "-sparse", "-o", tmpPath, m.profdataPath, profrawPath)
	} else {
		cmd = exec.Command(profrawBin, "merge", "-sparse", "-o", tmpPath, profrawPath)
	}
	_ = cmd.Run()
	_ = os.Rename(tmpPath, m.profdataPath)
}

// Snapshot returns the current coverage status instantly. It runs a single
// llvm-cov export on the aggregate profdata and attributes each uncovered
// branch to reaching seeds via the in-memory reverse index. No seed replay
// is performed — the heavy lifting was done incrementally in the background.
func (m *CorpusMonitor) Snapshot(sourceDir, buildDir string, logf func(string, ...any)) (CorpusCoverageStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !fileExists(m.profdataPath) {
		return CorpusCoverageStatus{CorpusDir: m.cfg.CorpusDir}, nil
	}

	cs, err := CollectCoverageStatus(m.profdataPath, m.cfg.BinaryPath, sourceDir, buildDir)
	if err != nil {
		return CorpusCoverageStatus{}, fmt.Errorf("monitor snapshot: %w", err)
	}

	status := CorpusCoverageStatus{
		Summary:   cs.Summary,
		SeedCount: m.totalSeeds,
		CorpusDir: m.cfg.CorpusDir,
		Uncovered: []UncoveredBranchWithReach{},
	}

	for _, pf := range cs.Partial {
		for _, br := range pf.UncoveredBranches {
			loc := br.Location
			var reach []string
			if fnIdx, ok := m.branchReachIndex[pf.Function]; ok {
				if seeds, ok2 := fnIdx[loc]; ok2 {
					reach = make([]string, len(seeds))
					copy(reach, seeds)
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

	sort.SliceStable(status.Uncovered, func(i, j int) bool {
		return status.Uncovered[i].ReachCount > status.Uncovered[j].ReachCount
	})
	if len(status.Uncovered) > DefaultMaxUncoveredBranches {
		status.Uncovered = status.Uncovered[:DefaultMaxUncoveredBranches]
	}

	if logf != nil {
		reachEntries := 0
		for _, locs := range m.branchReachIndex {
			reachEntries += len(locs)
		}
		logf("[corpus-monitor] snapshot: seeds=%d index_branches=%d executed=%d full=%d partial=%d uncovered=%d\n",
			m.totalSeeds, reachEntries, status.Summary.ExecutedFunctions,
			status.Summary.FullFunctions, status.Summary.PartialFunctions, len(status.Uncovered))
	}

	return status, nil
}

// writeReachFile persists a per-seed reach map to disk as JSON.
// Format: {"function":[[line,col],[line,col],...], ...}
func writeReachFile(path string, reach map[string]map[[2]int]bool) error {
	out := make(map[string][][]int, len(reach))
	for fn, locs := range reach {
		arr := make([][]int, 0, len(locs))
		for loc := range locs {
			arr = append(arr, []int{loc[0], loc[1]})
		}
		out[fn] = arr
	}
	data, err := json.Marshal(out)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// loadReachFile reads a per-seed reach file back into the in-memory format.
func loadReachFile(path string) (map[string]map[[2]int]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var in map[string][][]int
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, err
	}
	reach := make(map[string]map[[2]int]bool, len(in))
	for fn, arr := range in {
		locs := make(map[[2]int]bool, len(arr))
		for _, pair := range arr {
			if len(pair) >= 2 {
				locs[[2]int{pair[0], pair[1]}] = true
			}
		}
		reach[fn] = locs
	}
	return reach, nil
}

// crashLoop polls the snapshot's crashes/ dir every 10 seconds for new crash
// inputs, replays each on the snapshot's own binary, extracts the symbolized
// ASan stack for dedup, and persists the result to crash-analysis.json. This
// gives a real-time per-snapshot "total vs unique crash" count that the web UI
// shows in the driver-version comparison panel.
func (m *CorpusMonitor) crashLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stop:
			return
		case <-ticker.C:
			m.scanAndAnalyzeCrashes(ctx)
		}
	}
}

func (m *CorpusMonitor) scanAndAnalyzeCrashes(ctx context.Context) {
	entries, err := os.ReadDir(m.crashesDir)
	if err != nil {
		return
	}
	analyzed := 0
	const maxPerScan = 10
	for _, e := range entries {
		if e.IsDir() || analyzed >= maxPerScan {
			break
		}
		if ctx.Err() != nil {
			return
		}
		path := filepath.Join(m.crashesDir, e.Name())
		m.crashMu.Lock()
		seen := m.seenCrashes[path]
		m.crashMu.Unlock()
		if seen {
			continue
		}
		// Replay on the snapshot's own binary (the exact driver that found
		// the crash). ASan symbolization is ON (needed for stack-based dedup).
		reproduced, crashType, stack := replayCrash(ctx, m.snapshotBinaryPath, m.crashesDir, path)
		m.crashMu.Lock()
		m.seenCrashes[path] = true
		m.totalCrashCount++
		sig := stack
		if !reproduced {
			sig = "no-crash:" + e.Name()
		}
		isUnique := !m.crashSigs[sig]
		if isUnique {
			m.crashSigs[sig] = true
			m.uniqueCrashCount++
			m.uniqueCrashList = append(m.uniqueCrashList, CrashAnalysisEntry{
				File:  e.Name(),
				Type:  crashType,
				Stack: stack,
			})
			// Copy the crash input to unique_crashes/ (one per signature)
			// so the snapshot is self-contained for crash reproduction.
			_ = copyFile(path, filepath.Join(m.uniqueCrashesDir, e.Name()))
		}
		m.crashMu.Unlock()
		analyzed++
	}
	if analyzed > 0 {
		m.saveCrashAnalysis()
	}
}

// loadCrashAnalysis loads crash-analysis.json on startup (resume) so the
// dedup state survives restart. Existing crash files are marked as seen ONLY
// if a prior analysis was loaded (meaning they were already analyzed). If no
// analysis file exists (first time with new code on an old snapshot), existing
// crashes are NOT marked — the crash loop will analyze them from scratch.
func (m *CorpusMonitor) loadCrashAnalysis() {
	loaded := false
	data, err := os.ReadFile(m.crashAnalysisPath)
	if err == nil {
		var loaded_ struct {
			Total  int                  `json:"total_crashes"`
			Unique int                  `json:"unique_crashes"`
			List   []CrashAnalysisEntry `json:"unique_list"`
		}
		if json.Unmarshal(data, &loaded_) == nil {
			m.crashMu.Lock()
			m.uniqueCrashCount = loaded_.Unique
			m.uniqueCrashList = loaded_.List
			for _, e := range loaded_.List {
				m.crashSigs[e.Stack] = true
			}
			m.crashMu.Unlock()
			loaded = true
		}
	}
	// Only mark existing crash files as seen if we loaded a prior analysis.
	// Otherwise (no crash-analysis.json) the crash loop analyzes them fresh.
	if loaded {
		entries, err := os.ReadDir(m.crashesDir)
		if err == nil {
			m.crashMu.Lock()
			m.totalCrashCount = 0
			for _, e := range entries {
				if !e.IsDir() {
					m.totalCrashCount++
					m.seenCrashes[filepath.Join(m.crashesDir, e.Name())] = true
				}
			}
			m.crashMu.Unlock()
		}
	}
}

func (m *CorpusMonitor) saveCrashAnalysis() {
	m.crashMu.Lock()
	defer m.crashMu.Unlock()
	data, _ := json.MarshalIndent(struct {
		Total  int                  `json:"total_crashes"`
		Unique int                  `json:"unique_crashes"`
		List   []CrashAnalysisEntry `json:"unique_list"`
	}{
		Total:  m.totalCrashCount,
		Unique: m.uniqueCrashCount,
		List:   m.uniqueCrashList,
	}, "", "  ")
	_ = os.WriteFile(m.crashAnalysisPath, data, 0o644)
}

// CrashAnalysisData returns the current per-snapshot crash analysis state for
// the web UI's snapshot comparison panel.
type CrashAnalysisSummary struct {
	Total  int `json:"total_crashes"`
	Unique int `json:"unique_crashes"`
}

func (m *CorpusMonitor) CrashAnalysisData() CrashAnalysisSummary {
	m.crashMu.Lock()
	defer m.crashMu.Unlock()
	return CrashAnalysisSummary{Total: m.totalCrashCount, Unique: m.uniqueCrashCount}
}
