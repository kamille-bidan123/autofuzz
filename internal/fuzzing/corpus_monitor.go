package fuzzing

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	monitorCovInterval = 60 * time.Second
)

var liveCorpusMonitors = struct {
	sync.RWMutex
	bySnapshot map[string]*CorpusMonitor
}{bySnapshot: map[string]*CorpusMonitor{}}

// CoverageSnapshot is a cached llvm-cov export result, updated periodically by
// the monitor's coverage loop for the web UI.
type CoverageSnapshot struct {
	Timestamp   time.Time          `json:"timestamp"`
	Available   bool               `json:"available"`
	SeedCount   int                `json:"seed_count"`
	Coverage    CoverageStatus     `json:"coverage"`
	APICoverage *APICoverageReport `json:"api_coverage,omitempty"`
}

// CorpusMonitor watches runtime LLVM profile output in the background. The
// live fuzzer writes profraw files under profileDir; the monitor periodically
// merges them into aggregate.profdata and exports aggregate source coverage for
// the web UI and LLM analysis. It does not replay corpus seeds.
type CorpusMonitor struct {
	cfg          FuzzConfig
	workDir      string
	profileDir   string // live fuzzer profraw files
	profdataPath string // running aggregate (incrementally merged)
	profileMu    sync.Mutex

	mu         sync.RWMutex
	totalSeeds int

	covMu    sync.RWMutex
	covCache CoverageSnapshot

	// Per-snapshot real-time crash analysis: replays each new crash on the
	// snapshot's own binary, extracts the symbolized ASan stack for dedup,
	// and persists the result (total + unique count + unique list) to
	// crash-analysis.json in the snapshot dir.
	crashMu            sync.Mutex
	seenCrashes        map[string]bool
	crashSigs          map[string]bool
	uniqueCrashList    []CrashAnalysisEntry
	totalCrashCount    int
	uniqueCrashCount   int
	crashAnalysisPath  string
	snapshotDir        string
	snapshotBinaryPath string
	crashesDir         string
	uniqueCrashesDir   string
	crashReportsDir    string

	stop chan struct{}
	wg   sync.WaitGroup
}

func NewCorpusMonitor(cfg FuzzConfig, workDir string) *CorpusMonitor {
	snapDir := filepath.Dir(workDir) // fuzz-NNN/ (parent of monitor/)
	return &CorpusMonitor{
		cfg:                cfg,
		workDir:            workDir,
		profileDir:         filepath.Join(workDir, "profiles"),
		profdataPath:       filepath.Join(workDir, "aggregate.profdata"),
		seenCrashes:        map[string]bool{},
		crashSigs:          map[string]bool{},
		crashAnalysisPath:  filepath.Join(snapDir, "crash-analysis.json"),
		snapshotDir:        snapDir,
		snapshotBinaryPath: filepath.Join(snapDir, filepath.Base(cfg.BinaryPath)),
		crashesDir:         filepath.Join(snapDir, "crashes"),
		uniqueCrashesDir:   filepath.Join(snapDir, "unique_crashes"),
		crashReportsDir:    filepath.Join(snapDir, "crash-reports"),
		stop:               make(chan struct{}),
	}
}

func (m *CorpusMonitor) Start(ctx context.Context) {
	_ = os.MkdirAll(m.workDir, 0o755)
	_ = os.MkdirAll(m.profileDir, 0o755)
	_ = os.MkdirAll(m.uniqueCrashesDir, 0o755)
	_ = os.MkdirAll(m.crashReportsDir, 0o755)
	registerLiveCorpusMonitor(m)
	// Load existing crash analysis (resume): rebuild dedup state + mark
	// existing crash files as seen so we only analyze new ones.
	m.loadCrashAnalysis()
	m.enqueuePendingCrashReports(ctx)
	m.wg.Add(2)
	go func() { defer m.wg.Done(); m.coverageLoop(ctx) }()
	go func() { defer m.wg.Done(); m.crashLoop(ctx) }()
}

// coverageLoop merges live profraw files and runs llvm-cov export on the
// aggregate profdata every minute. The export is NOT under the main mutex.
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
	m.mergeLiveProfiles()
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
	seedCount := countCorpusSeeds(m.cfg.CorpusDir)
	m.mu.Lock()
	m.totalSeeds = seedCount
	m.mu.Unlock()
	snap.SeedCount = seedCount
	m.covMu.Lock()
	m.covCache = snap
	m.covMu.Unlock()
}

func (m *CorpusMonitor) mergeLiveProfiles() {
	m.profileMu.Lock()
	defer m.profileMu.Unlock()

	profrawBin := findTool("llvm-profdata")
	if profrawBin == "" {
		return
	}
	profraws := mergeableProfrawFiles(m.profileDir)
	if len(profraws) == 0 {
		return
	}
	tmpPath := m.profdataPath + ".tmp"
	args := []string{"merge", "-sparse", "-o", tmpPath}
	if fileExists(m.profdataPath) {
		args = append(args, m.profdataPath)
	}
	args = append(args, profraws...)
	cmd := exec.Command(profrawBin, args...)
	if err := cmd.Run(); err != nil {
		_ = os.Remove(tmpPath)
		return
	}
	if err := os.Rename(tmpPath, m.profdataPath); err != nil {
		_ = os.Remove(tmpPath)
		return
	}
	for _, profraw := range profraws {
		_ = os.Remove(profraw)
	}
}

func mergeableProfrawFiles(profileDir string) []string {
	paths, _ := filepath.Glob(filepath.Join(profileDir, "*.profraw"))
	if len(paths) == 0 {
		return nil
	}
	mergeable := make([]string, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() || info.Size() == 0 {
			continue
		}
		mergeable = append(mergeable, path)
	}
	return mergeable
}

func countCorpusSeeds(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			count++
		}
	}
	return count
}

func (m *CorpusMonitor) CoverageCache() CoverageSnapshot {
	m.covMu.RLock()
	defer m.covMu.RUnlock()
	return CloneCoverageSnapshot(m.covCache)
}

func (m *CorpusMonitor) Stop() {
	select {
	case <-m.stop:
	default:
		close(m.stop)
	}
	m.wg.Wait()
	unregisterLiveCorpusMonitor(m)
}

func registerLiveCorpusMonitor(m *CorpusMonitor) {
	if m == nil {
		return
	}
	liveCorpusMonitors.Lock()
	liveCorpusMonitors.bySnapshot[corpusMonitorSnapshotKey(m.snapshotDir)] = m
	liveCorpusMonitors.Unlock()
}

func unregisterLiveCorpusMonitor(m *CorpusMonitor) {
	if m == nil {
		return
	}
	key := corpusMonitorSnapshotKey(m.snapshotDir)
	liveCorpusMonitors.Lock()
	if liveCorpusMonitors.bySnapshot[key] == m {
		delete(liveCorpusMonitors.bySnapshot, key)
	}
	liveCorpusMonitors.Unlock()
}

func corpusMonitorSnapshotKey(snapshotDir string) string {
	if abs, err := filepath.Abs(snapshotDir); err == nil {
		snapshotDir = abs
	}
	return filepath.Clean(snapshotDir)
}

// Snapshot returns the current aggregate coverage status instantly. It does
// not replay corpus seeds or attribute branches to individual seeds.
func (m *CorpusMonitor) Snapshot(sourceDir, buildDir string, logf func(string, ...any)) (CorpusCoverageStatus, error) {
	m.mergeLiveProfiles()
	if !fileExists(m.profdataPath) {
		return CorpusCoverageStatus{CorpusDir: m.cfg.CorpusDir}, nil
	}

	cs, err := CollectCoverageStatus(m.profdataPath, m.cfg.BinaryPath, sourceDir, buildDir)
	if err != nil {
		return CorpusCoverageStatus{}, fmt.Errorf("monitor snapshot: %w", err)
	}

	seedCount := countCorpusSeeds(m.cfg.CorpusDir)
	m.mu.Lock()
	m.totalSeeds = seedCount
	m.mu.Unlock()
	m.covMu.Lock()
	m.covCache = CoverageSnapshot{
		Timestamp: time.Now(),
		Available: true,
		SeedCount: seedCount,
		Coverage:  cs,
	}
	m.covMu.Unlock()
	status := CoverageStatusToCorpusCoverage(cs, seedCount, false, m.cfg.CorpusDir)

	if logf != nil {
		logf("[corpus-monitor] snapshot: seeds=%d executed=%d full=%d partial=%d uncovered=%d\n",
			seedCount, status.Summary.ExecutedFunctions,
			status.Summary.FullFunctions, status.Summary.PartialFunctions, len(status.Uncovered))
	}

	return status, nil
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
	var uniqueFiles []string
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
		replay := replayCrashDetailed(ctx, m.snapshotBinaryPath, m.crashesDir, path)
		m.crashMu.Lock()
		m.seenCrashes[path] = true
		m.totalCrashCount++
		sig := replay.Stack
		if !replay.Reproduced {
			sig = "no-crash:" + e.Name()
		}
		isUnique := !m.crashSigs[sig]
		if isUnique {
			m.crashSigs[sig] = true
			m.uniqueCrashCount++
			entry := CrashAnalysisEntry{
				File:            e.Name(),
				Type:            normalizeCrashAnalysisType(e.Name(), replay.Type),
				Stack:           replay.Stack,
				ASanReport:      replay.ASanReport,
				Signature:       sig,
				UniquePath:      m.uniqueCrashRel(e.Name()),
				ReportPath:      m.crashReportRel(e.Name()),
				ReportStatus:    "pending",
				ReportUpdatedAt: time.Now().Format(time.RFC3339),
			}
			if shouldSkipCrashLLMAnalysis(entry) {
				entry.ReportStatus = "skipped"
				entry.ReportError = skippedCrashLLMAnalysisReason(entry)
			}
			m.uniqueCrashList = append(m.uniqueCrashList, entry)
			// Copy the crash input to unique_crashes/ (one per signature)
			// so the snapshot is self-contained for crash reproduction.
			_ = copyFile(path, filepath.Join(m.uniqueCrashesDir, e.Name()))
			if entry.ReportStatus != "skipped" {
				uniqueFiles = append(uniqueFiles, e.Name())
			}
		}
		m.crashMu.Unlock()
		analyzed++
	}
	if analyzed > 0 {
		m.saveCrashAnalysis()
	}
	for _, file := range uniqueFiles {
		m.enqueueCrashReport(ctx, file)
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
			for i := range m.uniqueCrashList {
				m.ensureCrashEntryPaths(&m.uniqueCrashList[i])
				sig := m.uniqueCrashList[i].Signature
				if sig == "" {
					sig = m.uniqueCrashList[i].Stack
				}
				if sig != "" {
					m.crashSigs[sig] = true
				}
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
	m.saveCrashAnalysisLocked()
}

func (m *CorpusMonitor) saveCrashAnalysisLocked() {
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

func (m *CorpusMonitor) uniqueCrashRel(file string) string {
	return filepath.ToSlash(filepath.Join("unique_crashes", filepath.Base(file)))
}

func (m *CorpusMonitor) crashReportRel(file string) string {
	return filepath.ToSlash(filepath.Join("crash-reports", safeCrashReportName(file)+".json"))
}

func safeCrashReportName(name string) string {
	name = filepath.Base(name)
	var b strings.Builder
	for _, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' {
			b.WriteRune(ch)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if strings.Trim(out, "._-") == "" {
		return "crash"
	}
	return out
}

func shouldSkipCrashLLMAnalysis(entry CrashAnalysisEntry) bool {
	if isLeakCrashAnalysisArtifact(entry.File) {
		return false
	}
	return isSkippedCrashAnalysisKind(entry.Type) || isSkippedCrashAnalysisArtifact(entry.File)
}

func ShouldSkipCrashLLMAnalysis(entry CrashAnalysisEntry) bool {
	return shouldSkipCrashLLMAnalysis(entry)
}

func NormalizeCrashAnalysisEntryType(entry *CrashAnalysisEntry) {
	if entry == nil {
		return
	}
	entry.Type = normalizeCrashAnalysisType(entry.File, entry.Type)
}

func skippedCrashLLMAnalysisReason(entry CrashAnalysisEntry) string {
	kind := entry.Type
	if !isSkippedCrashAnalysisKind(kind) {
		kind = filepath.Base(entry.File)
	}
	return fmt.Sprintf("LLM crash analysis skipped for %s unique crash", kind)
}

func isSkippedCrashAnalysisKind(value string) bool {
	kind := normalizeCrashAnalysisKind(value)
	return kind == "timeout" || kind == "slowunit"
}

func isSkippedCrashAnalysisArtifact(file string) bool {
	kind := normalizeCrashAnalysisKind(filepath.Base(file))
	return strings.HasPrefix(kind, "timeout") || strings.HasPrefix(kind, "slowunit")
}

func isLeakCrashAnalysisArtifact(file string) bool {
	return strings.HasPrefix(normalizeCrashAnalysisKind(filepath.Base(file)), "leak")
}

func normalizeCrashAnalysisType(file, typ string) string {
	if isLeakCrashAnalysisArtifact(file) {
		return "leak"
	}
	if strings.TrimSpace(typ) == "" {
		return "unknown"
	}
	return typ
}

func normalizeCrashAnalysisKind(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, ch := range value {
		if ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

func (m *CorpusMonitor) ensureCrashEntryPaths(entry *CrashAnalysisEntry) {
	entry.Type = normalizeCrashAnalysisType(entry.File, entry.Type)
	if entry.UniquePath == "" {
		entry.UniquePath = m.uniqueCrashRel(entry.File)
	}
	if entry.ReportPath == "" {
		entry.ReportPath = m.crashReportRel(entry.File)
	}
	if shouldSkipCrashLLMAnalysis(*entry) && entry.ReportStatus != "completed" {
		entry.ReportStatus = "skipped"
		entry.ReportError = skippedCrashLLMAnalysisReason(*entry)
		return
	}
	if entry.ReportStatus == "" {
		reportPath := filepath.Join(m.snapshotDir, filepath.FromSlash(entry.ReportPath))
		if fileExists(reportPath) {
			entry.ReportStatus = "completed"
		} else {
			entry.ReportStatus = "pending"
		}
	}
}

func (m *CorpusMonitor) enqueuePendingCrashReports(ctx context.Context) {
	var files []string
	m.crashMu.Lock()
	for i := range m.uniqueCrashList {
		m.ensureCrashEntryPaths(&m.uniqueCrashList[i])
		switch m.uniqueCrashList[i].ReportStatus {
		case "completed", "skipped":
			continue
		default:
			files = append(files, m.uniqueCrashList[i].File)
		}
	}
	m.saveCrashAnalysisLocked()
	m.crashMu.Unlock()
	for _, file := range files {
		m.enqueueCrashReport(ctx, file)
	}
}

func (m *CorpusMonitor) enqueueCrashReport(ctx context.Context, file string) {
	if file == "" {
		return
	}
	entry, ok := m.crashEntry(file)
	if !ok {
		return
	}
	analysisCfg := m.cfg
	analysisCfg.BinaryPath = m.snapshotBinaryPath
	queued, err := EnqueueCrashAnalysis(ctx, CrashAnalysisJob{
		Key:         CrashAnalysisJobKey(m.snapshotDir, file),
		Config:      analysisCfg,
		SnapshotDir: m.snapshotDir,
		Entry:       entry,
		OnQueued: func() {
			m.updateCrashReportState(file, "queued", "", "", "")
			m.cfg.logf("[crash-analysis] queued unique crash %s in %s\n", file, m.snapshotDir)
		},
		OnStart: func() {
			m.updateCrashReportState(file, "running", "", "", "")
			m.cfg.logf("[crash-analysis] analyzing unique crash %s in %s\n", file, m.snapshotDir)
		},
		OnComplete: func(report CrashLLMReport) {
			m.cfg.logf("[crash-analysis] unique crash %s classified as %s\n", file, report.Classification)
			m.updateCrashReportState(file, "completed", report.Classification, report.Analysis, "")
		},
		OnError: func(err error) {
			m.cfg.logf("[crash-analysis] unique crash %s analysis failed: %v\n", file, err)
			m.updateCrashReportState(file, "failed", "", "", err.Error())
		},
		OnCancel: func() {
			m.cfg.logf("[crash-analysis] unique crash %s removed from analysis queue\n", file)
			m.updateCrashReportState(file, "pending", "", "", "")
		},
	})
	if err != nil {
		m.cfg.logf("[crash-analysis] unique crash %s queue failed: %v\n", file, err)
		m.updateCrashReportState(file, "failed", "", "", err.Error())
		return
	}
	if !queued {
		m.cfg.logf("[crash-analysis] unique crash %s is already queued or running\n", file)
	}
}

func AnalyzeUniqueCrashWithLLM(ctx context.Context, cfg FuzzConfig, snapshotDir string, entry CrashAnalysisEntry) (CrashLLMReport, error) {
	file := filepath.Base(entry.File)
	if file == "." || file == string(filepath.Separator) || strings.TrimSpace(file) == "" {
		return CrashLLMReport{}, fmt.Errorf("invalid crash file")
	}
	if cfg.BinaryPath == "" {
		cfg.BinaryPath = filepath.Join(snapshotDir, "cov_driver")
	}
	if entry.UniquePath == "" {
		entry.UniquePath = filepath.ToSlash(filepath.Join("unique_crashes", file))
	}
	if entry.ReportPath == "" {
		entry.ReportPath = filepath.ToSlash(filepath.Join("crash-reports", safeCrashReportName(file)+".json"))
	}
	uniquePath := filepath.Join(snapshotDir, filepath.FromSlash(entry.UniquePath))
	reportPath := filepath.Join(snapshotDir, filepath.FromSlash(entry.ReportPath))
	crashPath := filepath.Join(snapshotDir, "crashes", file)
	workDir := filepath.Join(snapshotDir, "crash-llm-work", safeCrashReportName(file))
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return CrashLLMReport{}, err
	}
	analyzer := CodexAnalyzer{
		Command:   cfg.CodexCommand,
		Model:     cfg.CodexModel,
		Profile:   cfg.CodexProfile,
		Timeout:   30 * time.Minute,
		Runner:    cfg.Runner,
		EventSink: cfg.EventSink,
		LogSink:   cfg.LogSink,
	}
	report, err := analyzer.AnalyzeCrash(ctx, CrashAnalysisRequest{
		SnapshotDir:     snapshotDir,
		SourceDir:       cfg.SourceDir,
		BinaryPath:      cfg.BinaryPath,
		CrashPath:       crashPath,
		UniqueCrashPath: uniquePath,
		CrashFile:       file,
		CrashType:       entry.Type,
		Stack:           entry.Stack,
		ASanReport:      entry.ASanReport,
	}, workDir)
	if err != nil {
		return CrashLLMReport{}, err
	}
	entry.ReportStatus = "completed"
	entry.ReportError = ""
	entry.ReportUpdatedAt = time.Now().Format(time.RFC3339)
	entry.Classification = report.Classification
	entry.Analysis = report.Analysis
	out, _ := json.MarshalIndent(struct {
		GeneratedAt     string             `json:"generated_at"`
		SnapshotDir     string             `json:"snapshot_dir"`
		SourceDir       string             `json:"source_dir"`
		BinaryPath      string             `json:"binary_path"`
		CrashPath       string             `json:"crash_path"`
		UniqueCrashPath string             `json:"unique_crash_path"`
		StackSignature  string             `json:"stack_signature"`
		ASanReport      string             `json:"asan_report,omitempty"`
		Report          CrashLLMReport     `json:"report"`
		Entry           CrashAnalysisEntry `json:"entry"`
	}{
		GeneratedAt:     time.Now().Format(time.RFC3339),
		SnapshotDir:     snapshotDir,
		SourceDir:       cfg.SourceDir,
		BinaryPath:      cfg.BinaryPath,
		CrashPath:       crashPath,
		UniqueCrashPath: uniquePath,
		StackSignature:  entry.Stack,
		ASanReport:      entry.ASanReport,
		Report:          report,
		Entry:           entry,
	}, "", "  ")
	if err := os.MkdirAll(filepath.Dir(reportPath), 0o755); err != nil {
		return CrashLLMReport{}, err
	}
	if err := os.WriteFile(reportPath, out, 0o644); err != nil {
		return CrashLLMReport{}, err
	}
	return report, nil
}

func (m *CorpusMonitor) crashEntry(file string) (CrashAnalysisEntry, bool) {
	m.crashMu.Lock()
	defer m.crashMu.Unlock()
	for i := range m.uniqueCrashList {
		if m.uniqueCrashList[i].File == file {
			m.ensureCrashEntryPaths(&m.uniqueCrashList[i])
			return m.uniqueCrashList[i], true
		}
	}
	return CrashAnalysisEntry{}, false
}

func (m *CorpusMonitor) updateCrashReportState(file, status, classification, analysis, errText string) {
	m.crashMu.Lock()
	defer m.crashMu.Unlock()
	for i := range m.uniqueCrashList {
		if m.uniqueCrashList[i].File != file {
			continue
		}
		m.ensureCrashEntryPaths(&m.uniqueCrashList[i])
		m.uniqueCrashList[i].ReportStatus = status
		m.uniqueCrashList[i].ReportUpdatedAt = time.Now().Format(time.RFC3339)
		m.uniqueCrashList[i].ReportError = errText
		if classification != "" {
			m.uniqueCrashList[i].Classification = classification
		}
		if analysis != "" {
			m.uniqueCrashList[i].Analysis = analysis
		}
		break
	}
	m.saveCrashAnalysisLocked()
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

// DeleteLiveUniqueCrashes removes unique crash entries from a running monitor,
// if that monitor owns snapshotDir. It returns false when the snapshot is not
// currently monitored.
func DeleteLiveUniqueCrashes(snapshotDir string, files []string) bool {
	key := corpusMonitorSnapshotKey(snapshotDir)
	liveCorpusMonitors.RLock()
	monitor := liveCorpusMonitors.bySnapshot[key]
	liveCorpusMonitors.RUnlock()
	if monitor == nil {
		return false
	}
	monitor.deleteUniqueCrashes(files)
	return true
}

func (m *CorpusMonitor) deleteUniqueCrashes(files []string) {
	selected := map[string]bool{}
	for _, file := range files {
		name := filepath.Base(strings.TrimSpace(file))
		if name == "" || name == "." || name == string(filepath.Separator) {
			continue
		}
		selected[name] = true
	}
	if len(selected) == 0 {
		return
	}
	m.crashMu.Lock()
	defer m.crashMu.Unlock()
	filtered := m.uniqueCrashList[:0]
	for _, entry := range m.uniqueCrashList {
		if selected[filepath.Base(entry.File)] {
			continue
		}
		filtered = append(filtered, entry)
	}
	m.uniqueCrashList = filtered
	m.uniqueCrashCount = len(m.uniqueCrashList)
	m.saveCrashAnalysisLocked()
}
