package fuzzing

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const driverCandidateMarkerFile = "driver-fix-candidate.json"

type DriverCandidateAction struct {
	Action   string
	DriverID int
	Seq      int
	Result   chan error
}

type DriverCandidateEvent struct {
	State *TargetState
}

type DriverFixCandidateResult struct {
	State    *TargetState
	Response DriverCrashFixResponse
	Existing bool
}

type driverCandidateMarker struct {
	DriverID  int    `json:"driver_id"`
	Seq       int    `json:"seq"`
	BaseSeq   int    `json:"base_seq"`
	CrashFile string `json:"crash_file"`
	Status    string `json:"status"`
	Analysis  string `json:"analysis,omitempty"`
	Report    string `json:"report,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

func GenerateDriverFixCandidate(ctx context.Context, cfg FuzzConfig, snapshotDir string, entry CrashAnalysisEntry) (DriverFixCandidateResult, error) {
	driverID, baseSeq := snapshotDriverVersionIdentity(snapshotDir)
	if driverID <= 0 || baseSeq <= 0 {
		return DriverFixCandidateResult{}, fmt.Errorf("driver fix candidates require a multi-driver snapshot")
	}
	if existing := findDriverFixCandidateByBase(cfg.LogsDir, driverID, baseSeq); existing != nil {
		return DriverFixCandidateResult{
			State:    existing,
			Existing: true,
			Response: DriverCrashFixResponse{NeedsUpdate: true, CompilePassed: true, CrashResolved: existing.ApprovalStatus != "rejected", Analysis: existing.CandidateReport},
		}, nil
	}

	targetSource := targetSnapshotSource(snapshotDir, driverID)
	if targetSource == "" {
		return DriverFixCandidateResult{}, fmt.Errorf("driver source not found in %s", snapshotDir)
	}
	sourceState := &TargetState{
		DriverID:        driverID,
		Seq:             baseSeq,
		Source:          targetSource,
		CurrentSnapshot: snapshotDir,
		BinaryPath:      filepath.Join(snapshotDir, "cov_driver"),
		CorpusDir:       filepath.Join(snapshotDir, "corpus"),
		Status:          "running",
	}
	if hash, err := driverSourceHash(filepath.Join(snapshotDir, "driver")); err == nil {
		sourceState.SourceHash = hash
	}
	target := FuzzTarget{
		DriverID:    driverID,
		Source:      targetSource,
		BuildScript: filepath.Join(snapshotDir, "build_cov_driver.sh"),
	}

	tmpDir, _, err := prepareLLMWorkDir(ctx, cfg, target, sourceState, int(time.Now().Unix()%100000))
	if err != nil {
		return DriverFixCandidateResult{}, err
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
	crashPath := filepath.Join(snapshotDir, "unique_crashes", filepath.Base(entry.File))
	response, err := analyzer.AnalyzeDriverCrashFix(ctx, DriverCrashFixRequest{
		DriverID:      driverID,
		SourceDir:     cfg.SourceDir,
		WorkDir:       tmpDir,
		BuildScript:   filepath.Join(tmpDir, "build_cov_driver.sh"),
		BinaryPath:    filepath.Join(tmpDir, "cov_driver"),
		CrashFile:     filepath.Base(entry.File),
		CrashType:     entry.Type,
		UniqueCrash:   crashPath,
		ASanReport:    entry.ASanReport,
		CrashAnalysis: entry.Analysis,
	}, filepath.Join(tmpDir, "codex-driver-fix"))
	result := DriverFixCandidateResult{Response: response}
	if err != nil {
		return result, err
	}
	if !response.NeedsUpdate {
		return result, nil
	}
	if err := validateDriverFixCandidate(ctx, cfg, tmpDir, target, sourceState.SourceHash, crashPath, response); err != nil {
		return result, err
	}
	state, err := promoteTargetSnapshotCandidate(cfg, target, sourceState, tmpDir, filepath.Base(entry.File), response.Analysis)
	if err != nil {
		return result, err
	}
	result.State = state
	return result, nil
}

func validateDriverFixCandidate(ctx context.Context, cfg FuzzConfig, tmpDir string, target FuzzTarget, currentHash, crashPath string, response DriverCrashFixResponse) error {
	if !response.CompilePassed {
		return fmt.Errorf("LLM reported compile_passed=false")
	}
	if !response.CrashResolved {
		return fmt.Errorf("LLM reported crash_resolved=false")
	}
	if err := validateChangedFiles(tmpDir, target, response.ChangedFiles); err != nil {
		return err
	}
	if currentHash != "" {
		updatedHash, err := driverSourceHash(filepath.Join(tmpDir, "driver"))
		if err != nil {
			return err
		}
		if updatedHash == currentHash {
			return fmt.Errorf("LLM reported an update but target driver source did not change")
		}
	}
	if err := buildTargetSnapshot(ctx, cfg, tmpDir, "validate-driver-fix-build"); err != nil {
		return fmt.Errorf("validate build: %w", err)
	}
	if strings.TrimSpace(crashPath) == "" {
		return fmt.Errorf("unique crash path is empty")
	}
	if !fileExists(crashPath) {
		return fmt.Errorf("unique crash input not found: %s", crashPath)
	}
	replayCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	logDir := filepath.Join(tmpDir, "validate-driver-fix")
	if _, err := cfg.Runner.Run(replayCtx, logDir, "replay-driver-fix", tmpDir, nil, filepath.Join(tmpDir, "cov_driver"), "-runs=1", crashPath); err != nil {
		return fmt.Errorf("candidate driver still reproduces crash: %w", err)
	}
	return nil
}

func promoteTargetSnapshotCandidate(cfg FuzzConfig, target FuzzTarget, sourceState *TargetState, tmpDir, crashFile, analysis string) (*TargetState, error) {
	if sourceState == nil {
		return nil, fmt.Errorf("driver %d source state not found", target.DriverID)
	}
	nextSeq := nextTargetSnapshotSeq(cfg.LogsDir, target.DriverID, sourceState.Seq+1)
	finalDir := targetSnapshotDir(cfg.LogsDir, target.DriverID, nextSeq)
	if _, err := os.Stat(finalDir); err == nil {
		return nil, fmt.Errorf("target snapshot already exists: %s", finalDir)
	}
	if err := copyDirFiles(sourceState.CorpusDir, filepath.Join(tmpDir, "corpus"), false); err != nil {
		return nil, err
	}
	if err := rewriteSnapshotPaths(tmpDir, tmpDir, finalDir); err != nil {
		return nil, err
	}
	marker := driverCandidateMarker{
		DriverID:  target.DriverID,
		Seq:       nextSeq,
		BaseSeq:   sourceState.Seq,
		CrashFile: filepath.Base(crashFile),
		Status:    "pending",
		Analysis:  analysis,
		Report:    analysis,
		CreatedAt: time.Now().Format(time.RFC3339),
		UpdatedAt: time.Now().Format(time.RFC3339),
	}
	if err := writeDriverCandidateMarker(tmpDir, marker); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpDir, finalDir); err != nil {
		return nil, err
	}
	newState := &TargetState{DriverID: target.DriverID, Seq: nextSeq}
	updateTargetStateFromSnapshot(newState, target, finalDir, nextSeq)
	newState.Status = "candidate"
	applyDriverCandidateMarker(newState, &marker)
	return newState, nil
}

func applyDriverCandidateEvent(st *MultiFuzzState, event DriverCandidateEvent) bool {
	if st == nil || event.State == nil || event.State.DriverID <= 0 || event.State.Seq <= 0 {
		return false
	}
	st.addVersion(event.State)
	return true
}

func applyDriverCandidateAction(st *MultiFuzzState, action DriverCandidateAction) error {
	if st == nil {
		return fmt.Errorf("multi-fuzz state is unavailable")
	}
	state := st.Versions[targetVersionKey(action.DriverID, action.Seq)]
	if state == nil {
		return fmt.Errorf("driver candidate d%d/v%d not found", action.DriverID, action.Seq)
	}
	if state.ApprovalStatus != "" && state.ApprovalStatus != "pending" {
		return fmt.Errorf("driver candidate d%d/v%d is already %s", action.DriverID, action.Seq, state.ApprovalStatus)
	}
	marker := readDriverCandidateMarker(state.CurrentSnapshot)
	if marker == nil {
		marker = &driverCandidateMarker{
			DriverID:  state.DriverID,
			Seq:       state.Seq,
			BaseSeq:   state.CandidateBaseSeq,
			CrashFile: state.CandidateCrash,
			Analysis:  state.CandidateReport,
			Report:    state.CandidateReport,
			CreatedAt: state.CandidateAt,
		}
	}
	marker.UpdatedAt = time.Now().Format(time.RFC3339)
	switch action.Action {
	case "approve":
		state.ApprovalStatus = "approved"
		if state.Status == "" || state.Status == "candidate" || state.Status == "rejected" {
			state.Status = "queued"
		}
		marker.Status = "approved"
	case "reject":
		state.ApprovalStatus = "rejected"
		state.Status = "rejected"
		marker.Status = "rejected"
	default:
		return fmt.Errorf("unsupported candidate action %q", action.Action)
	}
	return writeDriverCandidateMarker(state.CurrentSnapshot, *marker)
}

func UpdateDriverCandidateApproval(logsDir string, driverID, seq int, action string) (*TargetState, error) {
	state, err := LoadDriverCandidateState(logsDir, driverID, seq)
	if err != nil {
		return nil, err
	}
	if state.ApprovalStatus != "" && state.ApprovalStatus != "pending" {
		return nil, fmt.Errorf("driver candidate d%d/v%d is already %s", driverID, seq, state.ApprovalStatus)
	}
	if err := applyDriverCandidateAction(&MultiFuzzState{
		Targets: map[int]*TargetState{driverID: state},
		Versions: map[string]*TargetState{
			targetVersionKey(driverID, seq): state,
		},
	}, DriverCandidateAction{Action: action, DriverID: driverID, Seq: seq}); err != nil {
		return nil, err
	}
	statePath := filepath.Join(logsDir, "multi-fuzzing-state.json")
	if multiState, err := LoadMultiFuzzState(statePath); err == nil && multiState != nil {
		if existing := multiState.Versions[targetVersionKey(driverID, seq)]; existing != nil {
			existing.Status = state.Status
			existing.ApprovalStatus = state.ApprovalStatus
			existing.CandidateBaseSeq = state.CandidateBaseSeq
			existing.CandidateCrash = state.CandidateCrash
			existing.CandidateReport = state.CandidateReport
			existing.CandidateAt = state.CandidateAt
		} else {
			multiState.addVersion(state)
		}
		if err := multiState.Save(statePath); err != nil {
			return nil, err
		}
	}
	return state, nil
}

func LoadDriverCandidateState(logsDir string, driverID, seq int) (*TargetState, error) {
	snapshotDir := targetSnapshotDir(logsDir, driverID, seq)
	source := targetSnapshotSource(snapshotDir, driverID)
	if source == "" {
		return nil, fmt.Errorf("driver candidate d%d/v%d not found", driverID, seq)
	}
	marker := readDriverCandidateMarker(snapshotDir)
	if marker == nil {
		return nil, fmt.Errorf("driver candidate d%d/v%d has no candidate marker", driverID, seq)
	}
	state := &TargetState{
		DriverID:        driverID,
		Seq:             seq,
		Source:          source,
		CurrentSnapshot: snapshotDir,
		BinaryPath:      filepath.Join(snapshotDir, "cov_driver"),
		CorpusDir:       filepath.Join(snapshotDir, "corpus"),
		Status:          "candidate",
	}
	applyDriverCandidateMarker(state, marker)
	return state, nil
}

func nextTargetSnapshotSeq(logsDir string, driverID, minSeq int) int {
	if minSeq < 1 {
		minSeq = 1
	}
	root := targetDriverRoot(logsDir, driverID)
	entries, err := os.ReadDir(root)
	if err != nil {
		return minSeq
	}
	nextSeq := minSeq
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		seq := parseVersionDirName(entry.Name())
		if seq >= nextSeq {
			nextSeq = seq + 1
		}
	}
	return nextSeq
}

func snapshotDriverVersionIdentity(snapshotDir string) (driverID, seq int) {
	base := filepath.Base(snapshotDir)
	parent := filepath.Base(filepath.Dir(snapshotDir))
	if !strings.HasPrefix(parent, "driver-") || !strings.HasPrefix(base, "v") {
		return 0, 0
	}
	driverID, _ = strconv.Atoi(strings.TrimPrefix(parent, "driver-"))
	seq, _ = strconv.Atoi(strings.TrimPrefix(base, "v"))
	return driverID, seq
}

func targetDriverRoot(logsDir string, driverID int) string {
	return filepath.Join(logsDir, "driver-targets", formatDriverID(driverID))
}

func findDriverFixCandidateByBase(logsDir string, driverID, baseSeq int) *TargetState {
	root := targetDriverRoot(logsDir, driverID)
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	var best *TargetState
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		seq := parseVersionDirName(entry.Name())
		if seq <= 0 {
			continue
		}
		snapDir := filepath.Join(root, entry.Name())
		marker := readDriverCandidateMarker(snapDir)
		if marker == nil || marker.BaseSeq != baseSeq {
			continue
		}
		source := targetSnapshotSource(snapDir, driverID)
		if source == "" {
			continue
		}
		state := &TargetState{
			DriverID:        driverID,
			Seq:             seq,
			Source:          source,
			CurrentSnapshot: snapDir,
			BinaryPath:      filepath.Join(snapDir, "cov_driver"),
			CorpusDir:       filepath.Join(snapDir, "corpus"),
			Status:          "candidate",
		}
		applyDriverCandidateMarker(state, marker)
		if best == nil || state.Seq > best.Seq {
			best = state
		}
	}
	return best
}

func FindDriverFixCandidateForBase(logsDir string, driverID, baseSeq int) *TargetState {
	return findDriverFixCandidateByBase(logsDir, driverID, baseSeq)
}

func driverCandidateMarkerPath(snapshotDir string) string {
	return filepath.Join(snapshotDir, driverCandidateMarkerFile)
}

func readDriverCandidateMarker(snapshotDir string) *driverCandidateMarker {
	data, err := os.ReadFile(driverCandidateMarkerPath(snapshotDir))
	if err != nil {
		return nil
	}
	var marker driverCandidateMarker
	if json.Unmarshal(data, &marker) != nil || marker.DriverID <= 0 || marker.Seq <= 0 {
		return nil
	}
	return &marker
}

func writeDriverCandidateMarker(snapshotDir string, marker driverCandidateMarker) error {
	if err := os.MkdirAll(snapshotDir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(driverCandidateMarkerPath(snapshotDir), append(data, '\n'), 0o644)
}

func applyDriverCandidateMarker(targetState *TargetState, marker *driverCandidateMarker) {
	if targetState == nil || marker == nil {
		return
	}
	targetState.CandidateBaseSeq = marker.BaseSeq
	targetState.CandidateCrash = marker.CrashFile
	targetState.CandidateReport = marker.Report
	targetState.CandidateAt = marker.CreatedAt
	switch marker.Status {
	case "pending", "":
		targetState.ApprovalStatus = "pending"
		targetState.Status = "candidate"
	case "approved":
		targetState.ApprovalStatus = "approved"
		if targetState.Status == "" || targetState.Status == "candidate" || targetState.Status == "rejected" {
			targetState.Status = "queued"
		}
	case "rejected":
		targetState.ApprovalStatus = "rejected"
		targetState.Status = "rejected"
	default:
		targetState.ApprovalStatus = marker.Status
	}
}
