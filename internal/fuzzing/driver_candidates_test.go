package fuzzing

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLoadMultiFuzzStateImportsPendingDriverCandidates(t *testing.T) {
	root := t.TempDir()
	logsDir := filepath.Join(root, "logs", "fuzzing")
	statePath := filepath.Join(logsDir, "multi-fuzzing-state.json")

	baseDir := writeDriverTargetSnapshotFixture(t, logsDir, 7, 1)
	candidateDir := writeDriverTargetSnapshotFixture(t, logsDir, 7, 2)
	if err := writeDriverCandidateMarker(candidateDir, driverCandidateMarker{
		DriverID:  7,
		Seq:       2,
		BaseSeq:   1,
		CrashFile: "crash-a",
		Status:    "pending",
		Report:    "added bounds check",
		CreatedAt: time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC).Format(time.RFC3339),
		UpdatedAt: time.Date(2026, 8, 3, 10, 0, 0, 0, time.UTC).Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}

	baseState := &TargetState{
		DriverID:        7,
		Seq:             1,
		Source:          targetSnapshotSource(baseDir, 7),
		CurrentSnapshot: baseDir,
		BinaryPath:      filepath.Join(baseDir, "cov_driver"),
		CorpusDir:       filepath.Join(baseDir, "corpus"),
		Status:          "queued",
	}
	if err := (&MultiFuzzState{
		Targets: map[int]*TargetState{7: baseState},
		Versions: map[string]*TargetState{
			targetVersionKey(7, 1): baseState,
		},
	}).Save(statePath); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadMultiFuzzState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	candidate := loaded.Versions[targetVersionKey(7, 2)]
	if candidate == nil {
		t.Fatal("candidate version was not imported from snapshot marker")
	}
	if candidate.ApprovalStatus != "pending" || candidate.Status != "candidate" {
		t.Fatalf("candidate status = %#v, want pending approval-gated candidate", candidate)
	}
	if candidate.CandidateBaseSeq != 1 || candidate.CandidateCrash != "crash-a" || candidate.CandidateReport != "added bounds check" {
		t.Fatalf("candidate marker fields were not restored: %#v", candidate)
	}
	if TargetSchedulable(candidate) {
		t.Fatalf("pending candidate should not be schedulable: %#v", candidate)
	}
	if TargetDisplayStatus(candidate) != "candidate" {
		t.Fatalf("display status = %q, want candidate", TargetDisplayStatus(candidate))
	}
}

func TestSchedulerVersionQueuesSkipApprovalGatedCandidates(t *testing.T) {
	runningReady := &TargetState{DriverID: 1, Seq: 1, Status: "running"}
	pendingCandidate := &TargetState{DriverID: 1, Seq: 2, Status: "candidate", ApprovalStatus: "pending"}
	rejectedCandidate := &TargetState{DriverID: 2, Seq: 1, Status: "rejected", ApprovalStatus: "rejected"}
	queuedReady := &TargetState{DriverID: 3, Seq: 1, Status: "queued"}
	state := &MultiFuzzState{
		Targets: map[int]*TargetState{
			1: pendingCandidate,
			2: rejectedCandidate,
			3: queuedReady,
		},
		Versions: map[string]*TargetState{
			targetVersionKey(1, 1): runningReady,
			targetVersionKey(1, 2): pendingCandidate,
			targetVersionKey(2, 1): rejectedCandidate,
			targetVersionKey(3, 1): queuedReady,
		},
	}

	running, queued := schedulerVersionQueues(state)
	if len(running) != 1 || running[0] != (TargetVersionRef{DriverID: 1, Seq: 1}) {
		t.Fatalf("running versions = %#v, want only approved/running d1/v1", running)
	}
	if len(queued) != 1 || queued[0] != (TargetVersionRef{DriverID: 3, Seq: 1}) {
		t.Fatalf("queued versions = %#v, want only schedulable queued d3/v1", queued)
	}
}

func TestUpdateDriverCandidateApprovalPersistsApprovedState(t *testing.T) {
	root := t.TempDir()
	logsDir := filepath.Join(root, "logs", "fuzzing")
	statePath := filepath.Join(logsDir, "multi-fuzzing-state.json")

	baseDir := writeDriverTargetSnapshotFixture(t, logsDir, 7, 1)
	candidateDir := writeDriverTargetSnapshotFixture(t, logsDir, 7, 2)
	createdAt := time.Date(2026, 8, 3, 11, 12, 13, 0, time.UTC).Format(time.RFC3339)
	if err := writeDriverCandidateMarker(candidateDir, driverCandidateMarker{
		DriverID:  7,
		Seq:       2,
		BaseSeq:   1,
		CrashFile: "crash-a",
		Status:    "pending",
		Report:    "added bounds check",
		CreatedAt: createdAt,
		UpdatedAt: createdAt,
	}); err != nil {
		t.Fatal(err)
	}

	baseState := &TargetState{
		DriverID:        7,
		Seq:             1,
		Source:          targetSnapshotSource(baseDir, 7),
		CurrentSnapshot: baseDir,
		BinaryPath:      filepath.Join(baseDir, "cov_driver"),
		CorpusDir:       filepath.Join(baseDir, "corpus"),
		Status:          "queued",
	}
	candidateState := &TargetState{
		DriverID:         7,
		Seq:              2,
		Source:           targetSnapshotSource(candidateDir, 7),
		CurrentSnapshot:  candidateDir,
		BinaryPath:       filepath.Join(candidateDir, "cov_driver"),
		CorpusDir:        filepath.Join(candidateDir, "corpus"),
		Status:           "candidate",
		ApprovalStatus:   "pending",
		CandidateBaseSeq: 1,
		CandidateCrash:   "crash-a",
		CandidateReport:  "added bounds check",
		CandidateAt:      createdAt,
	}
	if err := (&MultiFuzzState{
		Targets: map[int]*TargetState{7: candidateState},
		Versions: map[string]*TargetState{
			targetVersionKey(7, 1): baseState,
			targetVersionKey(7, 2): candidateState,
		},
	}).Save(statePath); err != nil {
		t.Fatal(err)
	}

	approved, err := UpdateDriverCandidateApproval(logsDir, 7, 2, "approve")
	if err != nil {
		t.Fatal(err)
	}
	if approved.ApprovalStatus != "approved" || approved.Status != "queued" {
		t.Fatalf("approved candidate = %#v, want queued+approved", approved)
	}

	marker := readDriverCandidateMarker(candidateDir)
	if marker == nil || marker.Status != "approved" {
		t.Fatalf("candidate marker = %#v, want approved", marker)
	}

	loaded, err := LoadMultiFuzzState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	reloaded := loaded.Versions[targetVersionKey(7, 2)]
	if reloaded == nil || reloaded.ApprovalStatus != "approved" || reloaded.Status != "queued" {
		t.Fatalf("reloaded approved candidate = %#v", reloaded)
	}

	if _, err := UpdateDriverCandidateApproval(logsDir, 7, 2, "reject"); err == nil || !strings.Contains(err.Error(), "already approved") {
		t.Fatalf("repeat action error = %v, want already approved rejection", err)
	}
}

func writeDriverTargetSnapshotFixture(t *testing.T, logsDir string, driverID, seq int) string {
	t.Helper()
	snapDir := targetSnapshotDir(logsDir, driverID, seq)
	for _, dir := range []string{
		filepath.Join(snapDir, "driver"),
		filepath.Join(snapDir, "corpus"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	source := filepath.Join(snapDir, "driver", "fuzz_driver_"+strconv.Itoa(driverID)+".c")
	if err := os.WriteFile(source, []byte("int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned long Size) { return Size > 0 ? Data[0] : 0; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapDir, "build_cov_driver.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return snapDir
}
