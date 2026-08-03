package state

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	want := New("https://github.com/a/b", "main", "b", "/tmp/b")
	want.Stage = StageBuilt
	want.StaticLibraries = []string{"/tmp/libb.a"}
	if err := want.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Stage != StageBuilt || got.ProjectName != "b" || len(got.StaticLibraries) != 1 {
		t.Fatalf("unexpected state: %#v", got)
	}
}

func TestEffectiveStageForLegacyTerminalState(t *testing.T) {
	runState := New("repo", "", "repo", "/source")
	runState.Stage = StageBlocked
	runState.RecordError(StageComprehended, errors.New("temporary failure"))

	if got := runState.EffectiveStage(); got != StagePreprocessed {
		t.Fatalf("EffectiveStage() = %q, want %q", got, StagePreprocessed)
	}
	if got := runState.TerminalStatus(); got != RunStatusBlocked {
		t.Fatalf("TerminalStatus() = %q, want %q", got, RunStatusBlocked)
	}
}

func TestRestoreResumeStageFromLegacyTerminalState(t *testing.T) {
	runState := New("repo", "", "repo", "/source")
	runState.Stage = StageBlocked
	runState.RecordError(StageComprehended, errors.New("temporary failure"))

	if err := runState.RestoreResumeStage(); err != nil {
		t.Fatal(err)
	}
	if runState.Stage != StagePreprocessed {
		t.Fatalf("got resume stage %q, want %q", runState.Stage, StagePreprocessed)
	}
	if runState.RunStatus != "" {
		t.Fatalf("RunStatus = %q, want cleared status", runState.RunStatus)
	}
}

func TestRestoreResumeStageFromRunStatusKeepsCompletedStage(t *testing.T) {
	runState := New("repo", "", "repo", "/source")
	runState.Stage = StageGenerated
	runState.RunStatus = RunStatusFailed
	runState.RecordError(StageFuzzing, errors.New("fuzz interrupted"))

	if err := runState.RestoreResumeStage(); err != nil {
		t.Fatal(err)
	}
	if runState.Stage != StageGenerated {
		t.Fatalf("got resume stage %q, want %q", runState.Stage, StageGenerated)
	}
	if runState.RunStatus != "" {
		t.Fatalf("RunStatus = %q, want cleared status", runState.RunStatus)
	}
}

func TestRestoreResumeStageRejectsLegacyMissingError(t *testing.T) {
	runState := New("repo", "", "repo", "/source")
	runState.Stage = StageFailed
	if err := runState.RestoreResumeStage(); err == nil {
		t.Fatal("expected malformed state to be rejected")
	}
}
