package webui

import (
	"testing"

	"autofuzz/internal/state"
)

func TestStageSnapshotsGivenAwaitingInput(t *testing.T) {
	runState := &state.RunState{
		GenerationTask: "given",
		Stage:          state.StagePreprocessed,
		RunStatus:      state.RunStatusAwaitingInput,
	}
	stages := stageSnapshotsFromState(runState)
	byID := map[string]StageSnapshot{}
	for _, stage := range stages {
		byID[stage.ID] = stage
	}
	if _, ok := byID[givenSelectionStageID]; !ok {
		t.Fatalf("given stage definitions must include %q, got %#v", givenSelectionStageID, stages)
	}
	if _, ok := byID[string(state.StageComprehended)]; ok {
		t.Fatalf("given stage definitions must NOT include comprehended, got %#v", stages)
	}
	if byID[givenSelectionStageID].Status != "running" {
		t.Fatalf("given_selection should be running while awaiting input, got %q", byID[givenSelectionStageID].Status)
	}
	if byID[string(state.StagePreprocessed)].Status != "completed" {
		t.Fatalf("preprocessed should be completed, got %q", byID[string(state.StagePreprocessed)].Status)
	}
	if byID[string(state.StageGenerated)].Status != "pending" {
		t.Fatalf("generated should be pending, got %q", byID[string(state.StageGenerated)].Status)
	}
}

func TestStageSnapshotsGivenSelectionDone(t *testing.T) {
	runState := &state.RunState{
		GenerationTask: "given",
		GivenFunctions: []string{"parse_value"},
		Stage:          state.StageGenerated,
	}
	stages := stageSnapshotsFromState(runState)
	byID := map[string]StageSnapshot{}
	for _, stage := range stages {
		byID[stage.ID] = stage
	}
	if byID[givenSelectionStageID].Status != "completed" {
		t.Fatalf("given_selection should be completed after generation, got %q", byID[givenSelectionStageID].Status)
	}
	if byID[string(state.StageGenerated)].Status != "completed" {
		t.Fatalf("generated should be completed, got %q", byID[string(state.StageGenerated)].Status)
	}
}
