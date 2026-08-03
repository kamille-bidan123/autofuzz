package agent

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"autofuzz/internal/state"
)

func TestFailKeepsStageOnContextCancellation(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "agent-state.json")
	runState := state.New("repo", "", "repo", "/source")
	runState.Stage = state.StageGenerated
	agent := &Agent{State: runState, StatePath: statePath}

	err := agent.fail(state.StageFuzzing, context.Canceled)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("fail() error = %v, want context.Canceled", err)
	}

	saved, loadErr := state.Load(statePath)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if saved.Stage != state.StageGenerated {
		t.Fatalf("saved stage = %q, want %q", saved.Stage, state.StageGenerated)
	}
	if saved.RunStatus != "" {
		t.Fatalf("saved RunStatus = %q, want empty", saved.RunStatus)
	}
	if len(saved.Errors) != 0 {
		t.Fatalf("saved errors = %#v, want none", saved.Errors)
	}
}

func TestBlockKeepsStageOnCommandCancelled(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "agent-state.json")
	runState := state.New("repo", "", "repo", "/source")
	runState.Stage = state.StageCloned
	agent := &Agent{State: runState, StatePath: statePath}

	err := agent.block(state.StageBuilt, errors.New("command cancelled"))
	if err == nil || err.Error() != "command cancelled" {
		t.Fatalf("block() error = %v, want command cancelled", err)
	}

	saved, loadErr := state.Load(statePath)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if saved.Stage != state.StageCloned {
		t.Fatalf("saved stage = %q, want %q", saved.Stage, state.StageCloned)
	}
	if saved.RunStatus != "" {
		t.Fatalf("saved RunStatus = %q, want empty", saved.RunStatus)
	}
	if len(saved.Errors) != 0 {
		t.Fatalf("saved errors = %#v, want none", saved.Errors)
	}
}
