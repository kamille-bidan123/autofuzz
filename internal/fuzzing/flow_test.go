package fuzzing

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFuzzFlowSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "fuzz-flow.json")
	started := time.Now().Add(-time.Second).Round(0)
	want := &FuzzFlowSnapshot{
		Iteration: 4, DriverSeq: 2, Phase: FuzzFlowAnalyzing,
		Status: "running", Trigger: "manual", Message: "Codex 正在分析",
		CycleStarted: &started,
		LastResult: &FuzzFlowResult{
			Iteration: 3, DriverSeq: 2, Trigger: "interval",
			StartedAt: started.Add(-time.Minute), FinishedAt: started,
			PlateauReached: true, NeedsUpdate: true, Regenerated: true,
		},
	}
	if err := want.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFuzzFlow(path)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Phase != FuzzFlowAnalyzing || got.Trigger != "manual" || got.LastResult == nil || !got.LastResult.Regenerated {
		t.Fatalf("unexpected restored flow: %#v", got)
	}
}

func TestLoadMissingFuzzFlow(t *testing.T) {
	got, err := LoadFuzzFlow(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil || got != nil {
		t.Fatalf("got (%#v, %v), want (nil, nil)", got, err)
	}
}
