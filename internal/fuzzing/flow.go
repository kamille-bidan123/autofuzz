package fuzzing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// FuzzFlowPhase describes the currently visible step in the repeating
// fuzz/analyze/rebuild loop. It is persisted independently from the main run
// stage so the web UI can restore the last activity after a restart.
type FuzzFlowPhase string

const (
	FuzzFlowStarting   FuzzFlowPhase = "starting"
	FuzzFlowFuzzing    FuzzFlowPhase = "fuzzing"
	FuzzFlowCollecting FuzzFlowPhase = "collecting"
	FuzzFlowAnalyzing  FuzzFlowPhase = "analyzing"
	FuzzFlowApplying   FuzzFlowPhase = "applying"
	FuzzFlowRebuilding FuzzFlowPhase = "rebuilding"
)

type FuzzFlowResult struct {
	Iteration      int       `json:"iteration"`
	DriverSeq      int       `json:"driver_seq"`
	Trigger        string    `json:"trigger,omitempty"`
	StartedAt      time.Time `json:"started_at"`
	FinishedAt     time.Time `json:"finished_at"`
	PlateauReached bool      `json:"plateau_reached"`
	NeedsUpdate    bool      `json:"needs_update"`
	Regenerated    bool      `json:"regenerated"`
	Analysis       string    `json:"analysis,omitempty"`
	Error          string    `json:"error,omitempty"`
}

type FuzzFlowSnapshot struct {
	Iteration    int             `json:"iteration"`
	DriverSeq    int             `json:"driver_seq"`
	Phase        FuzzFlowPhase   `json:"phase"`
	Status       string          `json:"status"`
	Trigger      string          `json:"trigger,omitempty"`
	Message      string          `json:"message"`
	CycleStarted *time.Time      `json:"cycle_started_at,omitempty"`
	UpdatedAt    time.Time       `json:"updated_at"`
	LastResult   *FuzzFlowResult `json:"last_result,omitempty"`
}

func LoadFuzzFlow(path string) (*FuzzFlowSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var snapshot FuzzFlowSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

func (s *FuzzFlowSnapshot) Save(path string) error {
	s.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
