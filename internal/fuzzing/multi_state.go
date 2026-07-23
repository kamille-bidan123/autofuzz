package fuzzing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const MultiFuzzStateVersion = 2

type MultiFuzzState struct {
	Version         int                  `json:"version"`
	Mode            string               `json:"mode"`
	Iteration       int                  `json:"iteration"`
	TargetCount     int                  `json:"target_count"`
	CurrentDriverID int                  `json:"current_driver_id,omitempty"`
	NextTargetIndex int                  `json:"next_target_index,omitempty"`
	Targets         map[int]*TargetState `json:"targets"`
	UpdatedAt       string               `json:"updated_at"`
}

type TargetState struct {
	DriverID         int                    `json:"driver_id"`
	Seq              int                    `json:"seq"`
	Source           string                 `json:"source"`
	SourceHash       string                 `json:"source_hash"`
	CurrentSnapshot  string                 `json:"current_snapshot"`
	BinaryPath       string                 `json:"binary_path"`
	CorpusDir        string                 `json:"corpus_dir"`
	Status           string                 `json:"status"`
	LastError        string                 `json:"last_error,omitempty"`
	LastLLMIteration int                    `json:"last_llm_iteration,omitempty"`
	LastCoverage     *CoverageSummaryPoint  `json:"last_coverage,omitempty"`
	CoverageHistory  []CoverageSummaryPoint `json:"coverage_history,omitempty"`
}

type CoverageSummaryPoint struct {
	Iteration         int       `json:"iteration"`
	Timestamp         time.Time `json:"timestamp"`
	ExecutedFunctions int       `json:"executed_functions"`
	FullFunctions     int       `json:"full_functions"`
	PartialFunctions  int       `json:"partial_functions"`
	UncoveredCount    int       `json:"uncovered_count"`
}

func LoadMultiFuzzState(path string) (*MultiFuzzState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var state MultiFuzzState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	if state.Targets == nil {
		state.Targets = map[int]*TargetState{}
	}
	return &state, nil
}

func (s *MultiFuzzState) Save(path string) error {
	if s.Version == 0 {
		s.Version = MultiFuzzStateVersion
	}
	if s.Mode == "" {
		s.Mode = "multi"
	}
	s.UpdatedAt = time.Now().Format(time.RFC3339)
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func targetRootDir(logsDir string, driverID int) string {
	return filepath.Join(logsDir, "driver-targets", formatDriverID(driverID))
}

func targetSnapshotDir(logsDir string, driverID, seq int) string {
	return filepath.Join(targetRootDir(logsDir, driverID), formatVersion(seq))
}

func formatDriverID(driverID int) string {
	return "driver-" + zeroPad(driverID, 4)
}

func formatVersion(seq int) string {
	return "v" + zeroPad(seq, 3)
}

func zeroPad(n, width int) string {
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if s == "" {
		s = "0"
	}
	for len(s) < width {
		s = "0" + s
	}
	return s
}
