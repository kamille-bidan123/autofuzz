package fuzzing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const MultiFuzzStateVersion = 3

type MultiFuzzState struct {
	Version          int                     `json:"version"`
	Mode             string                  `json:"mode"`
	Iteration        int                     `json:"iteration"`
	TargetCount      int                     `json:"target_count"`
	CurrentDriverID  int                     `json:"current_driver_id,omitempty"`
	CurrentDriverSeq int                     `json:"current_driver_seq,omitempty"`
	NextTargetIndex  int                     `json:"next_target_index,omitempty"`
	Targets          map[int]*TargetState    `json:"targets"`
	Versions         map[string]*TargetState `json:"versions,omitempty"`
	UpdatedAt        string                  `json:"updated_at"`
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
	state.ensureVersionIndex()
	state.importVersionSnapshots(filepath.Dir(path))
	return &state, nil
}

func (s *MultiFuzzState) Save(path string) error {
	s.Version = MultiFuzzStateVersion
	if s.Mode == "" {
		s.Mode = "multi"
	}
	s.ensureVersionIndex()
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

func targetVersionKey(driverID, seq int) string {
	return formatDriverID(driverID) + "-" + formatVersion(seq)
}

func (s *MultiFuzzState) ensureVersionIndex() {
	if s.Targets == nil {
		s.Targets = map[int]*TargetState{}
	}
	if s.Versions == nil {
		s.Versions = map[string]*TargetState{}
	}
	for driverID, state := range s.Targets {
		if state == nil {
			continue
		}
		if state.DriverID == 0 {
			state.DriverID = driverID
		}
		if state.Seq <= 0 {
			state.Seq = 1
		}
		s.Versions[targetVersionKey(state.DriverID, state.Seq)] = state
	}
	for _, state := range s.Versions {
		if state == nil || state.DriverID <= 0 {
			continue
		}
		if state.Seq <= 0 {
			state.Seq = 1
		}
		latest := s.Targets[state.DriverID]
		if latest == nil || state.Seq > latest.Seq {
			s.Targets[state.DriverID] = state
		}
	}
}

func (s *MultiFuzzState) addVersion(state *TargetState) {
	if state == nil || state.DriverID <= 0 || state.Seq <= 0 {
		return
	}
	s.ensureVersionIndex()
	s.Versions[targetVersionKey(state.DriverID, state.Seq)] = state
	latest := s.Targets[state.DriverID]
	if latest == nil || state.Seq >= latest.Seq {
		s.Targets[state.DriverID] = state
	}
}

func (s *MultiFuzzState) versionStates() []*TargetState {
	s.ensureVersionIndex()
	states := make([]*TargetState, 0, len(s.Versions))
	for _, state := range s.Versions {
		if state != nil && state.DriverID > 0 && state.Seq > 0 {
			states = append(states, state)
		}
	}
	sort.Slice(states, func(i, j int) bool {
		if states[i].DriverID != states[j].DriverID {
			return states[i].DriverID < states[j].DriverID
		}
		return states[i].Seq < states[j].Seq
	})
	return states
}

func (s *MultiFuzzState) importVersionSnapshots(logsDir string) {
	if logsDir == "" {
		return
	}
	s.ensureVersionIndex()
	targetsRoot := filepath.Join(logsDir, "driver-targets")
	drivers, err := os.ReadDir(targetsRoot)
	if err != nil {
		return
	}
	for _, driver := range drivers {
		if !driver.IsDir() {
			continue
		}
		driverID := parseDriverDirName(driver.Name())
		if driverID <= 0 {
			continue
		}
		driverRoot := filepath.Join(targetsRoot, driver.Name())
		versions, err := os.ReadDir(driverRoot)
		if err != nil {
			continue
		}
		for _, version := range versions {
			if !version.IsDir() {
				continue
			}
			seq := parseVersionDirName(version.Name())
			if seq <= 0 {
				continue
			}
			key := targetVersionKey(driverID, seq)
			if _, exists := s.Versions[key]; exists {
				continue
			}
			snapDir := filepath.Join(driverRoot, version.Name())
			source := targetSnapshotSource(snapDir, driverID)
			if source == "" || !fileExists(filepath.Join(snapDir, "build_cov_driver.sh")) {
				continue
			}
			targetState := &TargetState{
				DriverID:        driverID,
				Seq:             seq,
				Source:          source,
				CurrentSnapshot: snapDir,
				BinaryPath:      filepath.Join(snapDir, "cov_driver"),
				CorpusDir:       filepath.Join(snapDir, "corpus"),
				Status:          "queued",
			}
			if hash, err := driverSourceHash(filepath.Join(snapDir, "driver")); err == nil {
				targetState.SourceHash = hash
			}
			s.addVersion(targetState)
		}
	}
}

func parseDriverDirName(name string) int {
	if !strings.HasPrefix(name, "driver-") {
		return 0
	}
	id, err := strconv.Atoi(strings.TrimPrefix(name, "driver-"))
	if err != nil {
		return 0
	}
	return id
}

func parseVersionDirName(name string) int {
	if !strings.HasPrefix(name, "v") {
		return 0
	}
	seq, err := strconv.Atoi(strings.TrimPrefix(name, "v"))
	if err != nil {
		return 0
	}
	return seq
}

func targetSnapshotSource(snapDir string, driverID int) string {
	for _, ext := range []string{".c", ".cc", ".cpp", ".cxx"} {
		path := filepath.Join(snapDir, "driver", "fuzz_driver_"+strconv.Itoa(driverID)+ext)
		if fileExists(path) {
			return path
		}
	}
	matches, _ := filepath.Glob(filepath.Join(snapDir, "driver", "fuzz_driver_*"))
	sort.Strings(matches)
	for _, path := range matches {
		if info, err := os.Stat(path); err == nil && !info.IsDir() && isCompiledDriverSource(filepath.Base(path)) {
			return path
		}
	}
	return ""
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
