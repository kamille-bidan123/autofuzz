package fuzzing

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"autofuzz/internal/repository"
)

// FuzzState is the resumable fuzzing-phase checkpoint, persisted to
// logs/fuzzing/fuzzing-state.json. It records the analysis iteration counter,
// the current driver version (seq), the source fingerprint of the currently
// built binary, and which snapshot holds that binary. On resume this lets the
// phase decide whether to reuse the existing binary (source unchanged) or
// build a new snapshot (source changed), instead of always restarting from
// scratch and contaminating the previous snapshot.
type FuzzState struct {
	Iteration        int    `json:"iteration"`
	Seq              int    `json:"seq"`
	DriverSourceHash string `json:"driver_source_hash"`
	CurrentSnapshot  string `json:"current_snapshot"`
	BinaryPath       string `json:"binary_path"`
	UpdatedAt        string `json:"updated_at"`
}

// LoadFuzzState reads the fuzzing checkpoint. It returns (nil, nil) when the
// file is missing or unreadable/corrupt so the caller falls back to scanning
// existing snapshots; only a successfully parsed state is returned non-nil.
func LoadFuzzState(path string) (*FuzzState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil // missing or unreadable -> fall back to scan
	}
	var s FuzzState
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, nil // corrupt -> fall back to scan
	}
	return &s, nil
}

// Save writes the checkpoint atomically (tmp + rename) so a crash mid-write
// never leaves a half-written state file.
func (s *FuzzState) Save(path string) error {
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

// driverSourceHash returns a content fingerprint of the synthesized driver
// sources (the .c files the binary is built from). It is used to detect
// whether the live driver source has changed since the last build, so resume
// can reuse the existing binary when nothing changed and build a new snapshot
// only when it did.
func driverSourceHash(synthesizedDir string) (string, error) {
	return repository.TreeHash(synthesizedDir)
}

// highestSnapshotSeq scans logs/driver-snapshots/fuzz-NNN/ and returns the
// highest N found (0 if none). Used as a fallback when no fuzzing-state.json
// exists, to resume the seq counter from a prior run's snapshots.
func highestSnapshotSeq(logsDir string) (int, error) {
	root := filepath.Join(logsDir, "driver-snapshots")
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	highest := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "fuzz-") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(name, "fuzz-"))
		if err != nil || n <= 0 {
			continue
		}
		if n > highest {
			highest = n
		}
	}
	return highest, nil
}

// snapshotDirPath returns the snapshot directory path for a given seq.
func snapshotDirPath(logsDir string, seq int) string {
	return filepath.Join(logsDir, "driver-snapshots", fmt.Sprintf("fuzz-%03d", seq))
}
