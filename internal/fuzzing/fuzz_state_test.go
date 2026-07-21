package fuzzing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFuzzStateSaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "fuzzing-state.json") // Save must create parent dirs
	want := &FuzzState{
		Iteration:        9,
		Seq:              2,
		DriverSourceHash: "abc123",
		CurrentSnapshot:  "/path/to/fuzz-002",
		BinaryPath:       "/path/to/cov_synthesized_driver",
	}
	if err := want.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Save must be atomic — no leftover .tmp
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("leftover .tmp file: %v", err)
	}

	got, err := LoadFuzzState(path)
	if err != nil || got == nil {
		t.Fatalf("Load: %v, %v", got, err)
	}
	if got.Iteration != 9 || got.Seq != 2 || got.DriverSourceHash != "abc123" ||
		got.CurrentSnapshot != "/path/to/fuzz-002" {
		t.Fatalf("loaded state mismatch: %#v", got)
	}
	// UpdatedAt must be populated by Save.
	if got.UpdatedAt == "" {
		t.Fatal("UpdatedAt not set")
	}
}

func TestLoadFuzzStateMissing(t *testing.T) {
	// A missing or corrupt file must return (nil, nil) so the caller falls
	// back to scanning snapshots — never an error that aborts the phase.
	got, err := LoadFuzzState(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil || got != nil {
		t.Fatalf("missing file: got=%v err=%v (want nil,nil)", got, err)
	}

	dir := t.TempDir()
	corrupt := filepath.Join(dir, "state.json")
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = LoadFuzzState(corrupt)
	if err != nil || got != nil {
		t.Fatalf("corrupt file: got=%v err=%v (want nil,nil)", got, err)
	}
}

func TestDriverSourceHashOnlyTracksCompiledSources(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"1.c":       "int driver_one(void) { return 1; }\n",
		"entry.cpp": "int main() { return 0; }\n",
		"1.c.bak":   "old backup\n",
		"notes.txt": "generated notes\n",
	}
	for name, contents := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	baseline, err := driverSourceHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range map[string]string{"1.c.bak": "new backup\n", "notes.txt": "new notes\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	unchanged, err := driverSourceHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged != baseline {
		t.Fatalf("non-source files changed driver hash: before=%s after=%s", baseline, unchanged)
	}

	if err := os.WriteFile(filepath.Join(dir, "1.c"), []byte("int driver_one(void) { return 2; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := driverSourceHash(dir)
	if err != nil {
		t.Fatal(err)
	}
	if changed == baseline {
		t.Fatal("compiled source change did not change driver hash")
	}
}

func TestHighestSnapshotSeq(t *testing.T) {
	logsDir := t.TempDir()
	// no snapshots dir at all
	if n, _ := highestSnapshotSeq(logsDir); n != 0 {
		t.Fatalf("empty: got %d, want 0", n)
	}
	// create fuzz-001, fuzz-002, fuzz-007, plus a non-matching dir and a file
	snapRoot := filepath.Join(logsDir, "driver-snapshots")
	for _, n := range []int{1, 2, 7} {
		if err := os.MkdirAll(filepath.Join(snapRoot, "fuzz-"+pad3(n)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(snapRoot, "other"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapRoot, "fuzz-abc"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, _ := highestSnapshotSeq(logsDir)
	if got != 7 {
		t.Fatalf("highest seq: got %d, want 7", got)
	}
}

func pad3(n int) string {
	s := ""
	for i := 0; i < 3; i++ {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
