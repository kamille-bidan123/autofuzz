package fuzzing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMultiFuzzStatePersistsAllDriverVersions(t *testing.T) {
	v1 := &TargetState{DriverID: 1, Seq: 1, Status: "running", CurrentSnapshot: "/tmp/d1/v001"}
	v2 := &TargetState{DriverID: 1, Seq: 2, Status: "queued", CurrentSnapshot: "/tmp/d1/v002"}
	state := &MultiFuzzState{Targets: map[int]*TargetState{1: v1}}
	state.addVersion(v1)
	state.addVersion(v2)

	path := filepath.Join(t.TempDir(), "multi-fuzzing-state.json")
	if err := state.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadMultiFuzzState(path)
	if err != nil {
		t.Fatal(err)
	}
	versions := loaded.versionStates()
	if len(versions) != 2 {
		t.Fatalf("version count = %d, want 2", len(versions))
	}
	if versions[0].Seq != 1 || versions[0].Status != "running" {
		t.Fatalf("old version was not retained: %#v", versions[0])
	}
	if versions[1].Seq != 2 || loaded.Targets[1] != versions[1] {
		t.Fatalf("latest version index is wrong: versions=%#v latest=%#v", versions, loaded.Targets[1])
	}
}

func TestLoadMultiFuzzStateImportsLegacyVersionSnapshots(t *testing.T) {
	root := t.TempDir()
	logsDir := filepath.Join(root, "logs", "fuzzing")
	statePath := filepath.Join(logsDir, "multi-fuzzing-state.json")
	latest := &TargetState{
		DriverID:        17,
		Seq:             4,
		Source:          filepath.Join(logsDir, "driver-targets", "driver-0017", "v004", "driver", "fuzz_driver_17.c"),
		CurrentSnapshot: filepath.Join(logsDir, "driver-targets", "driver-0017", "v004"),
		BinaryPath:      filepath.Join(logsDir, "driver-targets", "driver-0017", "v004", "cov_driver"),
		CorpusDir:       filepath.Join(logsDir, "driver-targets", "driver-0017", "v004", "corpus"),
		Status:          "running",
	}
	state := &MultiFuzzState{
		Version: 2,
		Mode:    "multi",
		Targets: map[int]*TargetState{17: latest},
	}
	for seq := 1; seq <= 4; seq++ {
		snapDir := filepath.Join(logsDir, "driver-targets", "driver-0017", formatVersion(seq))
		if err := os.MkdirAll(filepath.Join(snapDir, "driver"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(snapDir, "driver", "fuzz_driver_17.c"), []byte("int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned long Size) { return 0; }\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(snapDir, "build_cov_driver.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.Save(statePath); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a legacy v2 state file produced before the Versions index existed.
	data = []byte(`{"version":2,"mode":"multi","targets":{"17":` + string(mustJSON(t, latest)) + `}}`)
	if err := os.WriteFile(statePath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadMultiFuzzState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	versions := loaded.versionStates()
	if len(versions) != 4 {
		t.Fatalf("version count = %d, want 4: %#v", len(versions), versions)
	}
	for index, version := range versions {
		if version.DriverID != 17 || version.Seq != index+1 {
			t.Fatalf("unexpected version[%d]: %#v", index, version)
		}
	}
	if loaded.Targets[17].Seq != 4 || loaded.Targets[17].Status != "running" {
		t.Fatalf("latest target not preserved: %#v", loaded.Targets[17])
	}
}

func TestSchedulerQueuesDriverVersionsIndependently(t *testing.T) {
	v1 := &TargetState{DriverID: 1, Seq: 1, Status: "running"}
	v2 := &TargetState{DriverID: 1, Seq: 2, Status: "queued"}
	v3 := &TargetState{DriverID: 2, Seq: 1, Status: "queued"}
	state := &MultiFuzzState{
		Targets: map[int]*TargetState{1: v2, 2: v3},
		Versions: map[string]*TargetState{
			targetVersionKey(1, 1): v1,
			targetVersionKey(1, 2): v2,
			targetVersionKey(2, 1): v3,
		},
	}

	running, queued := schedulerVersionQueues(state)
	if len(running) != 1 || running[0] != (TargetVersionRef{DriverID: 1, Seq: 1}) {
		t.Fatalf("running versions = %#v", running)
	}
	if len(queued) != 2 ||
		queued[0] != (TargetVersionRef{DriverID: 1, Seq: 2}) ||
		queued[1] != (TargetVersionRef{DriverID: 2, Seq: 1}) {
		t.Fatalf("queued versions = %#v", queued)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
