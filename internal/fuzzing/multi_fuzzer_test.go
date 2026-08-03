package fuzzing

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDiscoverFuzzTargetsIgnoresEntry(t *testing.T) {
	driverDir := t.TempDir()
	for name, body := range map[string]string{
		"fuzz_driver_2.c":   "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long s) { return 0; }\n",
		"fuzz_driver_1.cpp": "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long s) { return 0; }\n",
		"1.c":               "ignored old synthesized name\n",
		"entry.c":           "ignored unified dispatcher\n",
		"note.txt":          "ignored\n",
	} {
		if err := os.WriteFile(filepath.Join(driverDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	targets, err := DiscoverFuzzTargets(driverDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("targets len = %d, want 2", len(targets))
	}
	if targets[0].DriverID != 1 || targets[1].DriverID != 2 {
		t.Fatalf("targets not sorted by id: %#v", targets)
	}
	if filepath.Base(targets[0].Source) != "fuzz_driver_1.cpp" ||
		filepath.Base(targets[0].BuildScript) != "build_fuzz_driver_1.sh" {
		t.Fatalf("target 1 should use root PromeFuzz child driver artifacts: %#v", targets[0])
	}
}

func TestSplitUnifiedCorpusOnceRoutesAndStripsSelector(t *testing.T) {
	root := t.TempDir()
	driverDir := filepath.Join(root, "fuzz_driver")
	corpusDir := filepath.Join(driverDir, "corpus")
	if err := os.MkdirAll(corpusDir, 0o755); err != nil {
		t.Fatal(err)
	}
	seeds := map[string][]byte{
		"a": {0, 'x', 'y'},
		"b": {1, 'z'},
		"c": {2},
	}
	for name, data := range seeds {
		if err := os.WriteFile(filepath.Join(corpusDir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	logsDir := filepath.Join(root, "logs", "fuzzing")
	st := &MultiFuzzState{Targets: map[int]*TargetState{}}
	targets := []FuzzTarget{{DriverID: 1}, {DriverID: 2}}
	for _, target := range targets {
		corpus := filepath.Join(logsDir, "driver-targets", formatDriverID(target.DriverID), "v001", "corpus")
		if err := os.MkdirAll(corpus, 0o755); err != nil {
			t.Fatal(err)
		}
		st.Targets[target.DriverID] = &TargetState{DriverID: target.DriverID, CorpusDir: corpus}
	}

	if err := splitUnifiedCorpusOnce(FuzzConfig{DriverDir: driverDir, LogsDir: logsDir}, targets, st); err != nil {
		t.Fatal(err)
	}
	if got := readOnlySeedPayloads(t, st.Targets[1].CorpusDir); len(got) != 2 {
		t.Fatalf("driver 1 seeds = %d, want 2", len(got))
	}
	if got := readOnlySeedPayloads(t, st.Targets[2].CorpusDir); len(got) != 1 || string(got[0]) != "z" {
		t.Fatalf("driver 2 payloads = %#v, want z", got)
	}
}

func TestTargetReachedPlateauRequiresTwoFlatDeltas(t *testing.T) {
	now := time.Now()
	history := []CoverageSummaryPoint{
		{Iteration: 1, Timestamp: now, ExecutedFunctions: 10, FullFunctions: 4, PartialFunctions: 6, UncoveredCount: 12},
		{Iteration: 2, Timestamp: now, ExecutedFunctions: 10, FullFunctions: 4, PartialFunctions: 6, UncoveredCount: 12},
		{Iteration: 3, Timestamp: now, ExecutedFunctions: 10, FullFunctions: 4, PartialFunctions: 6, UncoveredCount: 12},
	}
	if !targetReachedPlateau(history) {
		t.Fatal("expected plateau after two flat deltas")
	}
	history[2].FullFunctions = 5
	if targetReachedPlateau(history) {
		t.Fatal("coverage improvement should clear plateau")
	}
}

func TestResolveMultiFuzzParallelismCapsChildDrivers(t *testing.T) {
	wantDefault := runtime.NumCPU() / 2
	if wantDefault < 1 {
		wantDefault = 1
	}
	if wantDefault > 64 {
		wantDefault = 64
	}
	if got := resolveMultiFuzzParallelism(FuzzConfig{}, 64); got != wantDefault {
		t.Fatalf("default parallelism = %d, want min(max(1, nproc/2), target count) = %d", got, wantDefault)
	}
	if got := resolveMultiFuzzParallelism(FuzzConfig{MaxParallelDrivers: 4}, 64); got != 4 {
		t.Fatalf("parallelism = %d, want 4", got)
	}
	if got := resolveMultiFuzzParallelism(FuzzConfig{MaxParallelDrivers: 200}, 64); got != 64 {
		t.Fatalf("parallelism = %d, want total target count", got)
	}
	if got := resolveMultiFuzzParallelism(FuzzConfig{MaxParallelDrivers: 1}, 64); got != 1 {
		t.Fatalf("parallelism = %d, want 1", got)
	}
}

func TestBuildMultiCoverageSnapshotIncludesQueuedTargets(t *testing.T) {
	st := &MultiFuzzState{Iteration: 9, NextTargetIndex: 1, Targets: map[int]*TargetState{
		1: {DriverID: 1, Seq: 1, Status: "running", CorpusDir: "/tmp/d1"},
		2: {DriverID: 2, Seq: 1, Status: "queued", CorpusDir: "/tmp/d2", LastCoverage: &CoverageSummaryPoint{ExecutedFunctions: 3, FullFunctions: 1, PartialFunctions: 2, UncoveredCount: 5}},
	}}
	data := []targetCycleData{{
		state: st.Targets[1],
		cache: CoverageSnapshot{Available: true, SeedCount: 7, Coverage: CoverageStatus{Summary: CoverageSummary{
			ExecutedFunctions: 2,
			FullFunctions:     1,
			PartialFunctions:  1,
		}}},
		coverage: CorpusCoverageStatus{Summary: CoverageSummary{ExecutedFunctions: 2, FullFunctions: 1, PartialFunctions: 1}},
	}}
	nextAnalysisAt := time.Now().Add(5 * time.Minute)
	snapshot := buildMultiCoverageSnapshot(data, st, 1, 30*time.Minute, nextAnalysisAt)
	if snapshot.ActiveTargets != 1 || snapshot.MaxParallelTargets != 1 || len(snapshot.Targets) != 2 {
		t.Fatalf("unexpected snapshot shape: %#v", snapshot)
	}
	if snapshot.Iteration != 9 || len(snapshot.RunningTargets) != 1 || snapshot.RunningTargets[0] != 1 ||
		len(snapshot.QueuedTargets) != 1 || snapshot.QueuedTargets[0] != 2 ||
		len(snapshot.NextTargets) != 1 || snapshot.NextTargets[0] != 2 {
		t.Fatalf("scheduler fields missing from snapshot: %#v", snapshot)
	}
	if len(snapshot.RunningVersions) != 1 || snapshot.RunningVersions[0].DriverID != 1 || snapshot.RunningVersions[0].Seq != 1 ||
		len(snapshot.QueuedVersions) != 1 || snapshot.QueuedVersions[0].DriverID != 2 || snapshot.QueuedVersions[0].Seq != 1 ||
		len(snapshot.NextVersions) != 1 || snapshot.NextVersions[0].DriverID != 2 || snapshot.NextVersions[0].Seq != 1 {
		t.Fatalf("version scheduler fields missing from snapshot: %#v", snapshot)
	}
	if snapshot.Targets[1].DriverID != 2 || snapshot.Targets[1].Status != "queued" || snapshot.Targets[1].Summary.ExecutedFunctions != 3 {
		t.Fatalf("queued target not preserved in snapshot: %#v", snapshot.Targets)
	}
	if snapshot.NextAnalysisAt == nil || snapshot.FuzzIntervalSeconds != int64((30*time.Minute)/time.Second) || snapshot.AnalysisRemainingSeconds <= 0 {
		t.Fatalf("analysis countdown fields missing from snapshot: %#v", snapshot)
	}
}

func TestBuildMultiCoverageSnapshotKeepsMultipleVersionsPerDriver(t *testing.T) {
	v1 := &TargetState{DriverID: 1, Seq: 1, Status: "running", CorpusDir: "/tmp/d1-v1"}
	v2 := &TargetState{DriverID: 1, Seq: 2, Status: "queued", CorpusDir: "/tmp/d1-v2"}
	st := &MultiFuzzState{
		Iteration:       4,
		NextTargetIndex: 1,
		Targets:         map[int]*TargetState{1: v2},
		Versions: map[string]*TargetState{
			targetVersionKey(1, 1): v1,
			targetVersionKey(1, 2): v2,
		},
	}
	data := []targetCycleData{{
		state: v1,
		cache: CoverageSnapshot{Available: true, SeedCount: 1, Coverage: CoverageStatus{Summary: CoverageSummary{
			ExecutedFunctions: 1,
			FullFunctions:     1,
		}}},
		coverage: CorpusCoverageStatus{Summary: CoverageSummary{ExecutedFunctions: 1, FullFunctions: 1}},
	}}

	snapshot := buildMultiCoverageSnapshot(data, st, 1, 30*time.Minute, time.Now().Add(time.Minute))
	if len(snapshot.Targets) != 2 || snapshot.Targets[0].Seq != 1 || snapshot.Targets[1].Seq != 2 {
		t.Fatalf("snapshot should include both driver versions: %#v", snapshot.Targets)
	}
	if len(snapshot.RunningVersions) != 1 || snapshot.RunningVersions[0] != (TargetVersionRef{DriverID: 1, Seq: 1}) {
		t.Fatalf("running versions = %#v, want d1/v1", snapshot.RunningVersions)
	}
	if len(snapshot.NextVersions) != 1 || snapshot.NextVersions[0] != (TargetVersionRef{DriverID: 1, Seq: 2}) {
		t.Fatalf("next versions = %#v, want d1/v2", snapshot.NextVersions)
	}
}

func TestEnsureInitialTargetSnapshotsKeepsVersionSnapshot(t *testing.T) {
	root := t.TempDir()
	driverDir := filepath.Join(root, "fuzz_driver")
	logsDir := filepath.Join(root, "logs", "fuzzing")
	if err := os.MkdirAll(driverDir, 0o755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(driverDir, "fuzz_driver_1.c")
	if err := os.WriteFile(source, []byte("int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long s) { return 0; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	buildScript := filepath.Join(driverDir, "build_fuzz_driver_1.sh")
	if err := os.WriteFile(buildScript, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	snapDir := targetSnapshotDir(logsDir, 1, 2)
	if err := os.MkdirAll(filepath.Join(snapDir, "driver"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(snapDir, "corpus"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapDir, "driver", "fuzz_driver_1.c"), []byte("optimized\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapDir, "build_cov_driver.sh"), []byte("#!/bin/sh\nclang wrapper.c -o cov_driver\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(snapDir, "cov_driver")
	if err := os.WriteFile(binaryPath, []byte("binary\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	state := &TargetState{DriverID: 1, Seq: 2, CurrentSnapshot: snapDir, BinaryPath: binaryPath, CorpusDir: filepath.Join(snapDir, "corpus"), Status: "running", LastLLMIteration: 7}
	st := &MultiFuzzState{
		Version: MultiFuzzStateVersion,
		Targets: map[int]*TargetState{
			1: state,
		},
		Versions: map[string]*TargetState{
			targetVersionKey(1, 2): state,
		},
	}

	err := ensureInitialTargetSnapshots(context.Background(), FuzzConfig{DriverDir: driverDir, BuildScript: filepath.Join(driverDir, "build_cov_synthesized_driver.sh"), LogsDir: logsDir}, st, []FuzzTarget{{DriverID: 1, Source: source, BuildScript: buildScript}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Targets[1].Seq != 2 || st.Targets[1].CurrentSnapshot != snapDir || st.Targets[1].Status != "ready" {
		t.Fatalf("version snapshot was not preserved: %#v", st.Targets[1])
	}
	if _, err := os.Stat(targetSnapshotDir(logsDir, 1, 1)); !os.IsNotExist(err) {
		t.Fatalf("initial snapshot v1 should not have been rebuilt, stat err = %v", err)
	}
}

func TestBuildMultiCoverageSnapshotClonesBranchCounts(t *testing.T) {
	branch := ub([2]int{12, 4}, "x==1")
	coverage := coverageWith(nil, partialSpec{"f", "x.c", []UncoveredBranch{branch}})
	st := &MultiFuzzState{Iteration: 1, Targets: map[int]*TargetState{
		1: {DriverID: 1, Seq: 1, Status: "running", CorpusDir: "/tmp/d1"},
	}}
	data := []targetCycleData{{
		state:    st.Targets[1],
		cache:    CoverageSnapshot{Available: true, SeedCount: 1, Coverage: coverage},
		coverage: CoverageStatusToCorpusCoverage(coverage, 1, false, "/tmp/d1"),
	}}
	snapshot := buildMultiCoverageSnapshot(data, st, 1, 30*time.Minute, time.Now().Add(time.Minute))
	snapshot.Targets[0].Coverage.Partial[0].UncoveredBranches[0].Counts["false"] = 9
	snapshot.Coverage.Partial[0].UncoveredBranches[0].Counts["false"] = 11
	if coverage.Partial[0].UncoveredBranches[0].Counts["false"] != 1 {
		t.Fatalf("multi coverage snapshot aliased source counts: %#v", coverage.Partial[0].UncoveredBranches[0].Counts)
	}
}

func TestCollectMultiLiveDataPreservesLastSummary(t *testing.T) {
	state := &TargetState{
		DriverID:  1,
		Seq:       1,
		Status:    "running",
		CorpusDir: t.TempDir(),
		LastCoverage: &CoverageSummaryPoint{
			ExecutedFunctions: 9,
			FullFunctions:     4,
			PartialFunctions:  5,
		},
	}
	data := collectMultiLiveData(map[targetRuntimeKey]*runningTarget{
		runtimeKey(state): {state: state, tracker: NewFuzzStatusTracker()},
	}, 2)
	if len(data) != 1 {
		t.Fatalf("live data length = %d, want 1", len(data))
	}
	if data[0].coverage.Summary.ExecutedFunctions != 9 {
		t.Fatalf("executed summary = %d, want preserved value 9", data[0].coverage.Summary.ExecutedFunctions)
	}
}

func TestSortedRunningTargetKeysOrdersByDriverThenSeq(t *testing.T) {
	running := map[targetRuntimeKey]*runningTarget{
		{driverID: 3, seq: 1}: {state: &TargetState{DriverID: 3, Seq: 1}},
		{driverID: 1, seq: 2}: {state: &TargetState{DriverID: 1, Seq: 2}},
		{driverID: 1, seq: 1}: {state: &TargetState{DriverID: 1, Seq: 1}},
		{driverID: 2, seq: 4}: {state: &TargetState{DriverID: 2, Seq: 4}},
	}

	got := sortedRunningTargetKeys(running)
	want := []targetRuntimeKey{
		{driverID: 1, seq: 1},
		{driverID: 1, seq: 2},
		{driverID: 2, seq: 4},
		{driverID: 3, seq: 1},
	}
	if len(got) != len(want) {
		t.Fatalf("len(sortedRunningTargetKeys) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sortedRunningTargetKeys()[%d] = %#v, want %#v", i, got[i], want[i])
		}
	}
}

func TestWriteTargetBuildScriptRewritesChildSourceAndOutput(t *testing.T) {
	root := t.TempDir()
	driverDir := filepath.Join(root, "fuzz_driver")
	if err := os.MkdirAll(driverDir, 0o755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(driverDir, "fuzz_driver_7.c")
	if err := os.WriteFile(source, []byte("int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long s) { return 0; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	template := filepath.Join(driverDir, "build_fuzz_driver_7.sh")
	templateBody := "#!/bin/sh\nclang " + source +
		" -o " + filepath.Join(driverDir, "fuzz_driver_7") + " -fsanitize=fuzzer -lm\n"
	if err := os.WriteFile(template, []byte(templateBody), 0o755); err != nil {
		t.Fatal(err)
	}
	target := FuzzTarget{DriverID: 7, Source: source, BuildScript: template}
	snapDir := filepath.Join(root, "snap")
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := writeTargetBuildScript(driverDir, filepath.Join(driverDir, "build_cov_synthesized_driver.sh"), target, snapDir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(snapDir, "build_cov_driver.sh"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, want := range []string{
		filepath.Join(snapDir, "driver", "fuzz_driver_7.c"),
		filepath.Join(snapDir, "cov_driver"),
		"-fprofile-instr-generate",
		"-fcoverage-mapping",
		"-fsanitize=fuzzer,address",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("rewritten build script missing %q:\n%s", want, content)
		}
	}
	for _, old := range []string{source, filepath.Join(driverDir, "fuzz_driver_7"), "cov_synthesized_driver", "*.c", "wrapper.c"} {
		if strings.Contains(content, old) {
			t.Fatalf("rewritten build script still contains old artifact %q:\n%s", old, content)
		}
	}
}

func TestTargetSnapshotUsesRootDriverRejectsLegacySynthesized(t *testing.T) {
	root := t.TempDir()
	target := FuzzTarget{DriverID: 7, Source: filepath.Join(root, "fuzz_driver", "fuzz_driver_7.c")}
	snapDir := filepath.Join(root, "snap")
	if err := os.MkdirAll(filepath.Join(snapDir, "driver"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapDir, "driver", "fuzz_driver_7.c"), []byte("int x;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	buildScript := filepath.Join(snapDir, "build_cov_driver.sh")
	rootScript := "#!/bin/sh\nclang " + filepath.Join(snapDir, "driver", "fuzz_driver_7.c") + " -o " + filepath.Join(snapDir, "cov_driver") + "\n"
	if err := os.WriteFile(buildScript, []byte(rootScript), 0o755); err != nil {
		t.Fatal(err)
	}
	if !targetSnapshotUsesRootDriver(snapDir, target) {
		t.Fatal("root child driver snapshot should be accepted")
	}
	legacyScript := "#!/bin/sh\nclang " + filepath.Join(snapDir, "synthesized", "*.c") + " wrapper.c -o " + filepath.Join(snapDir, "cov_driver") + "\n"
	if err := os.WriteFile(buildScript, []byte(legacyScript), 0o755); err != nil {
		t.Fatal(err)
	}
	if targetSnapshotUsesRootDriver(snapDir, target) {
		t.Fatal("legacy synthesized/wrapper snapshot should be rejected")
	}
}

func readOnlySeedPayloads(t *testing.T, dir string) [][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, data)
	}
	return out
}
