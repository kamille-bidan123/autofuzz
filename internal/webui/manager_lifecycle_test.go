package webui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"autofuzz/internal/agent"
	"autofuzz/internal/fuzzing"
	"autofuzz/internal/state"
)

func TestCreatePersistsPendingTaskWithoutStarting(t *testing.T) {
	request := lifecycleTestRequest(t)
	manager := NewManager(context.Background())

	snapshot, err := manager.Create(request)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Status != "pending" {
		t.Fatalf("status = %q, want pending", snapshot.Status)
	}
	if _, err := os.Stat(snapshot.StatePath); !os.IsNotExist(err) {
		t.Fatalf("state file exists before start: %v", err)
	}
	if _, exists := manager.Get(snapshot.ID); exists {
		t.Fatal("pending task unexpectedly exists in the active task map")
	}
	entries := readTaskRegistry()
	if len(entries) != 1 || entries[0].Request.RepositoryURL != request.RepositoryURL {
		t.Fatalf("unexpected registry: %#v", entries)
	}
}

func TestTaskCanStopAndResumeWithSameID(t *testing.T) {
	request := lifecycleTestRequest(t)
	manager := NewManager(context.Background())
	started := make(chan struct{}, 2)
	manager.runAgent = func(runContext context.Context, autoAgent *agent.Agent) error {
		if err := os.MkdirAll(autoAgent.TargetDir, 0o755); err != nil {
			return err
		}
		if err := autoAgent.State.Save(autoAgent.StatePath); err != nil {
			return err
		}
		started <- struct{}{}
		<-runContext.Done()
		return runContext.Err()
	}

	pending, err := manager.Create(request)
	if err != nil {
		t.Fatal(err)
	}
	task, err := manager.StartTask(pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if task.Snapshot().Status != "running" {
		t.Fatalf("status = %q, want running", task.Snapshot().Status)
	}
	if err := manager.Cancel(pending.ID); err != nil {
		t.Fatal(err)
	}
	waitForTaskStatus(t, task, "stopped")

	resumed, err := manager.StartTask(pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	resumedSnapshot := resumed.Snapshot()
	if resumedSnapshot.ID != pending.ID || !resumedSnapshot.Request.Resume {
		t.Fatalf("unexpected resumed snapshot: %#v", resumedSnapshot)
	}
	if err := manager.Cancel(pending.ID); err != nil {
		t.Fatal(err)
	}
	waitForTaskStatus(t, resumed, "stopped")
}

func TestPersistedRunningTaskAppearsInterruptedAfterRestart(t *testing.T) {
	request := lifecycleTestRequest(t)
	manager := NewManager(context.Background())
	started := make(chan struct{}, 1)
	manager.runAgent = func(runContext context.Context, autoAgent *agent.Agent) error {
		if err := os.MkdirAll(autoAgent.TargetDir, 0o755); err != nil {
			return err
		}
		if err := autoAgent.State.Save(autoAgent.StatePath); err != nil {
			return err
		}
		started <- struct{}{}
		<-runContext.Done()
		return runContext.Err()
	}
	pending, err := manager.Create(request)
	if err != nil {
		t.Fatal(err)
	}
	task, err := manager.StartTask(pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	<-started

	restartedManager := NewManager(context.Background())
	tasks := restartedManager.List()
	if len(tasks) != 1 || tasks[0].Status != "interrupted" {
		t.Fatalf("unexpected restarted task list: %#v", tasks)
	}

	if err := manager.Cancel(pending.ID); err != nil {
		t.Fatal(err)
	}
	waitForTaskStatus(t, task, "stopped")
}

func TestFuzzFlowDataRestoresAfterManagerRestart(t *testing.T) {
	request := lifecycleTestRequest(t)
	manager := NewManager(context.Background())
	pending, err := manager.Create(request)
	if err != nil {
		t.Fatal(err)
	}
	flowPath := filepath.Join(pending.TargetDir, "logs", "fuzzing", "fuzz-flow.json")
	want := &fuzzing.FuzzFlowSnapshot{
		Iteration: 5, DriverSeq: 2, Phase: fuzzing.FuzzFlowApplying,
		Status: "running", Trigger: "interval", Message: "正在校验分析结果",
	}
	if err := want.Save(flowPath); err != nil {
		t.Fatal(err)
	}

	restarted := NewManager(context.Background())
	got := restarted.FuzzFlowData(pending.ID, 50)
	if got.Current == nil || got.Current.Iteration != want.Iteration || got.Current.Phase != want.Phase {
		t.Fatalf("unexpected restored fuzz flow: %#v", got.Current)
	}
}

func TestFailedTaskCanResumeWithSameID(t *testing.T) {
	request := lifecycleTestRequest(t)
	manager := NewManager(context.Background())
	runError := errors.New("build failed")
	manager.runAgent = func(_ context.Context, autoAgent *agent.Agent) error {
		autoAgent.State.Stage = state.StageFailed
		autoAgent.State.RecordError(state.StageCloned, runError)
		if err := autoAgent.State.Save(autoAgent.StatePath); err != nil {
			return err
		}
		return runError
	}

	pending, err := manager.Create(request)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := manager.StartTask(pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	waitForTaskStatus(t, failed, "failed")
	waitForRegistryStatus(t, pending.ID, "failed")

	started := make(chan struct{}, 1)
	manager.runAgent = func(runContext context.Context, _ *agent.Agent) error {
		started <- struct{}{}
		<-runContext.Done()
		return runContext.Err()
	}
	resumed, err := manager.StartTask(pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	if snapshot := resumed.Snapshot(); snapshot.ID != pending.ID || !snapshot.Request.Resume {
		t.Fatalf("unexpected resumed task: %#v", snapshot)
	}
	if err := manager.Cancel(pending.ID); err != nil {
		t.Fatal(err)
	}
	waitForTaskStatus(t, resumed, "stopped")
}

func TestCreateAndStartHTTPRoutesAreSeparate(t *testing.T) {
	request := lifecycleTestRequest(t)
	manager := NewManager(context.Background())
	manager.runAgent = func(runContext context.Context, _ *agent.Agent) error {
		<-runContext.Done()
		return runContext.Err()
	}
	server := NewServer(manager)
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}

	createRequest := httptest.NewRequest(http.MethodPost, "/api/runs", strings.NewReader(string(body)))
	createResponse := httptest.NewRecorder()
	server.ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", createResponse.Code, createResponse.Body.String())
	}
	var pending TaskSnapshot
	if err := json.Unmarshal(createResponse.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}
	if pending.Status != "pending" {
		t.Fatalf("create status = %q, want pending", pending.Status)
	}

	startRequest := httptest.NewRequest(http.MethodPost, "/api/runs/"+pending.ID+"/start", nil)
	startResponse := httptest.NewRecorder()
	server.ServeHTTP(startResponse, startRequest)
	if startResponse.Code != http.StatusAccepted {
		t.Fatalf("start status = %d, body = %s", startResponse.Code, startResponse.Body.String())
	}
	if err := manager.Cancel(pending.ID); err != nil {
		t.Fatal(err)
	}
	task, _ := manager.Get(pending.ID)
	waitForTaskStatus(t, task, "stopped")
}

func TestDriverDiffComparesPreviousVersion(t *testing.T) {
	request := lifecycleTestRequest(t)
	manager := NewManager(context.Background())
	pending, err := manager.Create(request)
	if err != nil {
		t.Fatal(err)
	}
	baseDir := filepath.Join(pending.TargetDir, "logs", "fuzzing", "driver-snapshots", "fuzz-001", "synthesized")
	targetDir := filepath.Join(pending.TargetDir, "logs", "fuzzing", "driver-snapshots", "fuzz-002", "synthesized")
	for _, directory := range []string{baseDir, targetDir} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		filepath.Join(baseDir, "1.c"):       "int value = 1;\n",
		filepath.Join(baseDir, "entry.c"):   "int entry(void) { return 0; }\n",
		filepath.Join(targetDir, "1.c"):     "int value = 2;\n",
		filepath.Join(targetDir, "entry.c"): "int entry(void) { return 0; }\n",
		filepath.Join(targetDir, "2.c"):     "int added = 1;\n",
	}
	for path, contents := range files {
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	result, err := manager.DriverDiff(pending.ID, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if result.BaseSeq != 1 || result.TargetSeq != 2 {
		t.Fatalf("unexpected versions: %#v", result)
	}
	for _, expected := range []string{"v1/1.c", "v2/1.c", "-int value = 1;", "+int value = 2;", "v2/2.c"} {
		if !strings.Contains(result.Diff, expected) {
			t.Fatalf("diff is missing %q:\n%s", expected, result.Diff)
		}
	}
	if _, err := manager.DriverDiff(pending.ID, 0, 1); err == nil {
		t.Fatal("v1 unexpectedly has a previous version")
	}

	multiBase := filepath.Join(pending.TargetDir, "logs", "fuzzing", "driver-targets", "driver-0007", "v001", "driver")
	multiTarget := filepath.Join(pending.TargetDir, "logs", "fuzzing", "driver-targets", "driver-0007", "v002", "driver")
	for _, directory := range []string{multiBase, multiTarget} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(multiBase, "fuzz_driver_7.c"), []byte("int value = 7;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(multiTarget, "fuzz_driver_7.c"), []byte("int value = 8;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	multiResult, err := manager.DriverDiff(pending.ID, 7, 2)
	if err != nil {
		t.Fatal(err)
	}
	if multiResult.DriverID != 7 || !strings.Contains(multiResult.Diff, "+int value = 8;") {
		t.Fatalf("unexpected multi diff result: %#v\n%s", multiResult, multiResult.Diff)
	}

	requestHTTP := httptest.NewRequest(http.MethodGet, "/api/runs/"+pending.ID+"/snapshots/2/diff", nil)
	responseHTTP := httptest.NewRecorder()
	NewServer(manager).ServeHTTP(responseHTTP, requestHTTP)
	if responseHTTP.Code != http.StatusOK {
		t.Fatalf("diff endpoint status = %d, body = %s", responseHTTP.Code, responseHTTP.Body.String())
	}
	var endpointResult DriverDiffResponse
	if err := json.Unmarshal(responseHTTP.Body.Bytes(), &endpointResult); err != nil {
		t.Fatal(err)
	}
	if endpointResult.BaseSeq != 1 || endpointResult.TargetSeq != 2 {
		t.Fatalf("unexpected endpoint response: %#v", endpointResult)
	}
}

func TestCreateCrashFixTaskRejectsIneligibleCrash(t *testing.T) {
	request := lifecycleTestRequest(t)
	manager := NewManager(context.Background())
	pending, err := manager.Create(request)
	if err != nil {
		t.Fatal(err)
	}
	setupCrashFixParent(t, pending, fuzzing.CrashAnalysisEntry{
		File:           "leak-abc",
		Type:           "leak",
		ASanReport:     "SUMMARY: LeakSanitizer: detected memory leaks",
		ReportStatus:   "completed",
		Classification: "library_bug",
		ReportPath:     "crash-reports/leak-abc.json",
	})

	_, err = manager.CreateCrashFixTask(pending.ID, CrashFixTaskRequest{
		DriverID: 9,
		Seq:      1,
		Crashes:  []string{"leak-abc"},
	})
	if err == nil || !strings.Contains(err.Error(), "not an OOB crash") {
		t.Fatalf("CreateCrashFixTask error = %v, want not OOB rejection", err)
	}
}

func TestCreateCrashFixTaskCreatesAndStartsChildTask(t *testing.T) {
	request := lifecycleTestRequest(t)
	manager := NewManager(context.Background())
	pending, err := manager.Create(request)
	if err != nil {
		t.Fatal(err)
	}
	fixture := setupCrashFixParent(t, pending, fuzzing.CrashAnalysisEntry{
		File:           "crash-oob",
		Type:           "heap-buffer-overflow",
		ASanReport:     "SUMMARY: AddressSanitizer: heap-buffer-overflow",
		ReportStatus:   "completed",
		Classification: "library_bug",
		ReportPath:     "crash-reports/crash-oob.json",
	})

	started := make(chan *agent.Agent, 1)
	manager.runAgent = func(_ context.Context, autoAgent *agent.Agent) error {
		if err := os.MkdirAll(autoAgent.TargetDir, 0o755); err != nil {
			return err
		}
		autoAgent.State.Stage = state.StageFuzzing
		if err := autoAgent.State.Save(autoAgent.StatePath); err != nil {
			return err
		}
		started <- autoAgent
		return nil
	}

	child, err := manager.CreateCrashFixTask(pending.ID, CrashFixTaskRequest{
		DriverID: 9,
		Seq:      1,
		Crashes:  []string{"crash-oob"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if child.TaskKind != "crash_fix_child" || child.ParentTaskID != pending.ID {
		t.Fatalf("unexpected child metadata: %#v", child)
	}
	if child.OriginDriverID != 9 || child.OriginDriverSeq != 1 || len(child.OriginCrashes) != 1 || child.OriginCrashes[0] != "crash-oob" {
		t.Fatalf("unexpected child origin: %#v", child)
	}

	var autoAgent *agent.Agent
	select {
	case autoAgent = <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("child task did not start")
	}
	if autoAgent.Options.RepositoryURL != fixture.SourceDir {
		t.Fatalf("child repository = %q, want %q", autoAgent.Options.RepositoryURL, fixture.SourceDir)
	}
	if autoAgent.Options.Origin.SnapshotDir != fixture.SnapshotDir ||
		autoAgent.Options.Origin.SourceDir != fixture.SourceDir ||
		autoAgent.Options.Origin.BuildDir != fixture.BuildDir ||
		autoAgent.Options.Origin.InstallDir != fixture.InstallDir ||
		len(autoAgent.Options.Origin.StaticLibraries) != 1 ||
		autoAgent.Options.Origin.StaticLibraries[0] != fixture.StaticLibrary {
		t.Fatalf("unexpected origin options: %#v", autoAgent.Options.Origin)
	}
	if !strings.Contains(autoAgent.Options.Origin.Context, "heap-buffer-overflow") ||
		!strings.Contains(autoAgent.Options.Origin.Context, "fuzz_driver_9.c") {
		t.Fatalf("origin context is missing crash details:\n%s", autoAgent.Options.Origin.Context)
	}
}

func waitForTaskStatus(t *testing.T, task *Task, wanted string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if task.Snapshot().Status == wanted {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("status = %q, want %q", task.Snapshot().Status, wanted)
}

func waitForRegistryStatus(t *testing.T, id, wanted string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		entry, exists := registryEntryByID(id)
		if exists && entry.Status == wanted {
			return
		}
		time.Sleep(time.Millisecond)
	}
	entry, _ := registryEntryByID(id)
	t.Fatalf("registry status = %q, want %q", entry.Status, wanted)
}

type crashFixFixture struct {
	SnapshotDir   string
	SourceDir     string
	BuildDir      string
	InstallDir    string
	StaticLibrary string
}

func setupCrashFixParent(t *testing.T, snapshot *TaskSnapshot, entry fuzzing.CrashAnalysisEntry) crashFixFixture {
	t.Helper()
	sourceDir := filepath.Join(snapshot.TargetDir, "source")
	buildDir := filepath.Join(snapshot.TargetDir, "build")
	installDir := filepath.Join(snapshot.TargetDir, "install")
	staticLibrary := filepath.Join(buildDir, "libsample.a")
	for _, dir := range []string{sourceDir, buildDir, installDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "sample.c"), []byte("int sample(void) { return 1; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staticLibrary, []byte("archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	runState := state.New(snapshot.Request.RepositoryURL, "", snapshot.Request.Name, sourceDir)
	runState.Stage = state.StageFuzzing
	runState.SourceKind = "local"
	runState.BuildDir = buildDir
	runState.InstallDir = installDir
	runState.CompileCommandsPath = filepath.Join(buildDir, "compile_commands.json")
	runState.StaticLibraries = []string{staticLibrary}
	runState.OutputPath = filepath.Join(snapshot.TargetDir, "output")
	if err := runState.Save(snapshot.StatePath); err != nil {
		t.Fatal(err)
	}

	snapDir := crashReportSnapshotDir(snapshot.TargetDir, 9, 1)
	for _, dir := range []string{
		filepath.Join(snapDir, "driver"),
		filepath.Join(snapDir, "unique_crashes"),
		filepath.Join(snapDir, "crashes"),
		filepath.Join(snapDir, "crash-reports"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	driverSource := filepath.Join(snapDir, "driver", "fuzz_driver_9.c")
	if err := os.WriteFile(driverSource, []byte("int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned long Size) { return 0; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	buildScript := filepath.Join(snapDir, "build_cov_driver.sh")
	if err := os.WriteFile(buildScript, []byte("#!/bin/sh\ncc "+driverSource+" "+staticLibrary+" -o "+filepath.Join(snapDir, "cov_driver")+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	crashFile := filepath.Base(entry.File)
	if err := os.WriteFile(filepath.Join(snapDir, "unique_crashes", crashFile), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapDir, "crashes", crashFile), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(snapDir, filepath.FromSlash(entry.ReportPath))
	report := map[string]any{
		"report": map[string]any{
			"crash_file":     crashFile,
			"classification": entry.Classification,
			"crash_type":     entry.Type,
			"asan_report":    entry.ASanReport,
			"root_cause":     "test root cause",
		},
	}
	reportData, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, reportData, 0o644); err != nil {
		t.Fatal(err)
	}
	analysis := crashAnalysisJSON{Total: 1, Unique: 1, List: []fuzzing.CrashAnalysisEntry{entry}}
	analysisData, err := json.Marshal(analysis)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapDir, "crash-analysis.json"), analysisData, 0o644); err != nil {
		t.Fatal(err)
	}
	return crashFixFixture{
		SnapshotDir:   snapDir,
		SourceDir:     sourceDir,
		BuildDir:      buildDir,
		InstallDir:    installDir,
		StaticLibrary: staticLibrary,
	}
}

func lifecycleTestRequest(t *testing.T) RunRequest {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	repository := filepath.Join(root, "sample-library")
	if err := os.MkdirAll(repository, 0o755); err != nil {
		t.Fatal(err)
	}
	promefuzz := filepath.Join(root, "PromeFuzz")
	python := filepath.Join(promefuzz, ".venv", "bin", "python")
	if err := os.MkdirAll(filepath.Dir(python), 0o755); err != nil {
		t.Fatal(err)
	}
	for path, contents := range map[string]string{
		filepath.Join(promefuzz, "PromeFuzz.py"): "",
		filepath.Join(promefuzz, "config.toml"):  "",
		python:                                   "",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return RunRequest{
		RepositoryURL:  repository,
		Workspace:      filepath.Join(root, "workspace"),
		PromeFuzzRoot:  promefuzz,
		ConfigPath:     filepath.Join(promefuzz, "config.toml"),
		PythonPath:     python,
		PoolSize:       1,
		Jobs:           1,
		MaxFuzzDrivers: 2,
		CodexCommand:   "codex",
		StopAfter:      "fuzzing",
		FuzzInterval:   "30m",
	}
}
