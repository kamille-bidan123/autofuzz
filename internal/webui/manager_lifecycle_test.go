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

	result, err := manager.DriverDiff(pending.ID, 2)
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
	if _, err := manager.DriverDiff(pending.ID, 1); err == nil {
		t.Fatal("v1 unexpectedly has a previous version")
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
		RepositoryURL: repository,
		Workspace:     filepath.Join(root, "workspace"),
		PromeFuzzRoot: promefuzz,
		ConfigPath:    filepath.Join(promefuzz, "config.toml"),
		PythonPath:    python,
		PoolSize:      1,
		Jobs:          1,
		CodexCommand:  "codex",
		StopAfter:     "fuzzing",
		FuzzInterval:  "30m",
	}
}
