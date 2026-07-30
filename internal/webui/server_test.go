package webui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"autofuzz/internal/agent"
	"autofuzz/internal/fuzzing"
	"autofuzz/internal/runevent"
	"autofuzz/internal/state"
)

func TestDefaultsEndpoint(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/defaults", nil)
	response := httptest.NewRecorder()
	NewServer(NewManager(context.Background())).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	var defaults RunRequest
	if err := json.Unmarshal(response.Body.Bytes(), &defaults); err != nil {
		t.Fatal(err)
	}
	if defaults.CodexCommand != "codex" || defaults.StopAfter != "fuzzing" || defaults.MaxFuzzDrivers != runtime.NumCPU() {
		t.Fatalf("unexpected defaults: %#v", defaults)
	}
}

func TestIndexUsesVueTaskConsole(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	NewServer(NewManager(context.Background())).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	combined := body + embeddedStaticText(t, "static/assets")
	for _, marker := range []string{
		`id="app"`,
		`/static/assets/`,
		`运行看板`,
		`创建任务`,
		`task-detail`,
		`linearStages`,
		`detailTabs`,
		`canTriggerFuzz`,
		`uniqueCrashItems`,
		`removeCrashQueueItem`,
		`snapshotRows`,
		`openSnapshotDiff`,
		`EventSource`,
		`/events`,
		`/fuzz-flow?limit=50`,
		`driver-cov-row`,
		`driver-graph-node`,
		`/coverage/function-sources`,
		`/crash-analysis-queue`,
		`unique-crashes`,
		`/crash-reports/analyze`,
		`/library-config`,
		`crash-analyze-button`,
		`stage-cycle`,
		`fuzz_flow`,
		`snap-version-button`,
		`/start`,
	} {
		if !strings.Contains(combined, marker) {
			t.Fatalf("index is missing %s", marker)
		}
	}
	for _, marker := range []string{
		`autofuzz-app-template`,
		`id="taskSelBtn"`,
		`task-sel-btn`,
		`window.Terminal`,
		`xterm.min.js`,
		`localStorage`,
	} {
		if strings.Contains(combined, marker) {
			t.Fatalf("index still contains removed runtime UI %s", marker)
		}
	}
	if strings.Contains(combined, "waitingForAnalysis") || strings.Contains(combined, "m.includes('plateau=')") {
		t.Fatal("index still infers LLM flow state from runtime log strings")
	}
	for _, marker := range []string{`__autofuzzLegacy`, `__autofuzzVueShell`, `mountLegacyApp`, `legacy-app.js`} {
		if strings.Contains(combined, marker) {
			t.Fatalf("index still contains legacy Vue bridge %s", marker)
		}
	}
}

func TestStaticAssetsServed(t *testing.T) {
	entries, err := staticFiles.ReadDir("static/assets")
	if err != nil {
		t.Fatalf("read embedded assets: %v", err)
	}
	assetsByExt := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext == ".js" || ext == ".css" {
			assetsByExt[ext] = entry.Name()
		}
	}

	server := NewServer(NewManager(context.Background()))
	for ext, expectedType := range map[string]string{".js": "javascript", ".css": "text/css"} {
		name := assetsByExt[ext]
		if name == "" {
			t.Fatalf("missing embedded %s asset", ext)
		}
		request := httptest.NewRequest(http.MethodGet, "/static/assets/"+name, nil)
		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status = %d", name, response.Code)
		}
		if !strings.Contains(response.Header().Get("Content-Type"), expectedType) {
			t.Fatalf("%s content-type = %q", name, response.Header().Get("Content-Type"))
		}
		if response.Body.Len() == 0 {
			t.Fatalf("%s returned empty body", name)
		}
	}
}

func TestFilterCoverageDataByDriverSelectsRequestedVersion(t *testing.T) {
	multi := fuzzing.MultiCoverageSnapshot{Targets: []fuzzing.TargetCoverageSnapshot{
		{
			DriverID:  1,
			Seq:       1,
			Available: true,
			Coverage: fuzzing.CoverageStatus{Summary: fuzzing.CoverageSummary{
				ExecutedFunctions: 1,
			}},
		},
		{
			DriverID:  1,
			Seq:       2,
			Available: true,
			Coverage: fuzzing.CoverageStatus{Summary: fuzzing.CoverageSummary{
				ExecutedFunctions: 2,
			}},
		},
	}}

	exact, ok := filterCoverageDataByDriver(multi, 1, 1).(fuzzing.CoverageSnapshot)
	if !ok || !exact.Available || exact.Coverage.Summary.ExecutedFunctions != 1 {
		t.Fatalf("exact version filter = %#v, want d1/v1", exact)
	}
	latest, ok := filterCoverageDataByDriver(multi, 1, 0).(fuzzing.CoverageSnapshot)
	if !ok || !latest.Available || latest.Coverage.Summary.ExecutedFunctions != 2 {
		t.Fatalf("latest version filter = %#v, want d1/v2", latest)
	}
}

func embeddedStaticText(t *testing.T, directory string) string {
	t.Helper()
	entries, err := staticFiles.ReadDir(directory)
	if err != nil {
		t.Fatalf("read embedded static dir %s: %v", directory, err)
	}
	var builder strings.Builder
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := staticFiles.ReadFile(directory + "/" + entry.Name())
		if err != nil {
			t.Fatalf("read embedded static file %s/%s: %v", directory, entry.Name(), err)
		}
		builder.Write(data)
	}
	return builder.String()
}

type libraryConfigTaskFixture struct {
	targetDir       string
	configPath      string
	compileCommands string
	outputPath      string
	headerDir       string
	staticLibrary   string
}

func setupLibraryConfigTask(t *testing.T, id string) libraryConfigTaskFixture {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	workspace := t.TempDir()
	targetDir := filepath.Join(workspace, "sample")
	sourceDir := filepath.Join(targetDir, "source")
	buildDir := filepath.Join(targetDir, "build")
	installDir := filepath.Join(targetDir, "install")
	promeFuzzRoot := filepath.Join(targetDir, "promefuzz")
	headerDir := filepath.Join(sourceDir, "include")
	sourceFile := filepath.Join(sourceDir, "src", "sample.c")
	installHeaderDir := filepath.Join(installDir, "include")
	outputPath := filepath.Join(targetDir, "promefuzz-output")
	compileCommands := filepath.Join(buildDir, "compile_commands.json")
	staticLibrary := filepath.Join(installDir, "lib", "libsample.a")
	promeFuzzConfig := filepath.Join(promeFuzzRoot, "config.toml")
	pythonPath := filepath.Join(promeFuzzRoot, ".venv", "bin", "python")
	for _, dir := range []string{
		headerDir,
		filepath.Dir(sourceFile),
		installHeaderDir,
		filepath.Dir(compileCommands),
		filepath.Dir(staticLibrary),
		filepath.Dir(pythonPath),
		filepath.Join(outputPath, "preprocessor"),
		filepath.Join(outputPath, "comprehender"),
		filepath.Join(outputPath, "fuzz_driver"),
		filepath.Join(targetDir, "logs", "fuzzing"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	headerContent := "#ifndef SAMPLE_H\n#define SAMPLE_H\nint sample(void);\n#endif\n"
	for path, content := range map[string]string{
		filepath.Join(headerDir, "sample.h"):                                 headerContent,
		filepath.Join(installHeaderDir, "sample.h"):                          headerContent,
		sourceFile:                                                           "#include \"sample.h\"\nint sample(void) { return 0; }\n",
		compileCommands:                                                      "[{\"directory\":\"" + targetDir + "\",\"file\":\"" + sourceFile + "\",\"arguments\":[\"clang\",\"-I\",\"" + headerDir + "\",\"-c\",\"" + sourceFile + "\"]}]\n",
		staticLibrary:   "",
		filepath.Join(promeFuzzRoot, "PromeFuzz.py"): "",
		promeFuzzConfig: "",
		pythonPath:      "",
		filepath.Join(outputPath, "preprocessor", "api.json"):           "{}\n",
		filepath.Join(outputPath, "comprehender", "semantic_relev.pkl"): "data",
		filepath.Join(outputPath, "fuzz_driver", "fuzz_driver_1.c"):     "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return 0; }\n",
		filepath.Join(targetDir, "logs", "fuzzing", "live.log"):         "old fuzzing data\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(targetDir, "library.toml")
	if err := os.WriteFile(configPath, []byte(libraryConfigContent("sample", compileCommands, outputPath, headerDir, staticLibrary)), 0o644); err != nil {
		t.Fatal(err)
	}
	runState := state.New(sourceDir, "", "sample", sourceDir)
	runState.Stage = state.StageFuzzing
	runState.BuildDir = buildDir
	runState.InstallDir = installDir
	runState.CompileCommandsPath = compileCommands
	runState.StaticLibraries = []string{staticLibrary}
	runState.Language = "c"
	runState.HeaderPaths = []string{headerDir}
	runState.LibraryConfigPath = configPath
	runState.OutputPath = outputPath
	runState.GenerationTask = "allcover"
	runState.GeneratedDrivers = []string{filepath.Join(outputPath, "fuzz_driver", "fuzz_driver_1.c")}
	if err := runState.Save(filepath.Join(targetDir, "agent-state.json")); err != nil {
		t.Fatal(err)
	}
	request := DefaultRunRequest()
	request.RepositoryURL = sourceDir
	request.Workspace = workspace
	request.Name = "sample"
	request.PromeFuzzRoot = promeFuzzRoot
	request.ConfigPath = promeFuzzConfig
	request.PythonPath = pythonPath
	if err := upsertTaskRegistry(registryEntry{
		ID:            id,
		Workspace:     workspace,
		Name:          "sample",
		RepositoryURL: sourceDir,
		CreatedAt:     time.Now().Format(time.RFC3339),
		Status:        "completed",
		Request:       request,
	}); err != nil {
		t.Fatal(err)
	}
	return libraryConfigTaskFixture{
		targetDir:       targetDir,
		configPath:      configPath,
		compileCommands: compileCommands,
		outputPath:      outputPath,
		headerDir:       headerDir,
		staticLibrary:   staticLibrary,
	}
}

func libraryConfigContent(project, compileCommands, outputPath, headerDir, staticLibrary string) string {
	return fmt.Sprintf(`[%s]
language = "c"
compile_commands_path = "%s"
document_paths = []
document_has_api_usage = false
output_path = "%s"
header_paths = ["%s"]
driver_build_args = ["%s"]
consumer_case_paths = []
exclude_paths = []
api_ban_list_path = ""
api_hints_path = ""
`, project, compileCommands, outputPath, headerDir, staticLibrary)
}

func TestOverviewEndpointAggregatesDashboardMetrics(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	workspace := t.TempDir()
	targetDir := filepath.Join(workspace, "lib-a")
	snapDir := filepath.Join(targetDir, "logs", "fuzzing", "driver-targets", "driver-0001", "v001")
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	analysis := `{
  "total_crashes": 2,
  "unique_crashes": 2,
  "unique_list": [{
    "file": "crash-a",
    "type": "heap-buffer-overflow",
    "stack": "stack",
    "report_status": "completed",
    "classification": "library_bug"
  }, {
    "file": "crash-b",
    "type": "SEGV",
    "stack": "stack",
    "report_status": "pending"
  }]
}`
	if err := os.WriteFile(filepath.Join(snapDir, "crash-analysis.json"), []byte(analysis), 0o644); err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	if err := upsertTaskRegistry(registryEntry{
		ID:            "run-a",
		Workspace:     workspace,
		Name:          "lib-a",
		RepositoryURL: "https://example.com/lib-a.git",
		CreatedAt:     createdAt.Format(time.RFC3339),
		Status:        "running",
	}); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(context.Background())
	manager.tasks["run-a"] = &Task{
		id:          "run-a",
		request:     RunRequest{RepositoryURL: "https://example.com/lib-a.git"},
		status:      "running",
		createdAt:   createdAt,
		targetDir:   targetDir,
		stages:      map[string]string{"fuzzing": "running"},
		subscribers: map[chan runevent.Event]struct{}{},
	}

	request := httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	response := httptest.NewRecorder()
	NewServer(manager).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var got OverviewResponse
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Tasks.Total != 1 || got.Tasks.Running != 1 {
		t.Fatalf("unexpected task counts: %#v", got.Tasks)
	}
	if got.Issues.DiscoveredTotal != 2 || got.Issues.LibraryBugs != 1 || got.Issues.PendingAnalysis != 1 {
		t.Fatalf("unexpected issue counts: %#v", got.Issues)
	}
	if len(got.RecentIssues) != 2 || got.RecentIssues[0].TaskID != "run-a" || got.RecentIssues[0].DriverID != 1 {
		t.Fatalf("unexpected recent issues: %#v", got.RecentIssues)
	}
}

func TestFuzzFlowEndpointRestoresCurrentAndLimitsHistory(t *testing.T) {
	targetDir := t.TempDir()
	logsDir := filepath.Join(targetDir, "logs", "fuzzing")
	flow := &fuzzing.FuzzFlowSnapshot{Iteration: 3, DriverSeq: 2, Phase: fuzzing.FuzzFlowAnalyzing, Status: "running", Trigger: "manual", Message: "Codex 正在分析"}
	if err := flow.Save(filepath.Join(logsDir, "fuzz-flow.json")); err != nil {
		t.Fatal(err)
	}
	history := "" +
		`{"iteration":1,"seq":1,"trigger":"interval","analysis":{"analysis":"第一轮"},"started_at":"2026-07-21T00:00:00Z","finished_at":"2026-07-21T00:00:01Z"}` + "\n" +
		`{"iteration":2,"seq":1,"trigger":"manual","analysis":{"analysis":"第二轮","plateau_reached":true,"needs_update":true},"regenerated":true,"started_at":"2026-07-21T00:01:00Z","finished_at":"2026-07-21T00:01:02Z"}` + "\n"
	if err := os.WriteFile(filepath.Join(logsDir, "fuzzing-history.jsonl"), []byte(history), 0o644); err != nil {
		t.Fatal(err)
	}
	task := &Task{id: "test", status: "running", createdAt: time.Now(), targetDir: targetDir, stages: map[string]string{}, subscribers: map[chan runevent.Event]struct{}{}}
	manager := NewManager(context.Background())
	manager.tasks[task.id] = task

	request := httptest.NewRequest(http.MethodGet, "/api/runs/test/fuzz-flow?limit=1", nil)
	response := httptest.NewRecorder()
	NewServer(manager).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var got FuzzFlowResponse
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Current == nil || got.Current.Phase != fuzzing.FuzzFlowAnalyzing || len(got.History) != 1 || got.History[0].Iteration != 2 || got.History[0].Trigger != "manual" {
		t.Fatalf("unexpected fuzz flow response: %#v", got)
	}
}

func TestLibraryConfigEndpointReadsGeneratedConfig(t *testing.T) {
	task := setupLibraryConfigTask(t, "library-view")
	request := httptest.NewRequest(http.MethodGet, "/api/runs/library-view/library-config", nil)
	response := httptest.NewRecorder()
	NewServer(NewManager(context.Background())).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var got LibraryConfigResponse
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Available || !got.Editable || got.Path != task.configPath || !strings.Contains(got.Content, "header_paths") {
		t.Fatalf("unexpected library config response: %#v", got)
	}
}

func TestLibraryConfigReprocessValidatesBeforeReplace(t *testing.T) {
	task := setupLibraryConfigTask(t, "library-invalid")
	original, err := os.ReadFile(task.configPath)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"content":"[sample]\nlanguage = \"c\"\n"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/runs/library-invalid/library-config/reprocess", bytes.NewReader(body))
	response := httptest.NewRecorder()
	NewServer(NewManager(context.Background())).ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	after, err := os.ReadFile(task.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, after) {
		t.Fatal("invalid library.toml replaced the existing config")
	}
}

func TestLibraryConfigReprocessResetsDownstreamAndRestarts(t *testing.T) {
	task := setupLibraryConfigTask(t, "library-reprocess")
	manager := NewManager(context.Background())
	runStarted := make(chan state.Stage, 1)
	manager.runAgent = func(_ context.Context, autoAgent *agent.Agent) error {
		runStarted <- autoAgent.State.Stage
		return nil
	}
	nextContent := libraryConfigContent("sample", task.compileCommands, task.outputPath, task.headerDir, task.staticLibrary) +
		"\n# manual edit\n"
	body, err := json.Marshal(LibraryConfigReprocessRequest{Content: nextContent})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/runs/library-reprocess/library-config/reprocess", bytes.NewReader(body))
	response := httptest.NewRecorder()
	NewServer(manager).ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	select {
	case stage := <-runStarted:
		if stage != state.StageConfigured {
			t.Fatalf("agent resumed from %s, want configured", stage)
		}
	case <-time.After(time.Second):
		t.Fatal("agent restart was not triggered")
	}
	updated, err := state.Load(filepath.Join(task.targetDir, "agent-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if updated.Stage != state.StageConfigured || updated.GenerationTask != "" || len(updated.GeneratedDrivers) != 0 {
		t.Fatalf("state was not reset to configured: %#v", updated)
	}
	if data, err := os.ReadFile(task.configPath); err != nil || !strings.Contains(string(data), "# manual edit") {
		t.Fatalf("library.toml was not replaced: %v %s", err, data)
	}
	for _, path := range []string{
		filepath.Join(task.outputPath, "preprocessor"),
		filepath.Join(task.outputPath, "comprehender"),
		filepath.Join(task.outputPath, "fuzz_driver"),
		filepath.Join(task.targetDir, "logs", "fuzzing"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after reprocess", path)
		}
	}
	backups, _ := filepath.Glob(filepath.Join(task.targetDir, "logs", "manual-library-config", "library-*.toml"))
	archives, _ := filepath.Glob(filepath.Join(task.targetDir, "logs", "manual-library-config", "fuzzing-*"))
	if len(backups) != 1 || len(archives) != 1 {
		t.Fatalf("backup/archive not created, backups=%v archives=%v", backups, archives)
	}
}

func TestCrashReportsEndpointReadsSnapshotReports(t *testing.T) {
	targetDir := t.TempDir()
	snapDir := filepath.Join(targetDir, "logs", "fuzzing", "driver-targets", "driver-0003", "v002")
	if err := os.MkdirAll(filepath.Join(snapDir, "crash-reports"), 0o755); err != nil {
		t.Fatal(err)
	}
	analysis := `{
  "total_crashes": 1,
  "unique_crashes": 1,
  "unique_list": [{
    "file": "crash-a",
    "type": "heap-buffer-overflow",
    "stack": "stack: lib_fn <- LLVMFuzzerTestOneInput",
    "asan_report": "ERROR: AddressSanitizer: heap-buffer-overflow\nSUMMARY: AddressSanitizer",
    "report_path": "crash-reports/crash-a.json",
    "report_status": "completed",
    "classification": "library_bug"
  }]
}`
	if err := os.WriteFile(filepath.Join(snapDir, "crash-analysis.json"), []byte(analysis), 0o644); err != nil {
		t.Fatal(err)
	}
	report := `{"report":{"classification":"library_bug","asan_report":"ERROR: AddressSanitizer: heap-buffer-overflow","root_cause":"库边界检查缺失"}}`
	if err := os.WriteFile(filepath.Join(snapDir, "crash-reports", "crash-a.json"), []byte(report), 0o644); err != nil {
		t.Fatal(err)
	}

	manager := NewManager(context.Background())
	manager.tasks["crash"] = &Task{id: "crash", status: "running", createdAt: time.Now(), targetDir: targetDir, stages: map[string]string{}}
	request := httptest.NewRequest(http.MethodGet, "/api/runs/crash/crash-reports?driver_id=3&seq=2", nil)
	response := httptest.NewRecorder()
	NewServer(manager).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var got CrashReportsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.DriverID != 3 || got.Seq != 2 || len(got.Reports) != 1 {
		t.Fatalf("unexpected crash reports response: %#v", got)
	}
	if got.Reports[0].Entry.Classification != "library_bug" || !strings.Contains(got.Reports[0].Entry.ASanReport, "AddressSanitizer") || !strings.Contains(string(got.Reports[0].Report), "库边界检查缺失") {
		t.Fatalf("unexpected report entry: %#v", got.Reports[0])
	}
}

func TestUniqueCrashesEndpointAggregatesDriverSnapshots(t *testing.T) {
	targetDir := t.TempDir()
	snapDir := filepath.Join(targetDir, "logs", "fuzzing", "driver-targets", "driver-0003", "v002")
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	crashTime := time.Date(2026, 7, 24, 1, 2, 3, 0, time.UTC)
	crashPath := filepath.Join(snapDir, "crashes", "leak-a")
	if err := os.MkdirAll(filepath.Dir(crashPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crashPath, []byte("crash"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(crashPath, crashTime, crashTime); err != nil {
		t.Fatal(err)
	}
	analysis := `{
  "total_crashes": 1,
  "unique_crashes": 1,
  "unique_list": [{
    "file": "leak-a",
    "type": "timeout",
    "stack": "(timeout)"
  }]
}`
	if err := os.WriteFile(filepath.Join(snapDir, "crash-analysis.json"), []byte(analysis), 0o644); err != nil {
		t.Fatal(err)
	}

	manager := NewManager(context.Background())
	manager.tasks["crashes"] = &Task{id: "crashes", status: "running", createdAt: time.Now(), targetDir: targetDir, stages: map[string]string{}}
	request := httptest.NewRequest(http.MethodGet, "/api/runs/crashes/unique-crashes", nil)
	response := httptest.NewRecorder()
	NewServer(manager).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var got UniqueCrashesResponse
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Crashes) != 1 || got.Crashes[0].DriverID != 3 || got.Crashes[0].Seq != 2 || got.Crashes[0].Entry.Type != "leak" || got.Crashes[0].Entry.ReportStatus != "pending" {
		t.Fatalf("unexpected unique crashes response: %#v", got)
	}
	requireSameRFC3339Instant(t, got.Crashes[0].CrashCreatedAt, crashTime)
	if got.Crashes[0].LastAnalysisAt != "" {
		t.Fatalf("unexpected unique crash timestamps: %#v", got.Crashes[0])
	}
}

func TestUniqueCrashesEndpointReconcilesStaleRunningReport(t *testing.T) {
	targetDir := t.TempDir()
	snapDir := filepath.Join(targetDir, "logs", "fuzzing", "driver-targets", "driver-0001", "v001")
	if err := os.MkdirAll(filepath.Join(snapDir, "crash-reports"), 0o755); err != nil {
		t.Fatal(err)
	}
	crashTime := time.Date(2026, 7, 24, 2, 3, 4, 0, time.UTC)
	reportTime := time.Date(2026, 7, 24, 3, 4, 5, 0, time.UTC)
	crashPath := filepath.Join(snapDir, "crashes", "crash-a")
	if err := os.MkdirAll(filepath.Dir(crashPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(crashPath, []byte("crash"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(crashPath, crashTime, crashTime); err != nil {
		t.Fatal(err)
	}
	analysis := `{
  "total_crashes": 1,
  "unique_crashes": 1,
  "unique_list": [{
    "file": "crash-a",
    "type": "heap-buffer-overflow",
    "stack": "stack",
    "report_path": "crash-reports/crash-a.json",
    "report_status": "running"
  }]
}`
	if err := os.WriteFile(filepath.Join(snapDir, "crash-analysis.json"), []byte(analysis), 0o644); err != nil {
		t.Fatal(err)
	}
	report := `{"report":{"classification":"library_bug","analysis":"这是库侧越界写入。","asan_report":"ERROR: AddressSanitizer: heap-buffer-overflow"}}`
	reportPath := filepath.Join(snapDir, "crash-reports", "crash-a.json")
	if err := os.WriteFile(reportPath, []byte(report), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(reportPath, reportTime, reportTime); err != nil {
		t.Fatal(err)
	}

	manager := NewManager(context.Background())
	manager.tasks["stale"] = &Task{id: "stale", status: "running", createdAt: time.Now(), targetDir: targetDir, stages: map[string]string{}}
	request := httptest.NewRequest(http.MethodGet, "/api/runs/stale/unique-crashes", nil)
	response := httptest.NewRecorder()
	NewServer(manager).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var got UniqueCrashesResponse
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Crashes) != 1 || got.Crashes[0].Entry.ReportStatus != "completed" || got.Crashes[0].Entry.Classification != "library_bug" || got.Crashes[0].Entry.Analysis != "这是库侧越界写入。" {
		t.Fatalf("stale running report was not reconciled: %#v", got.Crashes)
	}
	requireSameRFC3339Instant(t, got.Crashes[0].CrashCreatedAt, crashTime)
	requireSameRFC3339Instant(t, got.Crashes[0].LastAnalysisAt, reportTime)
}

func TestDeleteUniqueCrashesEndpointRemovesEntriesAndArtifacts(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	targetDir := t.TempDir()
	workspace := filepath.Dir(targetDir)
	taskName := filepath.Base(targetDir)
	snapDir := filepath.Join(targetDir, "logs", "fuzzing", "driver-targets", "driver-0001", "v001")
	for _, dir := range []string{
		filepath.Join(snapDir, "crashes"),
		filepath.Join(snapDir, "unique_crashes"),
		filepath.Join(snapDir, "crash-reports"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"crash-a", "crash-b"} {
		if err := os.WriteFile(filepath.Join(snapDir, "crashes", name), []byte("raw-"+name), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(snapDir, "unique_crashes", name), []byte("unique-"+name), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(snapDir, "crash-reports", name+".json"), []byte(`{"ok":true}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	analysis := crashAnalysisJSON{
		Total:  2,
		Unique: 2,
		List: []fuzzing.CrashAnalysisEntry{
			{File: "crash-a", Type: "heap-buffer-overflow", UniquePath: "unique_crashes/crash-a", ReportPath: "crash-reports/crash-a.json", ReportStatus: "completed"},
			{File: "crash-b", Type: "stack-buffer-overflow", UniquePath: "unique_crashes/crash-b", ReportPath: "crash-reports/crash-b.json", ReportStatus: "pending"},
		},
	}
	analysisData, err := json.MarshalIndent(analysis, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapDir, "crash-analysis.json"), analysisData, 0o644); err != nil {
		t.Fatal(err)
	}

	manager := NewManager(context.Background())
	createdAt := time.Date(2026, 7, 24, 4, 5, 6, 0, time.UTC)
	if err := upsertTaskRegistry(registryEntry{
		ID:            "delete-crash",
		Workspace:     workspace,
		Name:          taskName,
		RepositoryURL: "https://example.com/delete-crash.git",
		CreatedAt:     createdAt.Format(time.RFC3339),
		Status:        "running",
	}); err != nil {
		t.Fatal(err)
	}
	manager.tasks["delete-crash"] = &Task{id: "delete-crash", status: "running", createdAt: time.Now(), targetDir: targetDir, stages: map[string]string{}}
	body := []byte(`{"crashes":[{"driver_id":1,"seq":1,"file":"crash-a"}]}`)
	request := httptest.NewRequest(http.MethodDelete, "/api/runs/delete-crash/unique-crashes", bytes.NewReader(body))
	response := httptest.NewRecorder()
	NewServer(manager).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var result UniqueCrashDeleteResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Deleted != 1 {
		t.Fatalf("deleted = %d, want 1", result.Deleted)
	}
	data, err := os.ReadFile(filepath.Join(snapDir, "crash-analysis.json"))
	if err != nil {
		t.Fatal(err)
	}
	var refreshed crashAnalysisJSON
	if err := json.Unmarshal(data, &refreshed); err != nil {
		t.Fatal(err)
	}
	if refreshed.Total != 2 || refreshed.Unique != 1 || len(refreshed.List) != 1 || refreshed.List[0].File != "crash-b" {
		t.Fatalf("unexpected refreshed analysis: %s", data)
	}
	if _, err := os.Stat(filepath.Join(snapDir, "crashes", "crash-a")); err != nil {
		t.Fatalf("raw crash artifact should remain: %v", err)
	}
	if _, err := os.Stat(filepath.Join(snapDir, "unique_crashes", "crash-a")); !os.IsNotExist(err) {
		t.Fatalf("unique crash artifact still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(snapDir, "crash-reports", "crash-a.json")); !os.IsNotExist(err) {
		t.Fatalf("crash report still exists: %v", err)
	}
	if _, err := os.Stat(filepath.Join(snapDir, "unique_crashes", "crash-b")); err != nil {
		t.Fatalf("remaining unique crash was removed: %v", err)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	response = httptest.NewRecorder()
	NewServer(manager).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("overview status = %d, body = %s", response.Code, response.Body.String())
	}
	var overview OverviewResponse
	if err := json.Unmarshal(response.Body.Bytes(), &overview); err != nil {
		t.Fatal(err)
	}
	if overview.Issues.UniqueCrashesTotal != 1 || len(overview.RecentIssues) != 1 || overview.RecentIssues[0].File != "crash-b" {
		t.Fatalf("overview still includes deleted crash: %#v", overview)
	}
}

func requireSameRFC3339Instant(t *testing.T, got string, want time.Time) {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, got)
	if err != nil {
		t.Fatalf("parse time %q: %v", got, err)
	}
	if !parsed.Equal(want) {
		t.Fatalf("time = %s, want same instant as %s", got, want.Format(time.RFC3339))
	}
}

func TestCrashReportsEndpointNormalizesLegacyLeakTimeout(t *testing.T) {
	targetDir := t.TempDir()
	snapDir := filepath.Join(targetDir, "logs", "fuzzing", "driver-targets", "driver-0001", "v001")
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	analysis := `{
  "total_crashes": 1,
  "unique_crashes": 1,
  "unique_list": [{
    "file": "leak-b276eb69773681eada7c51666c7234b9b62846d0",
    "type": "timeout",
    "stack": "(timeout)"
  }]
}`
	if err := os.WriteFile(filepath.Join(snapDir, "crash-analysis.json"), []byte(analysis), 0o644); err != nil {
		t.Fatal(err)
	}

	manager := NewManager(context.Background())
	manager.tasks["legacy"] = &Task{id: "legacy", status: "running", createdAt: time.Now(), targetDir: targetDir, stages: map[string]string{}}
	request := httptest.NewRequest(http.MethodGet, "/api/runs/legacy/crash-reports?driver_id=1&seq=1", nil)
	response := httptest.NewRecorder()
	NewServer(manager).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var got CrashReportsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Reports) != 1 || got.Reports[0].Entry.Type != "leak" || got.Reports[0].Entry.ReportStatus != "pending" {
		t.Fatalf("legacy leak timeout was not normalized to pending leak: %#v", got.Reports)
	}
}

func TestSSEIncludesCodexJSONData(t *testing.T) {
	task := &Task{
		id: "test", status: "completed", createdAt: time.Now(), stages: map[string]string{},
		subscribers: map[chan runevent.Event]struct{}{},
	}
	raw := json.RawMessage(`{"type":"item.completed","item":{"type":"agent_message","text":"done"}}`)
	event := runevent.New("codex", "built", "", "codex-cli", "item.completed")
	event.Data = raw
	task.publish(event)
	now := time.Now()
	task.finishedAt = &now
	manager := NewManager(context.Background())
	manager.tasks[task.id] = task

	request := httptest.NewRequest(http.MethodGet, "/api/runs/test/events", nil)
	request.SetPathValue("id", "test")
	response := httptest.NewRecorder()
	NewServer(manager).runEvents(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	if !strings.Contains(body, "event: autofuzz") || !strings.Contains(body, `"item.completed"`) {
		t.Fatalf("unexpected SSE body: %s", body)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/runs/test/events", nil)
	request.SetPathValue("id", "test")
	request.Header.Set("Last-Event-ID", "1")
	response = httptest.NewRecorder()
	NewServer(manager).runEvents(response, request)
	if strings.Contains(response.Body.String(), "event: autofuzz") {
		t.Fatalf("reconnect replayed an acknowledged event: %s", response.Body.String())
	}
}

func TestSSEIncludesStructuredFuzzFlow(t *testing.T) {
	task := &Task{
		id: "flow", status: "completed", createdAt: time.Now(), stages: map[string]string{},
		subscribers: map[chan runevent.Event]struct{}{},
	}
	raw := json.RawMessage(`{"iteration":7,"driver_seq":3,"phase":"analyzing","status":"running","trigger":"manual","message":"Codex 正在分析","updated_at":"2026-07-21T00:00:00Z"}`)
	event := runevent.New("fuzz_flow", "fuzzing", "running", "fuzz-loop", "Codex 正在分析")
	event.Data = raw
	task.publish(event)
	now := time.Now()
	task.finishedAt = &now
	manager := NewManager(context.Background())
	manager.tasks[task.id] = task

	request := httptest.NewRequest(http.MethodGet, "/api/runs/flow/events", nil)
	request.SetPathValue("id", "flow")
	response := httptest.NewRecorder()
	NewServer(manager).runEvents(response, request)
	body := response.Body.String()
	if !strings.Contains(body, `"kind":"fuzz_flow"`) || !strings.Contains(body, `"phase":"analyzing"`) || !strings.Contains(body, `"trigger":"manual"`) {
		t.Fatalf("unexpected SSE flow body: %s", body)
	}
}
