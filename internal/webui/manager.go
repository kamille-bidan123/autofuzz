package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"autofuzz/internal/agent"
	"autofuzz/internal/fuzzing"
	"autofuzz/internal/runevent"
	"autofuzz/internal/runner"
	"autofuzz/internal/state"
)

type RunRequest struct {
	RepositoryURL         string   `json:"repository_url"`
	Ref                   string   `json:"ref"`
	Name                  string   `json:"name,omitempty"`
	Workspace             string   `json:"workspace"`
	PromeFuzzRoot         string   `json:"promefuzz"`
	ConfigPath            string   `json:"promefuzz_config"`
	PythonPath            string   `json:"python"`
	PoolSize              int      `json:"pool_size"`
	Jobs                  int      `json:"jobs"`
	MaxFuzzDrivers        int      `json:"max_fuzz_drivers"`
	CodexCommand          string   `json:"codex_command"`
	CodexModel            string   `json:"codex_model"`
	CodexProfile          string   `json:"codex_profile"`
	Resume                bool     `json:"resume"`
	Verbose               bool     `json:"verbose"`
	StopAfter             string   `json:"stop_after"`
	FuzzInterval          string   `json:"fuzz_interval"`
	TaskKind              string   `json:"task_kind,omitempty"`
	ParentTaskID          string   `json:"parent_task_id,omitempty"`
	OriginDriverID        int      `json:"origin_driver_id,omitempty"`
	OriginDriverSeq       int      `json:"origin_driver_seq,omitempty"`
	OriginCrashes         []string `json:"origin_crashes,omitempty"`
	OriginSnapshotDir     string   `json:"origin_snapshot_dir,omitempty"`
	OriginSourceDir       string   `json:"origin_source_dir,omitempty"`
	OriginBuildDir        string   `json:"origin_build_dir,omitempty"`
	OriginInstallDir      string   `json:"origin_install_dir,omitempty"`
	OriginStaticLibraries []string `json:"origin_static_libraries,omitempty"`
	CrashFixContext       string   `json:"crash_fix_context,omitempty"`
}

func DefaultRunRequest() RunRequest {
	options := agent.DefaultOptions()
	return RunRequest{
		Workspace: options.Workspace, PromeFuzzRoot: options.PromeFuzzRoot,
		ConfigPath: options.ConfigPath, PythonPath: options.PythonPath,
		PoolSize: options.PoolSize, Jobs: options.Jobs, MaxFuzzDrivers: options.MaxFuzzDrivers,
		CodexCommand: options.CodexCommand, CodexModel: options.CodexModel,
		CodexProfile: options.CodexProfile, StopAfter: string(options.StopAfter),
		FuzzInterval: options.FuzzInterval.String(),
	}
}

func (r RunRequest) options() agent.Options {
	opts := agent.Options{
		RepositoryURL: r.RepositoryURL, Ref: r.Ref, ProjectName: r.Name, Workspace: r.Workspace,
		PromeFuzzRoot: r.PromeFuzzRoot, ConfigPath: r.ConfigPath, PythonPath: r.PythonPath,
		PoolSize: r.PoolSize, Jobs: r.Jobs, MaxFuzzDrivers: r.MaxFuzzDrivers,
		CodexCommand: r.CodexCommand, CodexModel: r.CodexModel, CodexProfile: r.CodexProfile,
		Resume: r.Resume, Verbose: r.Verbose, StopAfter: state.Stage(r.StopAfter),
		TaskKind: r.TaskKind, ParentTaskID: r.ParentTaskID,
		Origin: agent.CrashFixOrigin{
			DriverID: r.OriginDriverID, DriverSeq: r.OriginDriverSeq,
			Crashes: append([]string(nil), r.OriginCrashes...), SnapshotDir: r.OriginSnapshotDir,
			SourceDir: r.OriginSourceDir, BuildDir: r.OriginBuildDir, InstallDir: r.OriginInstallDir,
			StaticLibraries: append([]string(nil), r.OriginStaticLibraries...), Context: r.CrashFixContext,
		},
	}
	if r.FuzzInterval != "" {
		if d, err := time.ParseDuration(r.FuzzInterval); err == nil {
			opts.FuzzInterval = d
		}
	}
	return opts
}

func normalizedRunRequest(original RunRequest, options agent.Options) RunRequest {
	original.RepositoryURL = options.RepositoryURL
	original.Ref = options.Ref
	original.Name = options.ProjectName
	original.Workspace = options.Workspace
	original.PromeFuzzRoot = options.PromeFuzzRoot
	original.ConfigPath = options.ConfigPath
	original.PythonPath = options.PythonPath
	original.PoolSize = options.PoolSize
	original.Jobs = options.Jobs
	original.MaxFuzzDrivers = options.MaxFuzzDrivers
	original.CodexCommand = options.CodexCommand
	original.CodexModel = options.CodexModel
	original.CodexProfile = options.CodexProfile
	original.Resume = options.Resume
	original.Verbose = options.Verbose
	original.StopAfter = string(options.StopAfter)
	original.FuzzInterval = options.FuzzInterval.String()
	original.TaskKind = options.TaskKind
	original.ParentTaskID = options.ParentTaskID
	original.OriginDriverID = options.Origin.DriverID
	original.OriginDriverSeq = options.Origin.DriverSeq
	original.OriginCrashes = append([]string(nil), options.Origin.Crashes...)
	original.OriginSnapshotDir = options.Origin.SnapshotDir
	original.OriginSourceDir = options.Origin.SourceDir
	original.OriginBuildDir = options.Origin.BuildDir
	original.OriginInstallDir = options.Origin.InstallDir
	original.OriginStaticLibraries = append([]string(nil), options.Origin.StaticLibraries...)
	original.CrashFixContext = options.Origin.Context
	return original
}

type StageSnapshot struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Owner  string `json:"owner"`
	Status string `json:"status"`
}

type TaskSnapshot struct {
	ID              string          `json:"id"`
	Status          string          `json:"status"`
	Error           string          `json:"error,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	FinishedAt      *time.Time      `json:"finished_at,omitempty"`
	TargetDir       string          `json:"target_dir"`
	StatePath       string          `json:"state_path"`
	TaskKind        string          `json:"task_kind,omitempty"`
	ParentTaskID    string          `json:"parent_task_id,omitempty"`
	OriginDriverID  int             `json:"origin_driver_id,omitempty"`
	OriginDriverSeq int             `json:"origin_driver_seq,omitempty"`
	OriginCrashes   []string        `json:"origin_crashes,omitempty"`
	OriginSourceDir string          `json:"origin_source_dir,omitempty"`
	Request         RunRequest      `json:"request"`
	Stages          []StageSnapshot `json:"stages"`
}

type stageDefinition struct {
	id    string
	name  string
	owner string
}

var stageDefinitions = []stageDefinition{
	{string(state.StageCloned), "准备源码", "Go"},
	{string(state.StageBuilt), "自主构建", "Codex CLI"},
	{string(state.StageConfigured), "生成 library.toml", "Codex CLI"},
	{string(state.StagePreprocessed), "API 预处理", "PromeFuzz"},
	{string(state.StageComprehended), "API 理解", "PromeFuzz + Codex"},
	{string(state.StageGenerated), "All-cover 全量生成", "PromeFuzz + Codex"},
	{string(state.StageFuzzing), "持续 Fuzz 测试", "libFuzzer + Codex"},
}

func stageDefinitionsFor(taskKind string) []stageDefinition {
	if taskKind == "crash_fix_child" {
		return []stageDefinition{
			{string(state.StageBuilt), "修复并编译库", "Codex CLI"},
			{string(state.StageGenerated), "编译 fuzz_driver", "Go"},
			{string(state.StageFuzzing), "持续 Fuzz 测试", "libFuzzer + Codex"},
		}
	}
	return stageDefinitions
}

var stageRanks = map[string]int{
	string(state.StageInit): 0, string(state.StageCloned): 1, string(state.StageBuilt): 2,
	string(state.StageConfigured): 3, string(state.StagePreprocessed): 4,
	string(state.StageComprehended): 5, string(state.StageGenerated): 6,
	string(state.StageFuzzing): 7,
}

type Task struct {
	mu            sync.RWMutex
	id            string
	request       RunRequest
	status        string
	err           string
	createdAt     time.Time
	finishedAt    *time.Time
	targetDir     string
	statePath     string
	stages        map[string]string
	events        []runevent.Event
	nextSeq       uint64
	subscribers   map[chan runevent.Event]struct{}
	cancel        context.CancelFunc
	agent         *agent.Agent
	stopRequested bool
	deleted       bool
}

func newTask(id string, createdAt time.Time, request RunRequest, autoAgent *agent.Agent, cancel context.CancelFunc) *Task {
	task := &Task{
		id: id, request: request, status: "running", createdAt: createdAt,
		targetDir: autoAgent.TargetDir, statePath: autoAgent.StatePath,
		stages: map[string]string{}, subscribers: map[chan runevent.Event]struct{}{}, cancel: cancel,
		agent: autoAgent,
	}
	task.resetStages(autoAgent)
	return task
}

func (t *Task) resetStages(autoAgent *agent.Agent) {
	completedRank := stageRanks[string(autoAgent.State.Stage)]
	for _, definition := range stageDefinitionsFor(t.request.TaskKind) {
		status := "pending"
		if stageRanks[definition.id] <= completedRank {
			status = "completed"
		}
		t.stages[definition.id] = status
	}
}

func (t *Task) restart(request RunRequest, autoAgent *agent.Agent, cancel context.CancelFunc) {
	t.mu.Lock()
	t.request = request
	t.status = "running"
	t.err = ""
	t.finishedAt = nil
	t.targetDir = autoAgent.TargetDir
	t.statePath = autoAgent.StatePath
	t.cancel = cancel
	t.agent = autoAgent
	t.stopRequested = false
	t.deleted = false
	t.events = nil
	t.nextSeq = 0
	t.resetStages(autoAgent)
	t.mu.Unlock()
}

func (t *Task) publish(event runevent.Event) {
	t.mu.Lock()
	t.nextSeq++
	event.Sequence = t.nextSeq
	if event.Time.IsZero() {
		event.Time = time.Now()
	}
	if event.Kind == "stage" && event.Stage != "" {
		t.stages[event.Stage] = event.Status
	}
	t.events = append(t.events, event)
	if len(t.events) > 4000 {
		t.events = append([]runevent.Event(nil), t.events[len(t.events)-4000:]...)
	}
	for subscriber := range t.subscribers {
		select {
		case subscriber <- event:
		default:
		}
	}
	t.mu.Unlock()
}

func (t *Task) finish(status, message string, err error) {
	t.publish(runevent.New("run", "", status, "autofuzz", message))
	t.mu.Lock()
	t.status = status
	if status == "failed" && err != nil {
		t.err = err.Error()
	} else {
		t.err = ""
	}
	now := time.Now()
	t.finishedAt = &now
	for subscriber := range t.subscribers {
		close(subscriber)
		delete(t.subscribers, subscriber)
	}
	t.mu.Unlock()
}

func (t *Task) Snapshot() TaskSnapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()
	definitions := stageDefinitionsFor(t.request.TaskKind)
	stages := make([]StageSnapshot, 0, len(definitions))
	for _, definition := range definitions {
		stages = append(stages, StageSnapshot{
			ID: definition.id, Name: definition.name, Owner: definition.owner,
			Status: t.stages[definition.id],
		})
	}
	return TaskSnapshot{
		ID: t.id, Status: t.status, Error: t.err, CreatedAt: t.createdAt,
		FinishedAt: t.finishedAt, TargetDir: t.targetDir, StatePath: t.statePath,
		TaskKind: t.request.TaskKind, ParentTaskID: t.request.ParentTaskID,
		OriginDriverID: t.request.OriginDriverID, OriginDriverSeq: t.request.OriginDriverSeq,
		OriginCrashes:   append([]string(nil), t.request.OriginCrashes...),
		OriginSourceDir: t.request.OriginSourceDir,
		Request:         t.request, Stages: stages,
	}
}

func (t *Task) subscribe(afterSequence uint64, forceLive bool) ([]runevent.Event, <-chan runevent.Event, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	history := make([]runevent.Event, 0, len(t.events))
	for _, event := range t.events {
		if event.Sequence > afterSequence {
			history = append(history, event)
		}
	}
	if t.finishedAt != nil && !forceLive {
		return history, nil, true
	}
	channel := make(chan runevent.Event, 256)
	t.subscribers[channel] = struct{}{}
	return history, channel, false
}

func (t *Task) unsubscribe(channel <-chan runevent.Event) {
	t.mu.Lock()
	for subscriber := range t.subscribers {
		if subscriber == channel {
			delete(t.subscribers, subscriber)
			close(subscriber)
			break
		}
	}
	t.mu.Unlock()
}

func (t *Task) closeSubscribersIfFinished() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.finishedAt == nil {
		return
	}
	for subscriber := range t.subscribers {
		close(subscriber)
		delete(t.subscribers, subscriber)
	}
}

type Manager struct {
	ctx                 context.Context
	mu                  sync.RWMutex
	tasks               map[string]*Task
	activeDir           map[string]string
	counter             atomic.Uint64
	runAgent            func(context.Context, *agent.Agent) error
	crashAnalysisMu     sync.Mutex
	activeCrashAnalysis map[string]bool
}

func NewManager(ctx context.Context) *Manager {
	return &Manager{
		ctx: ctx, tasks: map[string]*Task{}, activeDir: map[string]string{},
		activeCrashAnalysis: map[string]bool{},
		runAgent: func(runContext context.Context, autoAgent *agent.Agent) error {
			return autoAgent.Run(runContext)
		},
	}
}

func (m *Manager) Create(request RunRequest) (*TaskSnapshot, error) {
	if request.RepositoryURL == "" {
		return nil, fmt.Errorf("repository_url cannot be empty")
	}
	autoAgent, err := agent.New(request.options())
	if err != nil {
		return nil, err
	}
	id := fmt.Sprintf("run-%d-%03d", time.Now().Unix(), m.counter.Add(1))
	createdAt := time.Now()
	request = normalizedRunRequest(request, autoAgent.Options)
	entry := registryEntry{
		ID:            id,
		Workspace:     request.Workspace,
		Name:          autoAgent.State.ProjectName,
		RepositoryURL: request.RepositoryURL,
		TaskKind:      request.TaskKind,
		ParentTaskID:  request.ParentTaskID,
		CreatedAt:     createdAt.Format(time.RFC3339),
		UpdatedAt:     createdAt.Format(time.RFC3339),
		Status:        "pending",
		Request:       request,
	}
	if err := upsertTaskRegistry(entry); err != nil {
		return nil, fmt.Errorf("save task: %w", err)
	}
	snapshot := snapshotFromRegistry(entry)
	return &snapshot, nil
}

func (m *Manager) StartTask(id string) (*Task, error) {
	entry, exists := registryEntryByID(id)
	if !exists {
		return nil, fmt.Errorf("task not found")
	}
	status := effectiveRegistryStatus(entry)
	if status != "pending" && status != "stopped" && status != "interrupted" && status != "failed" {
		return nil, fmt.Errorf("task cannot be started from status %s", status)
	}
	request := entry.Request
	if status == "interrupted" || status == "failed" || (status == "stopped" && fileExists(filepath.Join(entry.Workspace, entry.Name, "agent-state.json"))) {
		request.Resume = true
	} else if status == "stopped" {
		request.Resume = false
	}
	autoAgent, err := agent.New(request.options())
	if err != nil {
		return nil, err
	}
	request = normalizedRunRequest(request, autoAgent.Options)
	runContext, cancel := context.WithCancel(m.ctx)
	createdAt, _ := time.Parse(time.RFC3339, entry.CreatedAt)
	if createdAt.IsZero() {
		createdAt = time.Now()
	}

	m.mu.Lock()
	if activeID, active := m.activeDir[autoAgent.TargetDir]; active {
		m.mu.Unlock()
		cancel()
		return nil, fmt.Errorf("target workspace is already running in task %s", activeID)
	}
	task, inMemory := m.tasks[id]
	if inMemory {
		task.mu.RLock()
		currentStatus := task.status
		task.mu.RUnlock()
		if currentStatus == "running" || currentStatus == "stopping" {
			m.mu.Unlock()
			cancel()
			return nil, fmt.Errorf("task is already %s", currentStatus)
		}
		task.restart(request, autoAgent, cancel)
	} else {
		task = newTask(id, createdAt, request, autoAgent, cancel)
		m.tasks[id] = task
	}
	m.activeDir[autoAgent.TargetDir] = id
	m.mu.Unlock()

	entry.Status = "running"
	entry.UpdatedAt = time.Now().Format(time.RFC3339)
	entry.Request = request
	entry.Workspace = request.Workspace
	entry.RepositoryURL = request.RepositoryURL
	entry.TaskKind = request.TaskKind
	entry.ParentTaskID = request.ParentTaskID
	if err := upsertTaskRegistry(entry); err != nil {
		cancel()
		m.mu.Lock()
		delete(m.activeDir, autoAgent.TargetDir)
		m.mu.Unlock()
		return nil, fmt.Errorf("save task: %w", err)
	}

	autoAgent.SetEventSink(task.publish)
	task.publish(runevent.New("run", "", "running", "autofuzz", "Autofuzz 任务已启动"))
	go func() {
		err := m.runAgent(runContext, autoAgent)
		m.finishTask(task, autoAgent.TargetDir, err)
	}()
	return task, nil
}

func (m *Manager) finishTask(task *Task, targetDir string, err error) {
	task.mu.RLock()
	stopRequested := task.stopRequested
	task.mu.RUnlock()
	status := "completed"
	message := "Autofuzz 运行完成"
	if stopRequested {
		status = "stopped"
		message = "Autofuzz 任务已停止"
	} else if m.ctx.Err() != nil {
		status = "interrupted"
		message = "Autofuzz 服务已中断任务"
	} else if err != nil {
		status = "failed"
		message = err.Error()
	}
	task.finish(status, message, err)
	m.mu.Lock()
	delete(m.activeDir, targetDir)
	m.mu.Unlock()
	task.mu.RLock()
	if !task.deleted {
		updateTaskRegistryStatus(task.id, status)
	}
	task.mu.RUnlock()
}

func (m *Manager) Get(id string) (*Task, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	task, exists := m.tasks[id]
	return task, exists
}

func (m *Manager) Cancel(id string) error {
	task, exists := m.Get(id)
	if !exists {
		return fmt.Errorf("task not found")
	}
	task.mu.Lock()
	if task.status != "running" {
		status := task.status
		task.mu.Unlock()
		return fmt.Errorf("task cannot be stopped from status %s", status)
	}
	task.status = "stopping"
	task.stopRequested = true
	cancel := task.cancel
	task.mu.Unlock()
	updateTaskRegistryStatus(id, "stopping")
	task.publish(runevent.New("run", "", "stopping", "autofuzz", "正在停止 Autofuzz 任务"))
	cancel()
	return nil
}

func (m *Manager) TriggerFuzzAnalysis(id string) error {
	task, exists := m.Get(id)
	if !exists {
		return fmt.Errorf("task not found")
	}
	task.mu.RLock()
	status := task.status
	agent := task.agent
	task.mu.RUnlock()
	if status != "running" {
		return fmt.Errorf("task is not running")
	}
	if agent == nil {
		return fmt.Errorf("agent not available")
	}
	if !agent.TriggerFuzzAnalysis() {
		return fmt.Errorf("fuzz analysis is not ready or a trigger is already queued")
	}
	return nil
}

// CoverageData returns the cached coverage snapshot from the task's corpus
// monitor (in-memory), or reads from disk for historical tasks.
func (m *Manager) CoverageData(id string, driverID, seq int) any {
	task, exists := m.Get(id)
	if !exists {
		return historicalCoverageData(id, driverID, seq)
	}
	task.mu.RLock()
	agent := task.agent
	task.mu.RUnlock()
	if agent == nil {
		return nil
	}
	data := agent.CoverageData()
	if driverID > 0 {
		return filterCoverageDataByDriver(data, driverID, seq)
	}
	return data
}

func filterCoverageDataByDriver(data any, driverID, seq int) any {
	multi, ok := data.(fuzzing.MultiCoverageSnapshot)
	if !ok {
		if ptr, ok := data.(*fuzzing.MultiCoverageSnapshot); ok && ptr != nil {
			multi = *ptr
		} else {
			return data
		}
	}
	var selected *fuzzing.TargetCoverageSnapshot
	for index := range multi.Targets {
		target := &multi.Targets[index]
		if target.DriverID != driverID || (seq > 0 && target.Seq != seq) {
			continue
		}
		if selected == nil || target.Seq > selected.Seq {
			selected = target
		}
	}
	if selected != nil {
		return fuzzing.CoverageSnapshot{
			Timestamp: multi.Timestamp,
			Available: selected.Available,
			SeedCount: selected.SeedCount,
			Coverage:  fuzzing.CloneCoverageStatus(selected.Coverage),
		}
	}
	return map[string]any{"available": false}
}

const maxFunctionGraphSourceLines = 80

type FunctionSourceResponse struct {
	DriverID  int                     `json:"driver_id,omitempty"`
	Seq       int                     `json:"seq,omitempty"`
	Available bool                    `json:"available"`
	Functions []FunctionSourceSnippet `json:"functions"`
}

type FunctionSourceSnippet struct {
	Function  string                 `json:"function"`
	File      string                 `json:"file"`
	Coverage  string                 `json:"coverage"`
	StartLine int                    `json:"start_line,omitempty"`
	EndLine   int                    `json:"end_line,omitempty"`
	Source    string                 `json:"source,omitempty"`
	Lines     []FunctionLineCoverage `json:"lines,omitempty"`
	Truncated bool                   `json:"truncated,omitempty"`
	Error     string                 `json:"error,omitempty"`
}

type FunctionLineCoverage struct {
	Line   int    `json:"line"`
	Count  int64  `json:"count"`
	Status string `json:"status"`
}

func (m *Manager) CoverageFunctionSources(id string, driverID, seq int) (FunctionSourceResponse, error) {
	targetDir := m.targetDirFor(id)
	if targetDir == "" {
		return FunctionSourceResponse{}, fmt.Errorf("task not found")
	}
	data := m.CoverageData(id, driverID, seq)
	status, available := coverageStatusFromData(data, driverID)
	if !available {
		return FunctionSourceResponse{DriverID: driverID, Seq: seq, Available: false, Functions: []FunctionSourceSnippet{}}, nil
	}
	roots := coverageSourceRoots(targetDir, driverID)
	out := FunctionSourceResponse{DriverID: driverID, Seq: seq, Available: true, Functions: []FunctionSourceSnippet{}}
	fileCache := map[string][]string{}
	for _, fn := range status.Full {
		snippet := FunctionSourceSnippet{
			Function:  fn.Function,
			File:      fn.File,
			Coverage:  "full",
			StartLine: fn.StartLine,
			EndLine:   fn.EndLine,
		}
		source, truncated, displayEndLine, readErr := readFunctionSource(fn.File, fn.StartLine, fn.EndLine, roots, fileCache)
		snippet.Source = source
		snippet.Truncated = truncated
		snippet.Error = readErr
		snippet.Lines = functionLineCoverage(fn.Regions, nil, fn.StartLine, displayEndLine)
		out.Functions = append(out.Functions, snippet)
	}
	for _, fn := range status.Partial {
		snippet := FunctionSourceSnippet{
			Function:  fn.Function,
			File:      fn.File,
			Coverage:  "partial",
			StartLine: fn.StartLine,
			EndLine:   fn.EndLine,
		}
		source, truncated, displayEndLine, readErr := readFunctionSource(fn.File, fn.StartLine, fn.EndLine, roots, fileCache)
		snippet.Source = source
		snippet.Truncated = truncated
		snippet.Error = readErr
		snippet.Lines = functionLineCoverage(fn.Regions, fn.UncoveredBranches, fn.StartLine, displayEndLine)
		out.Functions = append(out.Functions, snippet)
	}
	sort.SliceStable(out.Functions, func(i, j int) bool {
		if out.Functions[i].File != out.Functions[j].File {
			return out.Functions[i].File < out.Functions[j].File
		}
		if out.Functions[i].StartLine != out.Functions[j].StartLine {
			return out.Functions[i].StartLine < out.Functions[j].StartLine
		}
		return out.Functions[i].Function < out.Functions[j].Function
	})
	return out, nil
}

func (m *Manager) targetDirFor(id string) string {
	if task, exists := m.Get(id); exists {
		task.mu.RLock()
		targetDir := task.targetDir
		task.mu.RUnlock()
		return targetDir
	}
	workspace, name := historicalEntry(id)
	if workspace == "" {
		return ""
	}
	return filepath.Join(workspace, name)
}

func coverageStatusFromData(data any, driverID int) (fuzzing.CoverageStatus, bool) {
	switch v := data.(type) {
	case fuzzing.CoverageSnapshot:
		return v.Coverage, v.Available
	case *fuzzing.CoverageSnapshot:
		if v == nil {
			return fuzzing.CoverageStatus{}, false
		}
		return v.Coverage, v.Available
	case fuzzing.MultiCoverageSnapshot:
		if driverID > 0 {
			for _, target := range v.Targets {
				if target.DriverID == driverID {
					return target.Coverage, target.Available
				}
			}
			return fuzzing.CoverageStatus{}, false
		}
		return v.Coverage, v.Available
	case *fuzzing.MultiCoverageSnapshot:
		if v == nil {
			return fuzzing.CoverageStatus{}, false
		}
		return coverageStatusFromData(*v, driverID)
	case map[string]any:
		available, _ := v["available"].(bool)
		if cov, ok := v["coverage"].(fuzzing.CoverageStatus); ok {
			return cov, available
		}
		return fuzzing.CoverageStatus{}, false
	default:
		return fuzzing.CoverageStatus{}, false
	}
}

func coverageSourceRoots(targetDir string, driverID int) []string {
	sourceDir, buildDir := readStateDirs(filepath.Join(targetDir, "agent-state.json"))
	roots := []string{sourceDir, buildDir, filepath.Join(targetDir, "source"), filepath.Join(targetDir, "build")}
	if driverID > 0 {
		roots = append(roots, filepath.Join(targetDir, "logs", "fuzzing", "driver-targets", fmt.Sprintf("driver-%04d", driverID)))
	} else {
		roots = append(roots, filepath.Join(targetDir, "logs", "fuzzing", "driver-snapshots"))
	}
	return roots
}

func readFunctionSource(path string, startLine, endLine int, allowedRoots []string, fileCache map[string][]string) (string, bool, int, string) {
	if startLine <= 0 || endLine < startLine {
		return "", false, 0, "coverage 中没有该函数的源码行号范围"
	}
	if !isPathUnderAnyRoot(path, allowedRoots) {
		return "", false, 0, "源码路径不在当前 task 允许读取范围内"
	}
	lines, ok := fileCache[path]
	if !ok {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", false, 0, err.Error()
		}
		lines = strings.Split(string(data), "\n")
		fileCache[path] = lines
	}
	if startLine > len(lines) {
		return "", false, 0, "源码行号超出文件范围"
	}
	if endLine > len(lines) {
		endLine = len(lines)
	}
	truncated := false
	if endLine-startLine+1 > maxFunctionGraphSourceLines {
		endLine = startLine + maxFunctionGraphSourceLines - 1
		truncated = true
	}
	return strings.Join(lines[startLine-1:endLine], "\n"), truncated, endLine, ""
}

func functionLineCoverage(regions []fuzzing.CoverageRegion, uncoveredBranches []fuzzing.UncoveredBranch, startLine, endLine int) []FunctionLineCoverage {
	if startLine <= 0 || endLine < startLine {
		return nil
	}
	uncoveredBranchLines := map[int]bool{}
	for _, branch := range uncoveredBranches {
		line := branchDisplayLine(branch)
		if line > 0 {
			uncoveredBranchLines[line] = true
		}
	}
	lines := make([]FunctionLineCoverage, 0, endLine-startLine+1)
	for line := startLine; line <= endLine; line++ {
		status := "unknown"
		var count int64
		if region, ok := mostSpecificRegionForLine(regions, line); ok {
			count = region.Count
			if region.Count > 0 {
				status = "covered"
			} else {
				status = "uncovered"
			}
		}
		if uncoveredBranchLines[line] {
			status = "uncovered"
		}
		lines = append(lines, FunctionLineCoverage{Line: line, Count: count, Status: status})
	}
	return lines
}

func mostSpecificRegionForLine(regions []fuzzing.CoverageRegion, line int) (fuzzing.CoverageRegion, bool) {
	var best fuzzing.CoverageRegion
	bestScore := int64(0)
	found := false
	for _, region := range regions {
		if region.FileID != 0 {
			continue
		}
		if region.Kind == 3 { // LLVM gap region: formatting/spacing between code regions, not executable source.
			continue
		}
		if line < region.StartLine || line > region.EndLine {
			continue
		}
		score := regionSpecificityScore(region)
		if !found || score < bestScore {
			best = region
			bestScore = score
			found = true
		}
	}
	return best, found
}

func branchDisplayLine(branch fuzzing.UncoveredBranch) int {
	if branch.ExpansionLine > 0 {
		return branch.ExpansionLine
	}
	return branch.Location[0]
}

func regionSpecificityScore(region fuzzing.CoverageRegion) int64 {
	lineSpan := region.EndLine - region.StartLine
	if lineSpan < 0 {
		lineSpan = 0
	}
	colSpan := region.EndColumn - region.StartColumn
	if colSpan < 0 {
		colSpan = 0
	}
	return int64(lineSpan)*1_000_000 + int64(colSpan)
}

func isPathUnderAnyRoot(path string, roots []string) bool {
	for _, root := range roots {
		if isPathUnderRoot(path, root) {
			return true
		}
	}
	return false
}

func isPathUnderRoot(path, root string) bool {
	if path == "" || root == "" {
		return false
	}
	abs, err := canonicalWebPath(path)
	if err != nil {
		return false
	}
	absRoot, err := canonicalWebPath(root)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(absRoot, abs)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel))
}

func canonicalWebPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return filepath.Clean(resolved), nil
	}
	return filepath.Clean(abs), nil
}

// SnapshotComparison returns per-snapshot comparison data from the in-memory
// agent, or reads from disk for historical tasks.
func (m *Manager) SnapshotComparison(id string) any {
	task, exists := m.Get(id)
	if !exists {
		return historicalSnapshotComparison(id)
	}
	task.mu.RLock()
	agent := task.agent
	task.mu.RUnlock()
	if agent == nil {
		return nil
	}
	return agent.SnapshotComparison()
}

type CrashReportsResponse struct {
	DriverID    int               `json:"driver_id,omitempty"`
	Seq         int               `json:"seq"`
	SnapshotDir string            `json:"snapshot_dir"`
	Reports     []CrashReportView `json:"reports"`
}

type UniqueCrashesResponse struct {
	Crashes []UniqueCrashView `json:"crashes"`
}

type CrashAnalysisQueueResponse struct {
	Items []CrashAnalysisQueueView `json:"items"`
}

type CrashFixTaskRequest struct {
	DriverID int      `json:"driver_id"`
	Seq      int      `json:"seq"`
	Crashes  []string `json:"crashes"`
}

type UniqueCrashDeleteRequest struct {
	Crashes []UniqueCrashDeleteRef `json:"crashes"`
}

type UniqueCrashDeleteRef struct {
	DriverID int    `json:"driver_id,omitempty"`
	Seq      int    `json:"seq"`
	File     string `json:"file"`
}

type UniqueCrashDeleteResponse struct {
	Deleted int `json:"deleted"`
}

type CrashAnalysisQueueView struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	Position    int    `json:"position"`
	DriverID    int    `json:"driver_id,omitempty"`
	Seq         int    `json:"seq"`
	SnapshotDir string `json:"snapshot_dir"`
	File        string `json:"file"`
	Type        string `json:"type,omitempty"`
	QueuedAt    string `json:"queued_at,omitempty"`
	StartedAt   string `json:"started_at,omitempty"`
	Removable   bool   `json:"removable"`
}

type UniqueCrashView struct {
	DriverID       int                        `json:"driver_id,omitempty"`
	Seq            int                        `json:"seq"`
	SnapshotDir    string                     `json:"snapshot_dir"`
	CrashCreatedAt string                     `json:"crash_created_at,omitempty"`
	LastAnalysisAt string                     `json:"last_analysis_at,omitempty"`
	Entry          fuzzing.CrashAnalysisEntry `json:"entry"`
}

type CrashReportView struct {
	Entry  fuzzing.CrashAnalysisEntry `json:"entry"`
	Report json.RawMessage            `json:"report,omitempty"`
	Error  string                     `json:"error,omitempty"`
}

func (m *Manager) CrashAnalysisQueue(id string) (CrashAnalysisQueueResponse, error) {
	targetDir := m.targetDirFor(id)
	if targetDir == "" {
		return CrashAnalysisQueueResponse{}, fmt.Errorf("task not found")
	}
	logRoot := filepath.Join(targetDir, "logs", "fuzzing")
	result := CrashAnalysisQueueResponse{Items: []CrashAnalysisQueueView{}}
	for _, item := range fuzzing.CrashAnalysisQueueSnapshot() {
		if !isPathUnderRoot(item.SnapshotDir, logRoot) {
			continue
		}
		driverID, seq := crashAnalysisSnapshotIdentity(logRoot, item.SnapshotDir)
		view := CrashAnalysisQueueView{
			ID:          item.ID,
			Status:      item.Status,
			Position:    item.Position,
			DriverID:    driverID,
			Seq:         seq,
			SnapshotDir: item.SnapshotDir,
			File:        item.File,
			Type:        item.Type,
			Removable:   item.Status == "queued",
		}
		if !item.QueuedAt.IsZero() {
			view.QueuedAt = item.QueuedAt.Format(time.RFC3339)
		}
		if !item.StartedAt.IsZero() {
			view.StartedAt = item.StartedAt.Format(time.RFC3339)
		}
		result.Items = append(result.Items, view)
	}
	return result, nil
}

func (m *Manager) RemoveCrashAnalysisQueueItem(id, itemID string) error {
	targetDir := m.targetDirFor(id)
	if targetDir == "" {
		return fmt.Errorf("task not found")
	}
	itemID = strings.TrimSpace(itemID)
	if itemID == "" {
		return fmt.Errorf("missing queue item id")
	}
	logRoot := filepath.Join(targetDir, "logs", "fuzzing")
	found := false
	for _, item := range fuzzing.CrashAnalysisQueueSnapshot() {
		if item.ID != itemID || !isPathUnderRoot(item.SnapshotDir, logRoot) {
			continue
		}
		found = true
		if item.Status == "running" {
			return fmt.Errorf("crash analysis is already running")
		}
		break
	}
	if !found {
		return fmt.Errorf("queue item not found")
	}
	removed, err := fuzzing.RemoveQueuedCrashAnalysis(itemID)
	if err != nil {
		return err
	}
	if !removed {
		return fmt.Errorf("queue item not found or already running")
	}
	return nil
}

func (m *Manager) UniqueCrashes(id string) (UniqueCrashesResponse, error) {
	targetDir := m.targetDirFor(id)
	if targetDir == "" {
		return UniqueCrashesResponse{}, fmt.Errorf("task not found")
	}
	logRoot := filepath.Join(targetDir, "logs", "fuzzing")
	result := UniqueCrashesResponse{Crashes: []UniqueCrashView{}}
	for _, snap := range crashAnalysisSnapshots(logRoot) {
		if !isPathUnderRoot(snap.dir, logRoot) {
			continue
		}
		entries := readCrashAnalysisEntries(filepath.Join(snap.dir, "crash-analysis.json"))
		for _, entry := range entries {
			normalizeCrashReportEntryForDisplayInSnapshot(snap.dir, &entry)
			result.Crashes = append(result.Crashes, UniqueCrashView{
				DriverID:       snap.driverID,
				Seq:            snap.seq,
				SnapshotDir:    snap.dir,
				CrashCreatedAt: crashArtifactTime(snap.dir, entry),
				LastAnalysisAt: crashLastAnalysisTime(snap.dir, entry),
				Entry:          entry,
			})
		}
	}
	sort.SliceStable(result.Crashes, func(i, j int) bool {
		a, b := result.Crashes[i], result.Crashes[j]
		if a.DriverID != b.DriverID {
			return a.DriverID < b.DriverID
		}
		if a.Seq != b.Seq {
			return a.Seq < b.Seq
		}
		return a.Entry.File < b.Entry.File
	})
	return result, nil
}

func (m *Manager) DeleteUniqueCrashes(id string, input UniqueCrashDeleteRequest) (UniqueCrashDeleteResponse, error) {
	targetDir := m.targetDirFor(id)
	if targetDir == "" {
		return UniqueCrashDeleteResponse{}, fmt.Errorf("task not found")
	}
	if len(input.Crashes) == 0 {
		return UniqueCrashDeleteResponse{}, fmt.Errorf("no unique crash selected")
	}
	if len(input.Crashes) > 256 {
		return UniqueCrashDeleteResponse{}, fmt.Errorf("at most 256 unique crashes can be deleted at once")
	}
	logRoot := filepath.Join(targetDir, "logs", "fuzzing")
	bySnapshot := map[string][]string{}
	for _, crash := range input.Crashes {
		if crash.Seq <= 0 {
			return UniqueCrashDeleteResponse{}, fmt.Errorf("invalid snapshot version")
		}
		file := cleanUniqueCrashFile(crash.File)
		if file == "" {
			return UniqueCrashDeleteResponse{}, fmt.Errorf("invalid crash file")
		}
		snapDir := crashReportSnapshotDir(targetDir, crash.DriverID, crash.Seq)
		if !isPathUnderRoot(snapDir, logRoot) {
			return UniqueCrashDeleteResponse{}, fmt.Errorf("snapshot path escapes task logs")
		}
		bySnapshot[snapDir] = append(bySnapshot[snapDir], file)
	}

	result := UniqueCrashDeleteResponse{}
	for snapDir, files := range bySnapshot {
		deleted, err := deleteUniqueCrashesFromSnapshot(snapDir, files)
		if err != nil {
			return result, err
		}
		result.Deleted += deleted
	}
	return result, nil
}

func cleanUniqueCrashFile(file string) string {
	name := filepath.Base(strings.TrimSpace(file))
	if name == "" || name == "." || name == string(filepath.Separator) {
		return ""
	}
	return name
}

func deleteUniqueCrashesFromSnapshot(snapDir string, files []string) (int, error) {
	selected := map[string]bool{}
	for _, file := range files {
		name := cleanUniqueCrashFile(file)
		if name != "" {
			selected[name] = true
		}
	}
	if len(selected) == 0 {
		return 0, fmt.Errorf("no unique crash selected")
	}
	path := filepath.Join(snapDir, "crash-analysis.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Errorf("snapshot has no crash analysis")
		}
		return 0, err
	}
	var analysis crashAnalysisJSON
	if err := json.Unmarshal(data, &analysis); err != nil {
		return 0, err
	}
	filtered := make([]fuzzing.CrashAnalysisEntry, 0, len(analysis.List))
	deletedEntries := make([]fuzzing.CrashAnalysisEntry, 0, len(selected))
	deletedFiles := make([]string, 0, len(selected))
	for _, entry := range analysis.List {
		file := cleanUniqueCrashFile(entry.File)
		if file == "" || !selected[file] {
			filtered = append(filtered, entry)
			continue
		}
		if fuzzing.IsCrashAnalysisQueuedOrRunning(fuzzing.CrashAnalysisJobKey(snapDir, file)) {
			return 0, fmt.Errorf("unique crash %s is queued or running crash analysis", file)
		}
		deletedEntries = append(deletedEntries, entry)
		deletedFiles = append(deletedFiles, file)
	}
	if len(deletedEntries) == 0 {
		return 0, fmt.Errorf("unique crash not found")
	}
	analysis.List = filtered
	analysis.Unique = len(filtered)
	if !fuzzing.DeleteLiveUniqueCrashes(snapDir, deletedFiles) {
		if err := writeCrashAnalysisJSON(path, analysis); err != nil {
			return 0, err
		}
	}
	cleanupUniqueCrashArtifacts(snapDir, deletedEntries)
	return len(deletedEntries), nil
}

func cleanupUniqueCrashArtifacts(snapDir string, entries []fuzzing.CrashAnalysisEntry) {
	for _, entry := range entries {
		file := cleanUniqueCrashFile(entry.File)
		removeSnapshotSubdirFile(snapDir, "unique_crashes", entry.UniquePath)
		if file != "" {
			removeSnapshotSubdirFile(snapDir, "unique_crashes", filepath.Join("unique_crashes", file))
			removeSnapshotSubdirFile(snapDir, "crash-reports", filepath.Join("crash-reports", safeWebCrashReportName(file)+".json"))
		}
		removeSnapshotSubdirFile(snapDir, "crash-reports", entry.ReportPath)
	}
}

func removeSnapshotSubdirFile(snapDir, subdir, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	root := filepath.Join(snapDir, subdir)
	path := value
	if !filepath.IsAbs(path) {
		path = filepath.Join(snapDir, filepath.FromSlash(value))
	}
	if !isPathUnderRoot(path, root) {
		return
	}
	_ = os.Remove(path)
}

func (m *Manager) CrashReports(id string, driverID, seq int) (CrashReportsResponse, error) {
	targetDir := m.targetDirFor(id)
	if targetDir == "" {
		return CrashReportsResponse{}, fmt.Errorf("task not found")
	}
	snapDir := crashReportSnapshotDir(targetDir, driverID, seq)
	logRoot := filepath.Join(targetDir, "logs", "fuzzing")
	if !isPathUnderRoot(snapDir, logRoot) {
		return CrashReportsResponse{}, fmt.Errorf("snapshot path escapes task logs")
	}
	info, err := os.Stat(snapDir)
	if err != nil || !info.IsDir() {
		return CrashReportsResponse{}, fmt.Errorf("snapshot not found")
	}
	result := CrashReportsResponse{
		DriverID:    driverID,
		Seq:         seq,
		SnapshotDir: snapDir,
		Reports:     []CrashReportView{},
	}
	data, err := os.ReadFile(filepath.Join(snapDir, "crash-analysis.json"))
	if err != nil {
		return result, nil
	}
	analysis, ok := decodeCrashAnalysisEntries(data)
	if !ok {
		return result, nil
	}
	for _, entry := range analysis {
		normalizeCrashReportEntryForDisplayInSnapshot(snapDir, &entry)
		view := CrashReportView{Entry: entry}
		if entry.ReportPath != "" {
			reportPath := entry.ReportPath
			if !filepath.IsAbs(reportPath) {
				reportPath = filepath.Join(snapDir, filepath.FromSlash(reportPath))
			}
			if isPathUnderRoot(reportPath, snapDir) {
				if reportData, err := os.ReadFile(reportPath); err == nil && json.Valid(reportData) {
					view.Report = append(json.RawMessage(nil), reportData...)
				} else if err != nil && !os.IsNotExist(err) {
					view.Error = err.Error()
				}
			} else {
				view.Error = "report path escapes snapshot"
			}
		}
		result.Reports = append(result.Reports, view)
	}
	return result, nil
}

func normalizeCrashReportEntryForDisplay(entry *fuzzing.CrashAnalysisEntry) {
	if entry == nil {
		return
	}
	fuzzing.NormalizeCrashAnalysisEntryType(entry)
	if fuzzing.ShouldSkipCrashLLMAnalysis(*entry) && entry.ReportStatus != "completed" {
		entry.ReportStatus = "skipped"
		if entry.ReportError == "" {
			entry.ReportError = "LLM crash analysis skipped for timeout/slowunit unique crash"
		}
		return
	}
	if entry.ReportStatus == "" {
		if entry.ReportPath != "" {
			entry.ReportStatus = "completed"
		} else {
			entry.ReportStatus = "pending"
		}
	}
}

func normalizeCrashReportEntryForDisplayInSnapshot(snapDir string, entry *fuzzing.CrashAnalysisEntry) {
	normalizeCrashReportEntryForDisplay(entry)
	if entry == nil || snapDir == "" {
		return
	}
	reportPath := crashReportPathForEntry(snapDir, *entry)
	switch entry.ReportStatus {
	case "queued", "running":
		if fuzzing.IsCrashAnalysisQueuedOrRunning(fuzzing.CrashAnalysisJobKey(snapDir, entry.File)) {
			return
		}
		if reportPath != "" && fileExists(reportPath) {
			entry.ReportStatus = "completed"
			entry.ReportError = ""
			fillCrashEntryFromReport(reportPath, entry)
			return
		}
		entry.ReportStatus = "failed"
		if entry.ReportError == "" {
			entry.ReportError = "LLM crash analysis was interrupted or service restarted; no active analysis worker found"
		}
	case "pending":
		if reportPath != "" && fileExists(reportPath) {
			entry.ReportStatus = "completed"
			entry.ReportError = ""
			fillCrashEntryFromReport(reportPath, entry)
		}
	case "completed":
		if reportPath != "" && fileExists(reportPath) {
			fillCrashEntryFromReport(reportPath, entry)
		}
	}
}

func crashReportPathForEntry(snapDir string, entry fuzzing.CrashAnalysisEntry) string {
	if entry.ReportPath == "" {
		return ""
	}
	reportPath := entry.ReportPath
	if !filepath.IsAbs(reportPath) {
		reportPath = filepath.Join(snapDir, filepath.FromSlash(reportPath))
	}
	if !isPathUnderRoot(reportPath, snapDir) {
		return ""
	}
	return reportPath
}

func crashArtifactTime(snapDir string, entry fuzzing.CrashAnalysisEntry) string {
	for _, path := range crashArtifactCandidates(snapDir, entry) {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return info.ModTime().Format(time.RFC3339)
		}
	}
	return ""
}

func crashArtifactCandidates(snapDir string, entry fuzzing.CrashAnalysisEntry) []string {
	var candidates []string
	add := func(path string) {
		if path == "" {
			return
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(snapDir, filepath.FromSlash(path))
		}
		if !isPathUnderRoot(path, snapDir) {
			return
		}
		for _, existing := range candidates {
			if existing == path {
				return
			}
		}
		candidates = append(candidates, path)
	}
	file := filepath.Base(strings.TrimSpace(entry.File))
	if file != "" && file != "." && file != string(filepath.Separator) {
		add(filepath.Join("crashes", file))
		add(filepath.Join("unique_crashes", file))
	}
	add(entry.UniquePath)
	return candidates
}

func crashLastAnalysisTime(snapDir string, entry fuzzing.CrashAnalysisEntry) string {
	switch entry.ReportStatus {
	case "completed":
		if reportPath := crashReportPathForEntry(snapDir, entry); reportPath != "" {
			if info, err := os.Stat(reportPath); err == nil && !info.IsDir() {
				return info.ModTime().Format(time.RFC3339)
			}
		}
		return entry.ReportUpdatedAt
	case "queued", "running", "failed":
		return entry.ReportUpdatedAt
	default:
		return ""
	}
}

func fillCrashEntryFromReport(reportPath string, entry *fuzzing.CrashAnalysisEntry) {
	if entry == nil {
		return
	}
	data, err := os.ReadFile(reportPath)
	if err != nil || !json.Valid(data) {
		return
	}
	var envelope struct {
		Report struct {
			Classification string `json:"classification"`
			ASanReport     string `json:"asan_report"`
		} `json:"report"`
		Entry fuzzing.CrashAnalysisEntry `json:"entry"`
	}
	if json.Unmarshal(data, &envelope) != nil {
		return
	}
	if entry.Classification == "" {
		if envelope.Report.Classification != "" {
			entry.Classification = envelope.Report.Classification
		} else if envelope.Entry.Classification != "" {
			entry.Classification = envelope.Entry.Classification
		}
	}
	if entry.ASanReport == "" {
		if envelope.Report.ASanReport != "" {
			entry.ASanReport = envelope.Report.ASanReport
		} else if envelope.Entry.ASanReport != "" {
			entry.ASanReport = envelope.Entry.ASanReport
		}
	}
}

func (m *Manager) TriggerCrashReportAnalysis(id string, driverID, seq int, crashFile string) error {
	targetDir := m.targetDirFor(id)
	if targetDir == "" {
		return fmt.Errorf("task not found")
	}
	crashFile = filepath.Base(crashFile)
	if crashFile == "." || crashFile == string(filepath.Separator) || strings.TrimSpace(crashFile) == "" {
		return fmt.Errorf("invalid crash file")
	}
	snapDir := crashReportSnapshotDir(targetDir, driverID, seq)
	logRoot := filepath.Join(targetDir, "logs", "fuzzing")
	if !isPathUnderRoot(snapDir, logRoot) {
		return fmt.Errorf("snapshot path escapes task logs")
	}
	info, err := os.Stat(snapDir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("snapshot not found")
	}
	analysis, entry, err := updateCrashAnalysisEntry(snapDir, crashFile, func(entry *fuzzing.CrashAnalysisEntry) error {
		normalizeCrashReportEntryForDisplay(entry)
		if fuzzing.ShouldSkipCrashLLMAnalysis(*entry) {
			return fmt.Errorf("timeout/slowunit crash analysis is skipped")
		}
		if entry.UniquePath == "" {
			entry.UniquePath = filepath.ToSlash(filepath.Join("unique_crashes", filepath.Base(entry.File)))
		}
		if entry.ReportPath == "" {
			entry.ReportPath = filepath.ToSlash(filepath.Join("crash-reports", safeWebCrashReportName(entry.File)+".json"))
		}
		return nil
	})
	if err != nil {
		return err
	}
	_ = analysis
	request := m.requestFor(id)
	m.ensureManualEventTask(id, targetDir, request)
	runState, err := state.Load(filepath.Join(targetDir, "agent-state.json"))
	if err != nil {
		_, _, _ = updateCrashAnalysisEntry(snapDir, crashFile, func(entry *fuzzing.CrashAnalysisEntry) error {
			entry.ReportStatus = "failed"
			entry.ReportError = "load task state: " + err.Error()
			entry.ReportUpdatedAt = time.Now().Format(time.RFC3339)
			return nil
		})
		return fmt.Errorf("load task state: %w", err)
	}
	crashFile = filepath.Base(entry.File)
	cfg := fuzzing.FuzzConfig{
		SourceDir:    runState.SourceDir,
		BinaryPath:   snapshotCrashBinary(snapDir),
		CodexCommand: request.CodexCommand,
		CodexModel:   request.CodexModel,
		CodexProfile: request.CodexProfile,
		Runner:       runner.Runner{Verbose: request.Verbose},
		LogsDir:      filepath.Join(filepath.Dir(filepath.Dir(snapDir)), "manual-crash-analysis"),
		EventSink:    m.taskCodexEventSink(id),
		LogSink:      m.taskLogSink(id),
	}
	if cfg.CodexCommand == "" {
		cfg.CodexCommand = DefaultRunRequest().CodexCommand
	}

	webKey := fmt.Sprintf("%s/%d/%d/%s", id, driverID, seq, crashFile)
	m.crashAnalysisMu.Lock()
	if m.activeCrashAnalysis[webKey] {
		m.crashAnalysisMu.Unlock()
		return fmt.Errorf("crash analysis is already queued or running")
	}
	m.activeCrashAnalysis[webKey] = true
	m.crashAnalysisMu.Unlock()

	clearActive := func() {
		m.crashAnalysisMu.Lock()
		delete(m.activeCrashAnalysis, webKey)
		m.crashAnalysisMu.Unlock()
		m.closeFinishedTaskSubscribers(id)
	}
	queued, err := fuzzing.EnqueueCrashAnalysis(m.ctx, fuzzing.CrashAnalysisJob{
		Key:         fuzzing.CrashAnalysisJobKey(snapDir, crashFile),
		Config:      cfg,
		SnapshotDir: snapDir,
		Entry:       entry,
		OnQueued: func() {
			_, _, _ = updateCrashAnalysisEntry(snapDir, crashFile, func(entry *fuzzing.CrashAnalysisEntry) error {
				entry.ReportStatus = "queued"
				entry.ReportError = ""
				entry.ReportUpdatedAt = time.Now().Format(time.RFC3339)
				return nil
			})
			m.taskLogSink(id)("crash analysis queued: " + crashFile)
		},
		OnStart: func() {
			_, _, _ = updateCrashAnalysisEntry(snapDir, crashFile, func(entry *fuzzing.CrashAnalysisEntry) error {
				entry.ReportStatus = "running"
				entry.ReportError = ""
				entry.ReportUpdatedAt = time.Now().Format(time.RFC3339)
				return nil
			})
			m.taskLogSink(id)("crash analysis started: " + crashFile)
		},
		OnComplete: func(report fuzzing.CrashLLMReport) {
			_, _, _ = updateCrashAnalysisEntry(snapDir, crashFile, func(entry *fuzzing.CrashAnalysisEntry) error {
				entry.ReportStatus = "completed"
				entry.ReportError = ""
				entry.ReportUpdatedAt = time.Now().Format(time.RFC3339)
				entry.Classification = report.Classification
				return nil
			})
			m.taskLogSink(id)("crash analysis completed: " + crashFile)
		},
		OnError: func(err error) {
			_, _, _ = updateCrashAnalysisEntry(snapDir, crashFile, func(entry *fuzzing.CrashAnalysisEntry) error {
				entry.ReportStatus = "failed"
				entry.ReportError = err.Error()
				entry.ReportUpdatedAt = time.Now().Format(time.RFC3339)
				return nil
			})
			m.taskLogSink(id)("crash analysis failed: " + err.Error())
		},
		OnCancel: func() {
			_, _, _ = updateCrashAnalysisEntry(snapDir, crashFile, func(entry *fuzzing.CrashAnalysisEntry) error {
				entry.ReportStatus = "pending"
				entry.ReportError = ""
				entry.ReportUpdatedAt = time.Now().Format(time.RFC3339)
				return nil
			})
			m.taskLogSink(id)("crash analysis removed from queue: " + crashFile)
		},
		OnDone: clearActive,
	})
	if err != nil {
		clearActive()
		return err
	}
	if !queued {
		clearActive()
		return fmt.Errorf("crash analysis is already queued or running")
	}
	return nil
}

func (m *Manager) CreateCrashFixTask(id string, input CrashFixTaskRequest) (*TaskSnapshot, error) {
	if input.DriverID <= 0 || input.Seq <= 0 {
		return nil, fmt.Errorf("driver_id and seq are required")
	}
	if len(input.Crashes) == 0 {
		return nil, fmt.Errorf("at least one crash file is required")
	}
	if len(input.Crashes) > 8 {
		return nil, fmt.Errorf("at most 8 crashes can be fixed in one child task")
	}
	parentEntry, exists := registryEntryByID(id)
	if !exists {
		return nil, fmt.Errorf("parent task not found")
	}
	parentTargetDir := filepath.Join(parentEntry.Workspace, parentEntry.Name)
	parentState, err := state.Load(filepath.Join(parentTargetDir, "agent-state.json"))
	if err != nil {
		return nil, fmt.Errorf("load parent task state: %w", err)
	}
	if strings.TrimSpace(parentState.SourceDir) == "" {
		return nil, fmt.Errorf("parent task source directory is empty")
	}
	snapDir := crashReportSnapshotDir(parentTargetDir, input.DriverID, input.Seq)
	logRoot := filepath.Join(parentTargetDir, "logs", "fuzzing")
	if !isPathUnderRoot(snapDir, logRoot) {
		return nil, fmt.Errorf("snapshot path escapes task logs")
	}
	if info, err := os.Stat(snapDir); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("snapshot not found")
	}
	crashes, contextText, err := crashFixContextForSelection(parentEntry, parentState, snapDir, input)
	if err != nil {
		return nil, err
	}

	childName := safeTaskName(fmt.Sprintf("%s-fix-d%d-v%d-%d", parentEntry.Name, input.DriverID, input.Seq, time.Now().UnixNano()))
	request := parentEntry.Request
	if request.Workspace == "" {
		request.Workspace = parentEntry.Workspace
	}
	request.RepositoryURL = parentState.SourceDir
	request.Ref = ""
	request.Name = childName
	request.Resume = false
	request.StopAfter = string(state.StageFuzzing)
	request.MaxFuzzDrivers = 1
	request.TaskKind = "crash_fix_child"
	request.ParentTaskID = id
	request.OriginDriverID = input.DriverID
	request.OriginDriverSeq = input.Seq
	request.OriginCrashes = crashes
	request.OriginSnapshotDir = snapDir
	request.OriginSourceDir = parentState.SourceDir
	request.OriginBuildDir = parentState.BuildDir
	request.OriginInstallDir = parentState.InstallDir
	request.OriginStaticLibraries = append([]string(nil), parentState.StaticLibraries...)
	request.CrashFixContext = contextText

	snapshot, err := m.Create(request)
	if err != nil {
		return nil, err
	}
	task, err := m.StartTask(snapshot.ID)
	if err != nil {
		return snapshot, err
	}
	out := task.Snapshot()
	return &out, nil
}

func (m *Manager) requestFor(id string) RunRequest {
	if task, exists := m.Get(id); exists {
		task.mu.RLock()
		request := task.request
		task.mu.RUnlock()
		return request
	}
	if entry, exists := registryEntryByID(id); exists {
		return entry.Request
	}
	return DefaultRunRequest()
}

func (m *Manager) ensureManualEventTask(id, targetDir string, request RunRequest) {
	m.mu.Lock()
	if _, exists := m.tasks[id]; exists {
		m.mu.Unlock()
		return
	}
	entry, exists := registryEntryByID(id)
	if !exists {
		m.mu.Unlock()
		return
	}
	snapshot := snapshotFromRegistry(entry)
	stages := map[string]string{}
	for _, stage := range snapshot.Stages {
		stages[stage.ID] = stage.Status
	}
	finishedAt := time.Now()
	m.tasks[id] = &Task{
		id:          id,
		request:     request,
		status:      snapshot.Status,
		createdAt:   snapshot.CreatedAt,
		finishedAt:  &finishedAt,
		targetDir:   targetDir,
		statePath:   snapshot.StatePath,
		stages:      stages,
		subscribers: map[chan runevent.Event]struct{}{},
	}
	m.mu.Unlock()
}

func (m *Manager) taskLogSink(taskID string) func(string) {
	return func(message string) {
		task, exists := m.Get(taskID)
		if !exists {
			return
		}
		task.publish(runevent.New("log", string(state.StageFuzzing), "running", "crash-analysis", message))
	}
}

func (m *Manager) taskCodexEventSink(taskID string) func(json.RawMessage) {
	return func(raw json.RawMessage) {
		task, exists := m.Get(taskID)
		if !exists {
			return
		}
		message := "Codex crash analysis event"
		var envelope struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &envelope) == nil && envelope.Type != "" {
			message = envelope.Type
		}
		event := runevent.New("codex", string(state.StageFuzzing), "", "codex-cli", message)
		event.Data = append(json.RawMessage(nil), raw...)
		task.publish(event)
	}
}

func (m *Manager) hasActiveCrashAnalysis(taskID string) bool {
	prefix := taskID + "/"
	m.crashAnalysisMu.Lock()
	defer m.crashAnalysisMu.Unlock()
	for key := range m.activeCrashAnalysis {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

func (m *Manager) closeFinishedTaskSubscribers(taskID string) {
	task, exists := m.Get(taskID)
	if !exists {
		return
	}
	task.closeSubscribersIfFinished()
}

func snapshotCrashBinary(snapDir string) string {
	for _, name := range []string{"cov_driver", "cov_synthesized_driver"} {
		path := filepath.Join(snapDir, name)
		if fileExists(path) {
			return path
		}
	}
	return filepath.Join(snapDir, "cov_driver")
}

type crashAnalysisJSON struct {
	Total  int                          `json:"total_crashes"`
	Unique int                          `json:"unique_crashes"`
	List   []fuzzing.CrashAnalysisEntry `json:"unique_list"`
}

func updateCrashAnalysisEntry(snapDir, crashFile string, update func(*fuzzing.CrashAnalysisEntry) error) (crashAnalysisJSON, fuzzing.CrashAnalysisEntry, error) {
	path := filepath.Join(snapDir, "crash-analysis.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return crashAnalysisJSON{}, fuzzing.CrashAnalysisEntry{}, err
	}
	var analysis crashAnalysisJSON
	if err := json.Unmarshal(data, &analysis); err != nil {
		return crashAnalysisJSON{}, fuzzing.CrashAnalysisEntry{}, err
	}
	for i := range analysis.List {
		if analysis.List[i].File != crashFile {
			continue
		}
		if err := update(&analysis.List[i]); err != nil {
			return analysis, analysis.List[i], err
		}
		if err := writeCrashAnalysisJSON(path, analysis); err != nil {
			return analysis, analysis.List[i], err
		}
		return analysis, analysis.List[i], nil
	}
	return analysis, fuzzing.CrashAnalysisEntry{}, fmt.Errorf("unique crash not found")
}

func writeCrashAnalysisJSON(path string, analysis crashAnalysisJSON) error {
	out, err := json.MarshalIndent(analysis, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
}

func safeWebCrashReportName(name string) string {
	name = filepath.Base(name)
	var b strings.Builder
	for _, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' {
			b.WriteRune(ch)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if strings.Trim(out, "._-") == "" {
		return "crash"
	}
	return out
}

func safeTaskName(name string) string {
	name = strings.TrimSpace(name)
	var b strings.Builder
	for _, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			b.WriteRune(ch)
		} else {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-_")
	if len(out) > 96 {
		out = strings.Trim(out[:96], "-_")
	}
	if out == "" {
		return fmt.Sprintf("crash-fix-%d", time.Now().Unix())
	}
	return out
}

func crashFixContextForSelection(parent registryEntry, runState *state.RunState, snapDir string, input CrashFixTaskRequest) ([]string, string, error) {
	entries := readCrashAnalysisEntries(filepath.Join(snapDir, "crash-analysis.json"))
	if len(entries) == 0 {
		return nil, "", fmt.Errorf("snapshot has no unique crash analysis entries")
	}
	byFile := map[string]fuzzing.CrashAnalysisEntry{}
	for _, entry := range entries {
		normalizeCrashReportEntryForDisplayInSnapshot(snapDir, &entry)
		if entry.File == "" {
			continue
		}
		byFile[entry.File] = entry
		byFile[filepath.Base(entry.File)] = entry
	}

	seen := map[string]bool{}
	crashes := make([]string, 0, len(input.Crashes))
	var builder strings.Builder
	fmt.Fprintf(&builder, "父 task ID: %s\n", parent.ID)
	fmt.Fprintf(&builder, "父 task 名称: %s\n", parent.Name)
	fmt.Fprintf(&builder, "父源码目录: %s\n", runState.SourceDir)
	fmt.Fprintf(&builder, "发现 crash 的子 driver: d%d/v%d\n", input.DriverID, input.Seq)
	fmt.Fprintf(&builder, "父 snapshot: %s\n\n", snapDir)

	if driverSource, err := findSnapshotDriverSource(snapDir, input.DriverID); err == nil {
		if data, readErr := os.ReadFile(driverSource); readErr == nil {
			fmt.Fprintf(&builder, "## 发现该 crash 的 fuzz driver\n路径: %s\n\n```c\n%s\n```\n\n", driverSource, trimForPrompt(string(data), 12000))
		}
	}

	for _, raw := range input.Crashes {
		file := filepath.Base(strings.TrimSpace(raw))
		if file == "" || file == "." || file == string(filepath.Separator) {
			return nil, "", fmt.Errorf("invalid crash file")
		}
		if seen[file] {
			continue
		}
		entry, exists := byFile[file]
		if !exists {
			return nil, "", fmt.Errorf("unique crash %s not found in selected snapshot", file)
		}
		if !isOOBCrashType(entry.Type) {
			return nil, "", fmt.Errorf("unique crash %s is not an OOB crash: %s", file, entry.Type)
		}
		if entry.ReportStatus != "completed" {
			return nil, "", fmt.Errorf("unique crash %s has not completed LLM analysis", file)
		}
		if entry.Classification != "library_bug" {
			return nil, "", fmt.Errorf("unique crash %s is classified as %s, not library_bug", file, entry.Classification)
		}
		seen[file] = true
		crashes = append(crashes, file)
		entryJSON, _ := json.MarshalIndent(entry, "", "  ")
		fmt.Fprintf(&builder, "## 选中的 unique crash: %s\n", file)
		if len(entryJSON) > 0 {
			fmt.Fprintf(&builder, "crash-analysis 条目:\n```json\n%s\n```\n", trimForPrompt(string(entryJSON), 8000))
		}
		if entry.ASanReport != "" {
			fmt.Fprintf(&builder, "\nASan/UBSan 报告摘要:\n```text\n%s\n```\n", trimForPrompt(entry.ASanReport, 16000))
		}
		if reportPath := crashReportPathForEntry(snapDir, entry); reportPath != "" {
			if reportData, err := os.ReadFile(reportPath); err == nil && len(reportData) > 0 {
				fmt.Fprintf(&builder, "\nLLM crash 分析报告 (%s):\n```json\n%s\n```\n", reportPath, trimForPrompt(string(reportData), 20000))
			}
		}
		builder.WriteString("\n")
	}
	if len(crashes) == 0 {
		return nil, "", fmt.Errorf("no valid unique crash selected")
	}
	return crashes, builder.String(), nil
}

func findSnapshotDriverSource(snapDir string, driverID int) (string, error) {
	if driverID <= 0 {
		return "", fmt.Errorf("driver id is required")
	}
	for _, ext := range []string{".c", ".cc", ".cpp", ".cxx"} {
		path := filepath.Join(snapDir, "driver", fmt.Sprintf("fuzz_driver_%d%s", driverID, ext))
		if fileExists(path) {
			return path, nil
		}
	}
	matches, _ := filepath.Glob(filepath.Join(snapDir, "driver", "fuzz_driver_*"))
	sort.Strings(matches)
	for _, path := range matches {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, nil
		}
	}
	return "", fmt.Errorf("driver source not found")
}

func isOOBCrashType(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return false
	}
	for _, marker := range []string{
		"heap-buffer-overflow",
		"stack-buffer-overflow",
		"global-buffer-overflow",
		"dynamic-stack-buffer-overflow",
		"container-overflow",
		"out-of-bounds",
		"index-out-of-bounds",
		"oob",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func trimForPrompt(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	suffix := "\n\n[truncated]\n"
	keep := limit - len(suffix)
	if keep < 0 {
		keep = limit
		suffix = ""
	}
	return value[:keep] + suffix
}

type crashAnalysisSnapshot struct {
	driverID int
	seq      int
	dir      string
}

func crashAnalysisSnapshots(logRoot string) []crashAnalysisSnapshot {
	var snapshots []crashAnalysisSnapshot
	legacyRoot := filepath.Join(logRoot, "driver-snapshots")
	if entries, err := os.ReadDir(legacyRoot); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			seq := parseLegacySnapshotVersion(entry.Name())
			if seq <= 0 {
				continue
			}
			snapshots = append(snapshots, crashAnalysisSnapshot{
				seq: seq,
				dir: filepath.Join(legacyRoot, entry.Name()),
			})
		}
	}
	targetsRoot := filepath.Join(logRoot, "driver-targets")
	if drivers, err := os.ReadDir(targetsRoot); err == nil {
		for _, driver := range drivers {
			if !driver.IsDir() || !strings.HasPrefix(driver.Name(), "driver-") {
				continue
			}
			driverID, err := strconv.Atoi(strings.TrimPrefix(driver.Name(), "driver-"))
			if err != nil || driverID <= 0 {
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
				seq := parseTargetVersion(version.Name())
				if seq <= 0 {
					continue
				}
				snapshots = append(snapshots, crashAnalysisSnapshot{
					driverID: driverID,
					seq:      seq,
					dir:      filepath.Join(driverRoot, version.Name()),
				})
			}
		}
	}
	sort.SliceStable(snapshots, func(i, j int) bool {
		if snapshots[i].driverID != snapshots[j].driverID {
			return snapshots[i].driverID < snapshots[j].driverID
		}
		return snapshots[i].seq < snapshots[j].seq
	})
	return snapshots
}

func crashAnalysisSnapshotIdentity(logRoot, snapDir string) (driverID, seq int) {
	rel, err := filepath.Rel(filepath.Clean(logRoot), filepath.Clean(snapDir))
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return 0, 0
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) == 2 && parts[0] == "driver-snapshots" {
		return 0, parseLegacySnapshotVersion(parts[1])
	}
	if len(parts) == 3 && parts[0] == "driver-targets" {
		driverID, _ = strconv.Atoi(strings.TrimPrefix(parts[1], "driver-"))
		seq = parseTargetVersion(parts[2])
		return driverID, seq
	}
	return 0, 0
}

func parseLegacySnapshotVersion(name string) int {
	if !strings.HasPrefix(name, "fuzz-") {
		return 0
	}
	seq, _ := strconv.Atoi(strings.TrimPrefix(name, "fuzz-"))
	return seq
}

func readCrashAnalysisEntries(path string) []fuzzing.CrashAnalysisEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	entries, ok := decodeCrashAnalysisEntries(data)
	if !ok {
		return nil
	}
	return entries
}

func decodeCrashAnalysisEntries(data []byte) ([]fuzzing.CrashAnalysisEntry, bool) {
	var analysis struct {
		List []fuzzing.CrashAnalysisEntry `json:"unique_list"`
	}
	if err := json.Unmarshal(data, &analysis); err != nil {
		return nil, false
	}
	return analysis.List, true
}

func crashReportSnapshotDir(targetDir string, driverID, seq int) string {
	fuzzingLogsDir := filepath.Join(targetDir, "logs", "fuzzing")
	if driverID > 0 {
		return filepath.Join(fuzzingLogsDir, "driver-targets", fmt.Sprintf("driver-%04d", driverID), fmt.Sprintf("v%03d", seq))
	}
	return filepath.Join(fuzzingLogsDir, "driver-snapshots", fmt.Sprintf("fuzz-%03d", seq))
}

type DriverDiffResponse struct {
	DriverID  int    `json:"driver_id,omitempty"`
	BaseSeq   int    `json:"base_seq"`
	TargetSeq int    `json:"target_seq"`
	Diff      string `json:"diff"`
}

func (m *Manager) DriverDiff(id string, driverID, targetSeq int) (DriverDiffResponse, error) {
	if targetSeq <= 1 {
		return DriverDiffResponse{}, fmt.Errorf("driver version v%d has no previous version", targetSeq)
	}
	targetDir := ""
	if task, exists := m.Get(id); exists {
		task.mu.RLock()
		targetDir = task.targetDir
		task.mu.RUnlock()
	} else {
		workspace, name := historicalEntry(id)
		if workspace != "" {
			targetDir = filepath.Join(workspace, name)
		}
	}
	if targetDir == "" {
		return DriverDiffResponse{}, fmt.Errorf("task not found")
	}
	baseSeq := targetSeq - 1
	var baseDir, currentDir string
	if driverID > 0 {
		targetSnapDir := filepath.Join(targetDir, "logs", "fuzzing", "driver-targets", fmt.Sprintf("driver-%04d", driverID))
		baseDir = filepath.Join(targetSnapDir, fmt.Sprintf("v%03d", baseSeq), "driver")
		currentDir = filepath.Join(targetSnapDir, fmt.Sprintf("v%03d", targetSeq), "driver")
	} else {
		snapshotsDir := filepath.Join(targetDir, "logs", "fuzzing", "driver-snapshots")
		baseDir = filepath.Join(snapshotsDir, fmt.Sprintf("fuzz-%03d", baseSeq), "synthesized")
		currentDir = filepath.Join(snapshotsDir, fmt.Sprintf("fuzz-%03d", targetSeq), "synthesized")
	}
	for _, directory := range []string{baseDir, currentDir} {
		if info, err := os.Stat(directory); err != nil || !info.IsDir() {
			return DriverDiffResponse{}, fmt.Errorf("driver snapshot not found: %s", filepath.Base(filepath.Dir(directory)))
		}
	}
	command := exec.Command("diff", "-ruN", "--exclude=*.bak", baseDir, currentDir)
	command.Env = append(os.Environ(), "LC_ALL=C")
	output, err := command.CombinedOutput()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); !ok || exitError.ExitCode() != 1 {
			return DriverDiffResponse{}, fmt.Errorf("compare driver snapshots: %w: %s", err, strings.TrimSpace(string(output)))
		}
	}
	diff := string(output)
	diff = strings.ReplaceAll(diff, baseDir, fmt.Sprintf("v%d", baseSeq))
	diff = strings.ReplaceAll(diff, currentDir, fmt.Sprintf("v%d", targetSeq))
	return DriverDiffResponse{DriverID: driverID, BaseSeq: baseSeq, TargetSeq: targetSeq, Diff: diff}, nil
}

// historicalEntry looks up a task ID in the registry and returns the
// workspace+name path. Returns empty strings if not found.
func historicalEntry(id string) (workspace, name string) {
	entry, exists := registryEntryByID(id)
	if exists {
		return entry.Workspace, entry.Name
	}
	return "", ""
}

// historicalCoverageData reads the latest snapshot's aggregate.profdata for a
// historical task and exports it. Returns nil if data is unavailable.
func historicalCoverageData(id string, driverID, seq int) any {
	ws, name := historicalEntry(id)
	if ws == "" {
		return nil
	}
	targetDir := filepath.Join(ws, name)
	if driverID > 0 {
		return historicalTargetCoverageData(targetDir, driverID, seq)
	}
	if multi := historicalMultiCoverageData(targetDir); multi != nil {
		return multi
	}
	// Find the latest snapshot.
	entries, err := os.ReadDir(filepath.Join(targetDir, "logs", "fuzzing", "driver-snapshots"))
	if err != nil {
		return map[string]any{"available": false}
	}
	var latestSeq int
	var latestDir string
	for _, e := range entries {
		var seq int
		if _, err := fmt.Sscanf(e.Name(), "fuzz-%d", &seq); err != nil {
			continue
		}
		if seq > latestSeq {
			latestSeq = seq
			latestDir = filepath.Join(targetDir, "logs", "fuzzing", "driver-snapshots", e.Name())
		}
	}
	if latestDir == "" {
		return map[string]any{"available": false}
	}
	profdata := filepath.Join(latestDir, "monitor", "aggregate.profdata")
	binary := filepath.Join(latestDir, "cov_synthesized_driver")
	if !fileExists(profdata) || !fileExists(binary) {
		return map[string]any{"available": false}
	}
	// Read source/build dirs from agent-state.json.
	srcDir, buildDir := readStateDirs(filepath.Join(targetDir, "agent-state.json"))
	cs, err := fuzzing.CollectCoverageStatus(profdata, binary, srcDir, buildDir)
	if err != nil {
		return map[string]any{"available": false}
	}
	return map[string]any{
		"available":  true,
		"seed_count": 0,
		"coverage":   cs,
		"timestamp":  time.Now().Format(time.RFC3339),
	}
}

func historicalTargetCoverageData(targetDir string, driverID, seq int) any {
	targetRoot := filepath.Join(targetDir, "logs", "fuzzing", "driver-targets", fmt.Sprintf("driver-%04d", driverID))
	versionDir := ""
	if seq > 0 {
		versionDir = filepath.Join(targetRoot, fmt.Sprintf("v%03d", seq))
		if info, err := os.Stat(versionDir); err != nil || !info.IsDir() {
			versionDir = ""
		}
	} else {
		versionDir = latestTargetSnapshotDir(targetRoot)
	}
	if versionDir == "" {
		return map[string]any{"available": false}
	}
	profdata := filepath.Join(versionDir, "monitor", "aggregate.profdata")
	binary := filepath.Join(versionDir, "cov_driver")
	if !fileExists(profdata) || !fileExists(binary) {
		return map[string]any{"available": false}
	}
	srcDir, buildDir := readStateDirs(filepath.Join(targetDir, "agent-state.json"))
	cs, err := fuzzing.CollectCoverageStatus(profdata, binary, srcDir, buildDir)
	if err != nil {
		return map[string]any{"available": false}
	}
	return fuzzing.CoverageSnapshot{
		Timestamp: time.Now(),
		Available: true,
		SeedCount: countRegularFiles(filepath.Join(versionDir, "corpus")),
		Coverage:  cs,
	}
}

func historicalMultiCoverageData(targetDir string) any {
	targetsRoot := filepath.Join(targetDir, "logs", "fuzzing", "driver-targets")
	entries, err := os.ReadDir(targetsRoot)
	if err != nil {
		return nil
	}
	srcDir, buildDir := readStateDirs(filepath.Join(targetDir, "agent-state.json"))
	var targets []fuzzing.TargetCoverageSnapshot
	var coverages []fuzzing.CoverageStatus
	totalSeeds := 0
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "driver-") {
			continue
		}
		driverID, err := strconv.Atoi(strings.TrimPrefix(entry.Name(), "driver-"))
		if err != nil || driverID <= 0 {
			continue
		}
		versionDirs := targetSnapshotDirs(filepath.Join(targetsRoot, entry.Name()))
		if len(versionDirs) == 0 {
			continue
		}
		for _, versionDir := range versionDirs {
			profdata := filepath.Join(versionDir, "monitor", "aggregate.profdata")
			binary := filepath.Join(versionDir, "cov_driver")
			seedCount := countRegularFiles(filepath.Join(versionDir, "corpus"))
			totalSeeds += seedCount
			target := fuzzing.TargetCoverageSnapshot{
				DriverID:  driverID,
				Seq:       parseTargetVersion(filepath.Base(versionDir)),
				Status:    "historical",
				SeedCount: seedCount,
				CorpusDir: filepath.Join(versionDir, "corpus"),
			}
			if fileExists(profdata) && fileExists(binary) {
				if cs, err := fuzzing.CollectCoverageStatus(profdata, binary, srcDir, buildDir); err == nil {
					target.Available = true
					target.Coverage = cs
					target.Summary = cs.Summary
					target.UncoveredCount = historicalUncoveredCount(cs)
					coverages = append(coverages, cs)
				}
			}
			targets = append(targets, target)
		}
	}
	if len(targets) == 0 {
		return nil
	}
	return fuzzing.MultiCoverageSnapshot{
		Timestamp: time.Now(),
		Available: len(coverages) > 0,
		Mode:      "multi",
		SeedCount: totalSeeds,
		Coverage:  historicalUnionCoverageStatuses(coverages),
		Targets:   targets,
	}
}

func targetSnapshotDirs(targetRoot string) []string {
	entries, err := os.ReadDir(targetRoot)
	if err != nil {
		return nil
	}
	type versionDir struct {
		seq  int
		path string
	}
	var dirs []versionDir
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		seq := parseTargetVersion(entry.Name())
		if seq <= 0 {
			continue
		}
		dirs = append(dirs, versionDir{seq: seq, path: filepath.Join(targetRoot, entry.Name())})
	}
	sort.Slice(dirs, func(i, j int) bool {
		return dirs[i].seq < dirs[j].seq
	})
	out := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		out = append(out, dir.path)
	}
	return out
}

func latestTargetSnapshotDir(targetRoot string) string {
	entries, err := os.ReadDir(targetRoot)
	if err != nil {
		return ""
	}
	latestSeq := 0
	latestDir := ""
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		seq := parseTargetVersion(entry.Name())
		if seq > latestSeq {
			latestSeq = seq
			latestDir = filepath.Join(targetRoot, entry.Name())
		}
	}
	return latestDir
}

func parseTargetVersion(name string) int {
	if !strings.HasPrefix(name, "v") {
		return 0
	}
	seq, _ := strconv.Atoi(strings.TrimPrefix(name, "v"))
	return seq
}

func historicalUncoveredCount(cs fuzzing.CoverageStatus) int {
	n := 0
	for _, partial := range cs.Partial {
		n += len(partial.UncoveredBranches)
	}
	return n
}

func historicalUnionCoverageStatuses(statuses []fuzzing.CoverageStatus) fuzzing.CoverageStatus {
	type key struct {
		fn   string
		file string
	}
	full := map[key]fuzzing.FunctionCoverage{}
	partial := map[key]fuzzing.PartialFunctionCoverage{}
	for _, status := range statuses {
		for _, fc := range status.Full {
			k := key{fn: fc.Function, file: fc.File}
			full[k] = fc
			delete(partial, k)
		}
		for _, pc := range status.Partial {
			k := key{fn: pc.Function, file: pc.File}
			if _, ok := full[k]; ok {
				continue
			}
			partial[k] = pc
		}
	}
	out := fuzzing.CoverageStatus{}
	for _, fc := range full {
		out.Full = append(out.Full, fc)
	}
	for _, pc := range partial {
		out.Partial = append(out.Partial, pc)
	}
	out.Summary = fuzzing.CoverageSummary{
		ExecutedFunctions: len(out.Full) + len(out.Partial),
		FullFunctions:     len(out.Full),
		PartialFunctions:  len(out.Partial),
	}
	return out
}

// historicalSnapshotComparison constructs a temporary agent and calls
// SnapshotComparison for a historical task. Reads from disk.
func historicalSnapshotComparison(id string) any {
	ws, name := historicalEntry(id)
	if ws == "" {
		return []any{}
	}
	targetDir := filepath.Join(ws, name)
	statePath := filepath.Join(targetDir, "agent-state.json")
	data, err := os.ReadFile(statePath)
	if err != nil {
		return []any{}
	}
	var s state.RunState
	if json.Unmarshal(data, &s) != nil {
		return []any{}
	}
	a := agent.NewHistoricalAgent(targetDir, &s, filepath.Join(targetDir, "logs"))
	return a.SnapshotComparison()
}

func readStateDirs(statePath string) (sourceDir, buildDir string) {
	data, err := os.ReadFile(statePath)
	if err != nil {
		return "", ""
	}
	var s struct {
		SourceDir string `json:"source_dir"`
		BuildDir  string `json:"build_dir"`
	}
	json.Unmarshal(data, &s)
	return s.SourceDir, s.BuildDir
}

func (m *Manager) HistoricalSnapshot(id string) *TaskSnapshot {
	entry, exists := registryEntryByID(id)
	if !exists {
		return nil
	}
	snapshot := snapshotFromRegistry(entry)
	return &snapshot
}

func snapshotFromRegistry(entry registryEntry) TaskSnapshot {
	targetDir := filepath.Join(entry.Workspace, entry.Name)
	statePath := filepath.Join(targetDir, "agent-state.json")
	createdAt, _ := time.Parse(time.RFC3339, entry.CreatedAt)
	stages := pendingStageSnapshots(entry.Request.TaskKind)
	data, err := os.ReadFile(statePath)
	if err == nil {
		var runState state.RunState
		if json.Unmarshal(data, &runState) == nil {
			stages = stageSnapshotsFromState(&runState)
		}
	}
	status := effectiveRegistryStatus(entry)
	if err != nil && status != "pending" && status != "stopped" {
		status = "missing"
	}
	return TaskSnapshot{
		ID:              entry.ID,
		Status:          status,
		CreatedAt:       createdAt,
		TargetDir:       targetDir,
		StatePath:       statePath,
		TaskKind:        entry.Request.TaskKind,
		ParentTaskID:    entry.Request.ParentTaskID,
		OriginDriverID:  entry.Request.OriginDriverID,
		OriginDriverSeq: entry.Request.OriginDriverSeq,
		OriginCrashes:   append([]string(nil), entry.Request.OriginCrashes...),
		OriginSourceDir: entry.Request.OriginSourceDir,
		Stages:          stages,
		Request:         entry.Request,
	}
}

func pendingStageSnapshots(taskKind ...string) []StageSnapshot {
	kind := ""
	if len(taskKind) > 0 {
		kind = taskKind[0]
	}
	definitions := stageDefinitionsFor(kind)
	stages := make([]StageSnapshot, 0, len(definitions))
	for _, definition := range definitions {
		stages = append(stages, StageSnapshot{ID: definition.id, Name: definition.name, Owner: definition.owner, Status: "pending"})
	}
	return stages
}

func stageSnapshotsFromState(runState *state.RunState) []StageSnapshot {
	completedRank := stageRanks[string(runState.Stage)]
	failedStage := ""
	if (runState.Stage == state.StageFailed || runState.Stage == state.StageBlocked) && len(runState.Errors) > 0 {
		failedStage = string(runState.Errors[len(runState.Errors)-1].Stage)
		completedRank = stageRanks[failedStage] - 1
	}
	stages := pendingStageSnapshots(runState.TaskKind)
	for index := range stages {
		if stageRanks[stages[index].ID] <= completedRank {
			stages[index].Status = "completed"
		}
		if stages[index].ID == failedStage {
			stages[index].Status = "failed"
		}
	}
	return stages
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func countRegularFiles(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			count++
		}
	}
	return count
}

// TaskSummary is the per-task metadata returned by GET /api/runs.
type TaskSummary struct {
	ID              string `json:"id"`
	Status          string `json:"status"`
	Workspace       string `json:"workspace"`
	Name            string `json:"name"`
	RepositoryURL   string `json:"repository_url"`
	TaskKind        string `json:"task_kind,omitempty"`
	ParentTaskID    string `json:"parent_task_id,omitempty"`
	OriginDriverID  int    `json:"origin_driver_id,omitempty"`
	OriginDriverSeq int    `json:"origin_driver_seq,omitempty"`
	CreatedAt       string `json:"created_at"`
	CurrentStage    string `json:"current_stage,omitempty"`
}

type OverviewResponse struct {
	GeneratedAt  string                  `json:"generated_at"`
	Tasks        OverviewTaskCounts      `json:"tasks"`
	Issues       OverviewIssueCounts     `json:"issues"`
	CrashQueue   OverviewCrashQueueCount `json:"crash_queue"`
	RecentTasks  []TaskSummary           `json:"recent_tasks"`
	RecentIssues []OverviewIssueSummary  `json:"recent_issues"`
}

type OverviewTaskCounts struct {
	Total       int `json:"total"`
	Pending     int `json:"pending"`
	Running     int `json:"running"`
	Stopping    int `json:"stopping"`
	Stopped     int `json:"stopped"`
	Interrupted int `json:"interrupted"`
	Completed   int `json:"completed"`
	Failed      int `json:"failed"`
	Missing     int `json:"missing"`
	Other       int `json:"other"`
}

type OverviewIssueCounts struct {
	DiscoveredTotal    int `json:"discovered_total"`
	UniqueCrashesTotal int `json:"unique_crashes_total"`
	LibraryBugs        int `json:"library_bugs"`
	FuzzDriverBugs     int `json:"fuzz_driver_bugs"`
	Unknown            int `json:"unknown"`
	Unclassified       int `json:"unclassified"`
	PendingAnalysis    int `json:"pending_analysis"`
	RunningAnalysis    int `json:"running_analysis"`
	QueuedAnalysis     int `json:"queued_analysis"`
	FailedAnalysis     int `json:"failed_analysis"`
	SkippedAnalysis    int `json:"skipped_analysis"`
}

type OverviewCrashQueueCount struct {
	Total   int `json:"total"`
	Queued  int `json:"queued"`
	Running int `json:"running"`
}

type OverviewIssueSummary struct {
	TaskID         string `json:"task_id"`
	TaskName       string `json:"task_name"`
	RepositoryURL  string `json:"repository_url,omitempty"`
	DriverID       int    `json:"driver_id,omitempty"`
	Seq            int    `json:"seq"`
	File           string `json:"file"`
	Type           string `json:"type,omitempty"`
	ReportStatus   string `json:"report_status"`
	Classification string `json:"classification,omitempty"`
}

// Overview returns dashboard-level totals across registered Autofuzz tasks.
func (m *Manager) Overview() OverviewResponse {
	tasks := m.List()
	result := OverviewResponse{
		GeneratedAt:  time.Now().Format(time.RFC3339),
		RecentTasks:  []TaskSummary{},
		RecentIssues: []OverviewIssueSummary{},
	}
	result.Tasks.Total = len(tasks)
	for _, task := range tasks {
		countOverviewTaskStatus(&result.Tasks, task.Status)
		if len(result.RecentTasks) < 8 {
			result.RecentTasks = append(result.RecentTasks, task)
		}
		if unique, err := m.UniqueCrashes(task.ID); err == nil {
			for _, crash := range unique.Crashes {
				countOverviewIssue(&result.Issues, crash.Entry)
				if len(result.RecentIssues) < 12 {
					result.RecentIssues = append(result.RecentIssues, OverviewIssueSummary{
						TaskID:         task.ID,
						TaskName:       task.Name,
						RepositoryURL:  task.RepositoryURL,
						DriverID:       crash.DriverID,
						Seq:            crash.Seq,
						File:           crash.Entry.File,
						Type:           crash.Entry.Type,
						ReportStatus:   crash.Entry.ReportStatus,
						Classification: crash.Entry.Classification,
					})
				}
			}
		}
		if queue, err := m.CrashAnalysisQueue(task.ID); err == nil {
			for _, item := range queue.Items {
				result.CrashQueue.Total++
				switch item.Status {
				case "running":
					result.CrashQueue.Running++
				case "queued":
					result.CrashQueue.Queued++
				}
			}
		}
	}
	return result
}

func countOverviewTaskStatus(counts *OverviewTaskCounts, status string) {
	switch status {
	case "pending":
		counts.Pending++
	case "running":
		counts.Running++
	case "stopping":
		counts.Stopping++
	case "stopped":
		counts.Stopped++
	case "interrupted":
		counts.Interrupted++
	case "completed":
		counts.Completed++
	case "failed":
		counts.Failed++
	case "missing":
		counts.Missing++
	default:
		counts.Other++
	}
}

func countOverviewIssue(counts *OverviewIssueCounts, entry fuzzing.CrashAnalysisEntry) {
	counts.UniqueCrashesTotal++
	counts.DiscoveredTotal++
	switch entry.Classification {
	case "library_bug":
		counts.LibraryBugs++
	case "fuzz_driver_bug":
		counts.FuzzDriverBugs++
	case "unknown":
		counts.Unknown++
	default:
		counts.Unclassified++
	}
	switch entry.ReportStatus {
	case "pending":
		counts.PendingAnalysis++
	case "queued":
		counts.QueuedAnalysis++
	case "running":
		counts.RunningAnalysis++
	case "failed":
		counts.FailedAnalysis++
	case "skipped":
		counts.SkippedAnalysis++
	}
}

// List returns all tasks — both in-memory (from the current session) and
// historical (from the persistent registry, cross-session). For historical
// tasks, the status is derived from the workspace's agent-state.json.
func (m *Manager) List() []TaskSummary {
	registry := readTaskRegistry()
	m.mu.RLock()
	inMemory := map[string]*Task{}
	for id, t := range m.tasks {
		inMemory[id] = t
	}
	m.mu.RUnlock()

	result := make([]TaskSummary, 0, len(registry))
	for index := len(registry) - 1; index >= 0; index-- {
		entry := registry[index]
		if t, ok := inMemory[entry.ID]; ok {
			t.mu.RLock()
			status := t.status
			stage := ""
			for _, definition := range stageDefinitions {
				if t.stages[definition.id] == "running" {
					stage = definition.id
					break
				}
			}
			if stage == "" && t.agent != nil && t.agent.State != nil {
				stage = string(t.agent.State.Stage)
			}
			t.mu.RUnlock()
			result = append(result, TaskSummary{
				ID: entry.ID, Status: status, Workspace: entry.Workspace,
				Name: entry.Name, RepositoryURL: entry.RepositoryURL,
				TaskKind: entry.TaskKind, ParentTaskID: entry.ParentTaskID,
				OriginDriverID: entry.Request.OriginDriverID, OriginDriverSeq: entry.Request.OriginDriverSeq,
				CreatedAt: entry.CreatedAt, CurrentStage: stage,
			})
			continue
		}
		targetDir := filepath.Join(entry.Workspace, entry.Name)
		statePath := filepath.Join(targetDir, "agent-state.json")
		status := effectiveRegistryStatus(entry)
		_, stage := historicalStatus(statePath)
		if status != "pending" && status != "stopped" {
			if _, err := os.Stat(statePath); err != nil {
				status = "missing"
			}
		} else {
			stage = ""
		}
		result = append(result, TaskSummary{
			ID: entry.ID, Status: status, Workspace: entry.Workspace,
			Name: entry.Name, RepositoryURL: entry.RepositoryURL,
			TaskKind: entry.TaskKind, ParentTaskID: entry.ParentTaskID,
			OriginDriverID: entry.Request.OriginDriverID, OriginDriverSeq: entry.Request.OriginDriverSeq,
			CreatedAt: entry.CreatedAt, CurrentStage: stage,
		})
	}

	return result
}

func effectiveRegistryStatus(entry registryEntry) string {
	if entry.Status == "" {
		status, _ := historicalStatus(filepath.Join(entry.Workspace, entry.Name, "agent-state.json"))
		return status
	}
	if entry.Status == "running" || entry.Status == "stopping" {
		return "interrupted"
	}
	return entry.Status
}

// historicalStatus reads agent-state.json to determine the task's status and
// final stage. Returns ("completed", stage) if the last stage was reached,
// ("interrupted", stage) if the state file exists but the run didn't finish,
// ("missing", "") if the state file doesn't exist.
func historicalStatus(statePath string) (status, stage string) {
	data, err := os.ReadFile(statePath)
	if err != nil {
		return "missing", ""
	}
	var s struct {
		Stage string `json:"stage"`
	}
	if json.Unmarshal(data, &s) != nil {
		return "missing", ""
	}
	if s.Stage == string(state.StageFuzzing) {
		return "completed", s.Stage
	}
	if s.Stage == string(state.StageFailed) || s.Stage == string(state.StageBlocked) {
		return "failed", s.Stage
	}
	return "interrupted", s.Stage
}

// Delete removes a task from the registry. If the task is running, it is
// cancelled first. The workspace directory is NOT deleted (data stays on disk).
func (m *Manager) Delete(id string) error {
	var cancel context.CancelFunc
	running := false
	if task, exists := m.Get(id); exists {
		task.mu.Lock()
		running = task.status == "running" || task.status == "stopping"
		cancel = task.cancel
		task.deleted = true
		if running {
			task.stopRequested = true
		}
		if err := removeTaskFromRegistry(id); err != nil {
			task.deleted = false
			task.mu.Unlock()
			return fmt.Errorf("delete task: %w", err)
		}
		task.mu.Unlock()
	} else if err := removeTaskFromRegistry(id); err != nil {
		return fmt.Errorf("delete task: %w", err)
	}
	m.mu.Lock()
	delete(m.tasks, id)
	m.mu.Unlock()
	if running {
		cancel()
	}
	return nil
}

// HistoryEntry is one iteration's summary from fuzzing-history.jsonl.
type HistoryEntry struct {
	Iteration      int     `json:"iteration"`
	Seq            int     `json:"seq"`
	DriverID       int     `json:"driver_id,omitempty"`
	Trigger        string  `json:"trigger,omitempty"`
	Analysis       string  `json:"analysis"`
	PlateauReached bool    `json:"plateau_reached"`
	NeedsUpdate    bool    `json:"needs_update"`
	Regenerated    bool    `json:"regenerated"`
	Error          string  `json:"error,omitempty"`
	DurationSecs   float64 `json:"duration_seconds"`
	StartedAt      string  `json:"started_at"`
	FinishedAt     string  `json:"finished_at"`
}

type FuzzFlowResponse struct {
	Current *fuzzing.FuzzFlowSnapshot `json:"current,omitempty"`
	History []HistoryEntry            `json:"history"`
}

// FuzzFlowData restores the current repeating fuzz/LLM activity and recent
// completed analysis rounds from the task workspace.
func (m *Manager) FuzzFlowData(id string, limit int) FuzzFlowResponse {
	targetDir := ""
	if task, exists := m.Get(id); exists {
		task.mu.RLock()
		targetDir = task.targetDir
		task.mu.RUnlock()
	} else if workspace, name := historicalEntry(id); workspace != "" {
		targetDir = filepath.Join(workspace, name)
	}
	if targetDir == "" {
		return FuzzFlowResponse{History: []HistoryEntry{}}
	}
	logsDir := filepath.Join(targetDir, "logs", "fuzzing")
	current, _ := fuzzing.LoadFuzzFlow(filepath.Join(logsDir, "fuzz-flow.json"))
	history := readHistoryFile(filepath.Join(logsDir, "fuzzing-history.jsonl"))
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if len(history) > limit {
		history = append([]HistoryEntry(nil), history[len(history)-limit:]...)
	}
	return FuzzFlowResponse{Current: current, History: history}
}

// HistoricalHistory reads fuzzing-history.jsonl from a task's workspace and
// returns per-iteration summaries. Used by the web terminal when a historical
// task is selected (no live SSE available).
func (m *Manager) HistoricalHistory(id string) []HistoryEntry {
	// Try in-memory task first (live logs available via SSE, but return the
	// history anyway for the terminal).
	ws, name := historicalEntry(id)
	if ws == "" {
		// Not in registry — try in-memory task's workspace.
		task, exists := m.Get(id)
		if !exists {
			return []HistoryEntry{}
		}
		task.mu.RLock()
		td := task.targetDir
		task.mu.RUnlock()
		ws, name = filepath.Split(filepath.Clean(td))
		// ws is the parent dir name; need the full path relative.
		// Actually just use targetDir directly.
		return readHistoryFile(filepath.Join(td, "logs", "fuzzing", "fuzzing-history.jsonl"))
	}
	targetDir := filepath.Join(ws, name)
	return readHistoryFile(filepath.Join(targetDir, "logs", "fuzzing", "fuzzing-history.jsonl"))
}

func readHistoryFile(path string) []HistoryEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return []HistoryEntry{}
	}
	var entries []HistoryEntry
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var rec struct {
			Iteration int    `json:"iteration"`
			Seq       int    `json:"seq"`
			DriverID  int    `json:"driver_id"`
			Trigger   string `json:"trigger"`
			Analysis  struct {
				Analysis       string `json:"analysis"`
				PlateauReached bool   `json:"plateau_reached"`
				NeedsUpdate    bool   `json:"needs_update"`
			} `json:"analysis"`
			Regenerated bool   `json:"regenerated"`
			Error       string `json:"error"`
			StartedAt   string `json:"started_at"`
			FinishedAt  string `json:"finished_at"`
		}
		if json.Unmarshal(line, &rec) != nil {
			continue
		}
		entry := HistoryEntry{
			Iteration:      rec.Iteration,
			Seq:            rec.Seq,
			DriverID:       rec.DriverID,
			Trigger:        rec.Trigger,
			Analysis:       rec.Analysis.Analysis,
			PlateauReached: rec.Analysis.PlateauReached,
			NeedsUpdate:    rec.Analysis.NeedsUpdate,
			Regenerated:    rec.Regenerated,
			Error:          rec.Error,
			StartedAt:      rec.StartedAt,
			FinishedAt:     rec.FinishedAt,
		}
		if started, err := time.Parse(time.RFC3339Nano, rec.StartedAt); err == nil {
			if finished, err := time.Parse(time.RFC3339Nano, rec.FinishedAt); err == nil {
				entry.DurationSecs = finished.Sub(started).Seconds()
			}
		}
		if len(entries) > 0 && entries[len(entries)-1].Iteration == entry.Iteration {
			entries[len(entries)-1] = entry
		} else {
			entries = append(entries, entry)
		}
	}
	return entries
}
