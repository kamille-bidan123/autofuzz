package webui

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"autofuzz/internal/agent"
	"autofuzz/internal/fuzzing"
	"autofuzz/internal/runevent"
	"autofuzz/internal/state"
)

type RunRequest struct {
	RepositoryURL string `json:"repository_url"`
	Ref           string `json:"ref"`
	Workspace     string `json:"workspace"`
	PromeFuzzRoot string `json:"promefuzz"`
	ConfigPath    string `json:"promefuzz_config"`
	PythonPath    string `json:"python"`
	PoolSize      int    `json:"pool_size"`
	Jobs          int    `json:"jobs"`
	CodexCommand  string `json:"codex_command"`
	CodexModel    string `json:"codex_model"`
	CodexProfile  string `json:"codex_profile"`
	Resume        bool   `json:"resume"`
	Verbose       bool   `json:"verbose"`
	StopAfter     string `json:"stop_after"`
	FuzzInterval  string `json:"fuzz_interval"`
}

func DefaultRunRequest() RunRequest {
	options := agent.DefaultOptions()
	return RunRequest{
		Workspace: options.Workspace, PromeFuzzRoot: options.PromeFuzzRoot,
		ConfigPath: options.ConfigPath, PythonPath: options.PythonPath,
		PoolSize: options.PoolSize, Jobs: options.Jobs,
		CodexCommand: options.CodexCommand, CodexModel: options.CodexModel,
		CodexProfile: options.CodexProfile, StopAfter: string(options.StopAfter),
		FuzzInterval: options.FuzzInterval.String(),
	}
}

func (r RunRequest) options() agent.Options {
	opts := agent.Options{
		RepositoryURL: r.RepositoryURL, Ref: r.Ref, Workspace: r.Workspace,
		PromeFuzzRoot: r.PromeFuzzRoot, ConfigPath: r.ConfigPath, PythonPath: r.PythonPath,
		PoolSize: r.PoolSize, Jobs: r.Jobs,
		CodexCommand: r.CodexCommand, CodexModel: r.CodexModel, CodexProfile: r.CodexProfile,
		Resume: r.Resume, Verbose: r.Verbose, StopAfter: state.Stage(r.StopAfter),
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
	original.Workspace = options.Workspace
	original.PromeFuzzRoot = options.PromeFuzzRoot
	original.ConfigPath = options.ConfigPath
	original.PythonPath = options.PythonPath
	original.PoolSize = options.PoolSize
	original.Jobs = options.Jobs
	original.CodexCommand = options.CodexCommand
	original.CodexModel = options.CodexModel
	original.CodexProfile = options.CodexProfile
	original.Resume = options.Resume
	original.Verbose = options.Verbose
	original.StopAfter = string(options.StopAfter)
	original.FuzzInterval = options.FuzzInterval.String()
	return original
}

type StageSnapshot struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Owner  string `json:"owner"`
	Status string `json:"status"`
}

type TaskSnapshot struct {
	ID         string          `json:"id"`
	Status     string          `json:"status"`
	Error      string          `json:"error,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
	TargetDir  string          `json:"target_dir"`
	StatePath  string          `json:"state_path"`
	Request    RunRequest      `json:"request"`
	Stages     []StageSnapshot `json:"stages"`
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
	for _, definition := range stageDefinitions {
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
	stages := make([]StageSnapshot, 0, len(stageDefinitions))
	for _, definition := range stageDefinitions {
		stages = append(stages, StageSnapshot{
			ID: definition.id, Name: definition.name, Owner: definition.owner,
			Status: t.stages[definition.id],
		})
	}
	return TaskSnapshot{
		ID: t.id, Status: t.status, Error: t.err, CreatedAt: t.createdAt,
		FinishedAt: t.finishedAt, TargetDir: t.targetDir, StatePath: t.statePath,
		Request: t.request, Stages: stages,
	}
}

func (t *Task) subscribe(afterSequence uint64) ([]runevent.Event, <-chan runevent.Event, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	history := make([]runevent.Event, 0, len(t.events))
	for _, event := range t.events {
		if event.Sequence > afterSequence {
			history = append(history, event)
		}
	}
	if t.finishedAt != nil {
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

type Manager struct {
	ctx       context.Context
	mu        sync.RWMutex
	tasks     map[string]*Task
	activeDir map[string]string
	counter   atomic.Uint64
	runAgent  func(context.Context, *agent.Agent) error
}

func NewManager(ctx context.Context) *Manager {
	return &Manager{
		ctx: ctx, tasks: map[string]*Task{}, activeDir: map[string]string{},
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
	agent.TriggerFuzzAnalysis()
	return nil
}

// CoverageData returns the cached coverage snapshot from the task's corpus
// monitor (in-memory), or reads from disk for historical tasks.
func (m *Manager) CoverageData(id string) any {
	task, exists := m.Get(id)
	if !exists {
		return historicalCoverageData(id)
	}
	task.mu.RLock()
	agent := task.agent
	task.mu.RUnlock()
	if agent == nil {
		return nil
	}
	return agent.CoverageData()
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

type DriverDiffResponse struct {
	BaseSeq   int    `json:"base_seq"`
	TargetSeq int    `json:"target_seq"`
	Diff      string `json:"diff"`
}

func (m *Manager) DriverDiff(id string, targetSeq int) (DriverDiffResponse, error) {
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
	snapshotsDir := filepath.Join(targetDir, "logs", "fuzzing", "driver-snapshots")
	baseDir := filepath.Join(snapshotsDir, fmt.Sprintf("fuzz-%03d", baseSeq), "synthesized")
	currentDir := filepath.Join(snapshotsDir, fmt.Sprintf("fuzz-%03d", targetSeq), "synthesized")
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
	return DriverDiffResponse{BaseSeq: baseSeq, TargetSeq: targetSeq, Diff: diff}, nil
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
func historicalCoverageData(id string) any {
	ws, name := historicalEntry(id)
	if ws == "" {
		return nil
	}
	targetDir := filepath.Join(ws, name)
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
	stages := pendingStageSnapshots()
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
		ID:        entry.ID,
		Status:    status,
		CreatedAt: createdAt,
		TargetDir: targetDir,
		StatePath: statePath,
		Stages:    stages,
		Request:   entry.Request,
	}
}

func pendingStageSnapshots() []StageSnapshot {
	stages := make([]StageSnapshot, 0, len(stageDefinitions))
	for _, definition := range stageDefinitions {
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
	stages := pendingStageSnapshots()
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

// TaskSummary is the per-task metadata returned by GET /api/runs.
type TaskSummary struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	Workspace     string `json:"workspace"`
	Name          string `json:"name"`
	RepositoryURL string `json:"repository_url"`
	CreatedAt     string `json:"created_at"`
	CurrentStage  string `json:"current_stage,omitempty"`
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
	Iteration   int    `json:"iteration"`
	Seq         int    `json:"seq"`
	Analysis    string `json:"analysis"`
	Regenerated bool   `json:"regenerated"`
	StartedAt   string `json:"started_at"`
	FinishedAt  string `json:"finished_at"`
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
			Iteration int `json:"iteration"`
			Seq       int `json:"seq"`
			Analysis  struct {
				Analysis string `json:"analysis"`
			} `json:"analysis"`
			Regenerated bool   `json:"regenerated"`
			StartedAt   string `json:"started_at"`
			FinishedAt  string `json:"finished_at"`
		}
		if json.Unmarshal(line, &rec) != nil {
			continue
		}
		entries = append(entries, HistoryEntry{
			Iteration:   rec.Iteration,
			Seq:         rec.Seq,
			Analysis:    rec.Analysis.Analysis,
			Regenerated: rec.Regenerated,
			StartedAt:   rec.StartedAt,
			FinishedAt:  rec.FinishedAt,
		})
	}
	return entries
}
