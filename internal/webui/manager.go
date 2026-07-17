package webui

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"autofuzz/internal/agent"
	"autofuzz/internal/runevent"
	"autofuzz/internal/state"
)

type RunRequest struct {
	RepositoryURL string `json:"repository_url"`
	Ref           string `json:"ref"`
	Workspace     string `json:"workspace"`
	PromeFuzzRoot string `json:"promefuzz"`
	ConfigPath    string `json:"config"`
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
	mu          sync.RWMutex
	id          string
	request     RunRequest
	status      string
	err         string
	createdAt   time.Time
	finishedAt  *time.Time
	targetDir   string
	statePath   string
	stages      map[string]string
	events      []runevent.Event
	nextSeq     uint64
	subscribers map[chan runevent.Event]struct{}
	cancel      context.CancelFunc
	agent       *agent.Agent
}

func newTask(id string, request RunRequest, autoAgent *agent.Agent, cancel context.CancelFunc) *Task {
	task := &Task{
		id: id, request: request, status: "running", createdAt: time.Now(),
		targetDir: autoAgent.TargetDir, statePath: autoAgent.StatePath,
		stages: map[string]string{}, subscribers: map[chan runevent.Event]struct{}{}, cancel: cancel,
		agent: autoAgent,
	}
	completedRank := stageRanks[string(autoAgent.State.Stage)]
	for _, definition := range stageDefinitions {
		status := "pending"
		if stageRanks[definition.id] <= completedRank {
			status = "completed"
		}
		task.stages[definition.id] = status
	}
	return task
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

func (t *Task) finish(err error) {
	status := "completed"
	message := "Autofuzz 运行完成"
	if err != nil {
		status = "failed"
		message = err.Error()
	}
	t.publish(runevent.New("run", "", status, "autofuzz", message))
	t.mu.Lock()
	t.status = status
	if err != nil {
		t.err = err.Error()
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
}

func NewManager(ctx context.Context) *Manager {
	return &Manager{ctx: ctx, tasks: map[string]*Task{}, activeDir: map[string]string{}}
}

func (m *Manager) Start(request RunRequest) (*Task, error) {
	if request.RepositoryURL == "" {
		return nil, fmt.Errorf("repository_url cannot be empty")
	}
	autoAgent, err := agent.New(request.options())
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	if id, exists := m.activeDir[autoAgent.TargetDir]; exists {
		m.mu.Unlock()
		return nil, fmt.Errorf("target workspace is already running in task %s", id)
	}
	id := fmt.Sprintf("run-%d-%03d", time.Now().Unix(), m.counter.Add(1))
	runContext, cancel := context.WithCancel(m.ctx)
	task := newTask(id, request, autoAgent, cancel)
	m.tasks[id] = task
	m.activeDir[autoAgent.TargetDir] = id
	m.mu.Unlock()

	autoAgent.SetEventSink(task.publish)
	task.publish(runevent.New("run", "", "running", "autofuzz", "Autofuzz 任务已启动"))
	go func() {
		err := autoAgent.Run(runContext)
		task.finish(err)
		m.mu.Lock()
		delete(m.activeDir, autoAgent.TargetDir)
		m.mu.Unlock()
	}()
	return task, nil
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
	task.mu.RLock()
	finished := task.finishedAt != nil
	cancel := task.cancel
	task.mu.RUnlock()
	if finished {
		return fmt.Errorf("task has already finished")
	}
	cancel()
	return nil
}

func (m *Manager) TriggerFuzzAnalysis(id string) error {
	task, exists := m.Get(id)
	if !exists {
		return fmt.Errorf("task not found")
	}
	task.mu.RLock()
	finished := task.finishedAt != nil
	agent := task.agent
	task.mu.RUnlock()
	if finished {
		return fmt.Errorf("task has already finished")
	}
	if agent == nil {
		return fmt.Errorf("agent not available")
	}
	agent.TriggerFuzzAnalysis()
	return nil
}
