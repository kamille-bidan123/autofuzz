package fuzzing

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type coverageRequestMode int

const (
	coverageRequestRequired coverageRequestMode = iota
	coverageRequestRefresh
)

type coverageRequestKind string

const (
	coverageRequestCoverageSnapshot coverageRequestKind = "coverage_snapshot"
	coverageRequestLiveRefresh      coverageRequestKind = "live_refresh"
	coverageRequestBranchReach      coverageRequestKind = "branch_reach"
)

type CoverageQueueEntry struct {
	ID           string              `json:"id"`
	Status       string              `json:"status"`
	Position     int                 `json:"position"`
	Mode         string              `json:"mode"`
	Kind         coverageRequestKind `json:"kind"`
	QueuedAt     time.Time           `json:"queued_at,omitempty"`
	StartedAt    time.Time           `json:"started_at,omitempty"`
	Coalesced    int                 `json:"coalesced"`
	ProfdataPath string              `json:"profdata_path,omitempty"`
	BinaryPath   string              `json:"binary_path,omitempty"`
	TaskDir      string              `json:"task_dir,omitempty"`
	SourceDir    string              `json:"source_dir,omitempty"`
	BuildDir     string              `json:"build_dir,omitempty"`
	DriverDir    string              `json:"driver_dir,omitempty"`
}

type coverageRequestMetadata struct {
	kind         coverageRequestKind
	profdataPath string
	binaryPath   string
	taskDir      string
	sourceDir    string
	buildDir     string
	driverDir    string
}

type coverageWorkResult struct {
	status      CoverageStatus
	branchReach map[string]map[[2]int]bool
	err         error
}

type coverageWorkItem struct {
	id        string
	mode      coverageRequestMode
	key       string
	metadata  coverageRequestMetadata
	execCtx   context.Context
	run       func(context.Context) coverageWorkResult
	done      chan struct{}
	result    coverageWorkResult
	queuedAt  time.Time
	startedAt time.Time
	coalesced int
}

type coverageExecutor struct {
	mu             sync.Mutex
	cond           *sync.Cond
	nextID         uint64
	current        *coverageWorkItem
	queue          []*coverageWorkItem
	refreshPending map[string]*coverageWorkItem
}

var coverageExecManager = newCoverageExecutor()

func newCoverageExecutor() *coverageExecutor {
	exec := &coverageExecutor{
		refreshPending: map[string]*coverageWorkItem{},
	}
	exec.cond = sync.NewCond(&exec.mu)
	go exec.loop()
	return exec
}

func CoverageQueueSnapshot() []CoverageQueueEntry {
	return coverageExecManager.snapshot()
}

func (exec *coverageExecutor) submitRequired(execCtx context.Context, metadata coverageRequestMetadata, run func(context.Context) coverageWorkResult) *coverageWorkItem {
	item := &coverageWorkItem{
		id:        exec.nextWorkItemID(),
		mode:      coverageRequestRequired,
		metadata:  metadata,
		execCtx:   coverageExecContext(execCtx),
		run:       run,
		done:      make(chan struct{}),
		queuedAt:  time.Now(),
		coalesced: 1,
	}
	exec.mu.Lock()
	exec.queue = append(exec.queue, item)
	exec.cond.Signal()
	exec.mu.Unlock()
	return item
}

func (exec *coverageExecutor) submitRefresh(key string, metadata coverageRequestMetadata, run func(context.Context) coverageWorkResult) *coverageWorkItem {
	itemKey := strings.TrimSpace(key)
	if itemKey == "" {
		return exec.submitRequired(context.Background(), metadata, run)
	}

	exec.mu.Lock()
	defer exec.mu.Unlock()

	if pending := exec.refreshPending[itemKey]; pending != nil {
		pending.coalesced++
		return pending
	}

	item := &coverageWorkItem{
		id:        exec.nextWorkItemIDLocked(),
		mode:      coverageRequestRefresh,
		key:       itemKey,
		metadata:  metadata,
		execCtx:   context.Background(),
		run:       run,
		done:      make(chan struct{}),
		queuedAt:  time.Now(),
		coalesced: 1,
	}
	exec.queue = append(exec.queue, item)
	exec.refreshPending[itemKey] = item
	exec.cond.Signal()
	return item
}

func (exec *coverageExecutor) loop() {
	for {
		item := exec.next()
		item.result = item.run(item.execCtx)
		exec.finish(item)
		close(item.done)
	}
}

func (exec *coverageExecutor) next() *coverageWorkItem {
	exec.mu.Lock()
	defer exec.mu.Unlock()

	for len(exec.queue) == 0 {
		exec.cond.Wait()
	}

	item := exec.queue[0]
	exec.queue = exec.queue[1:]
	if item.mode == coverageRequestRefresh && exec.refreshPending[item.key] == item {
		delete(exec.refreshPending, item.key)
	}
	item.startedAt = time.Now()
	exec.current = item
	return item
}

func (exec *coverageExecutor) finish(item *coverageWorkItem) {
	exec.mu.Lock()
	if exec.current == item {
		exec.current = nil
	}
	exec.mu.Unlock()
}

func (exec *coverageExecutor) snapshot() []CoverageQueueEntry {
	exec.mu.Lock()
	defer exec.mu.Unlock()

	items := make([]CoverageQueueEntry, 0, len(exec.queue)+1)
	if exec.current != nil {
		items = append(items, queueEntryFromCoverageItem(exec.current, "running", 0))
	}
	for index, item := range exec.queue {
		items = append(items, queueEntryFromCoverageItem(item, "queued", index+1))
	}
	return items
}

func queueEntryFromCoverageItem(item *coverageWorkItem, status string, position int) CoverageQueueEntry {
	if item == nil {
		return CoverageQueueEntry{}
	}
	mode := "required"
	if item.mode == coverageRequestRefresh {
		mode = "refresh"
	}
	return CoverageQueueEntry{
		ID:           item.id,
		Status:       status,
		Position:     position,
		Mode:         mode,
		Kind:         item.metadata.kind,
		QueuedAt:     item.queuedAt,
		StartedAt:    item.startedAt,
		Coalesced:    item.coalesced,
		ProfdataPath: item.metadata.profdataPath,
		BinaryPath:   item.metadata.binaryPath,
		TaskDir:      item.metadata.taskDir,
		SourceDir:    item.metadata.sourceDir,
		BuildDir:     item.metadata.buildDir,
		DriverDir:    item.metadata.driverDir,
	}
}

func (exec *coverageExecutor) nextWorkItemID() string {
	exec.mu.Lock()
	defer exec.mu.Unlock()
	return exec.nextWorkItemIDLocked()
}

func (exec *coverageExecutor) nextWorkItemIDLocked() string {
	exec.nextID++
	return fmt.Sprintf("llvm-cov-%06d", exec.nextID)
}

func coverageExecContext(ctx context.Context) context.Context {
	if ctx != nil {
		return ctx
	}
	return context.Background()
}

func waitCoverageStatus(ctx context.Context, item *coverageWorkItem) (CoverageStatus, error) {
	if item == nil {
		return CoverageStatus{}, context.Canceled
	}
	select {
	case <-item.done:
		return item.result.status, item.result.err
	default:
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-item.done:
		return item.result.status, item.result.err
	case <-ctx.Done():
		return CoverageStatus{}, ctx.Err()
	}
}

func waitBranchReach(ctx context.Context, item *coverageWorkItem) (map[string]map[[2]int]bool, error) {
	if item == nil {
		return nil, context.Canceled
	}
	select {
	case <-item.done:
		return item.result.branchReach, item.result.err
	default:
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-item.done:
		return item.result.branchReach, item.result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func coverageStatusRefreshKey(profdataPath, binaryPath, sourceDir, buildDir, taskDir, driverDir string) string {
	parts := []string{
		"status",
		normalizeCoverageKeyPath(profdataPath),
		normalizeCoverageKeyPath(binaryPath),
		normalizeCoverageKeyPath(taskDir),
		normalizeCoverageKeyPath(sourceDir),
		normalizeCoverageKeyPath(buildDir),
		normalizeCoverageKeyPath(driverDir),
	}
	return strings.Join(parts, "\x00")
}

func normalizeCoverageKeyPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	return filepath.Clean(path)
}
