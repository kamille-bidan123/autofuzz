package fuzzing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	CrashFixQueueKindCrashAnalysis = "crash_analysis"
	CrashFixQueueKindDriverFix     = "driver_fix"
)

// CrashAnalysisJob is a single unique-crash LLM analysis request. Jobs are
// deduplicated by Key while they are queued or running.
type CrashAnalysisJob struct {
	Key         string
	Config      FuzzConfig
	SnapshotDir string
	Entry       CrashAnalysisEntry

	OnQueued   func()
	OnStart    func()
	OnComplete func(CrashLLMReport)
	OnError    func(error)
	OnCancel   func()
	OnDone     func()
}

// DriverFixQueueJob is a single approval-gated driver-fix generation request.
// Jobs are deduplicated by Key while they are queued or running.
type DriverFixQueueJob struct {
	Key         string
	Config      FuzzConfig
	SnapshotDir string
	Entry       CrashAnalysisEntry

	OnQueued   func()
	OnStart    func()
	OnComplete func(DriverFixCandidateResult)
	OnError    func(DriverFixCandidateResult, error)
	OnCancel   func()
	OnDone     func()
}

type CrashFixQueueEntry struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	Status      string    `json:"status"`
	Position    int       `json:"position"`
	SnapshotDir string    `json:"snapshot_dir"`
	File        string    `json:"file"`
	Type        string    `json:"type,omitempty"`
	QueuedAt    time.Time `json:"queued_at,omitempty"`
	StartedAt   time.Time `json:"started_at,omitempty"`
}

type CrashAnalysisQueueEntry = CrashFixQueueEntry

type crashFixQueueRunner func(context.Context) error

type crashFixQueueJob struct {
	key         string
	kind        string
	snapshotDir string
	entry       CrashAnalysisEntry
	run         crashFixQueueRunner
	onQueued    func()
	onStart     func()
	onError     func(error)
	onCancel    func()
	onDone      func()
}

type crashFixQueueItem struct {
	ctx       context.Context
	job       crashFixQueueJob
	queuedAt  time.Time
	startedAt time.Time
}

type crashFixQueueScheduler struct {
	mu      sync.Mutex
	queue   []crashFixQueueItem
	current *crashFixQueueItem
	active  map[string]bool
	running bool
}

var globalCrashFixQueue = newCrashFixQueueScheduler()

func newCrashFixQueueScheduler() *crashFixQueueScheduler {
	return &crashFixQueueScheduler{active: map[string]bool{}}
}

// CrashAnalysisJobKey returns the stable queue key shared by runtime-triggered
// and manually-triggered analyses for the same snapshot crash artifact.
func CrashAnalysisJobKey(snapshotDir, crashFile string) string {
	return crashFixQueueJobKey(CrashFixQueueKindCrashAnalysis, snapshotDir, crashFile)
}

// DriverFixJobKey returns the stable queue key used for approval-gated driver
// fix generation for the same snapshot crash artifact.
func DriverFixJobKey(snapshotDir, crashFile string) string {
	return crashFixQueueJobKey(CrashFixQueueKindDriverFix, snapshotDir, crashFile)
}

func crashFixQueueJobKey(kind, snapshotDir, crashFile string) string {
	return strings.TrimSpace(kind) + "\x00" + filepath.Clean(snapshotDir) + "\x00" + filepath.Base(crashFile)
}

func CrashFixQueueJobID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func CrashAnalysisQueueJobID(key string) string {
	return CrashFixQueueJobID(key)
}

// EnqueueCrashAnalysis adds a unique-crash analysis job to the shared global
// crash-and-fix LLM scheduler. It returns false when the same snapshot crash
// analysis is already queued or running.
func EnqueueCrashAnalysis(ctx context.Context, job CrashAnalysisJob) (bool, error) {
	return globalCrashFixQueue.enqueue(ctx, crashFixQueueJob{
		key:         job.Key,
		kind:        CrashFixQueueKindCrashAnalysis,
		snapshotDir: job.SnapshotDir,
		entry:       job.Entry,
		run: func(runCtx context.Context) error {
			report, err := AnalyzeUniqueCrashWithLLM(runCtx, job.Config, job.SnapshotDir, job.Entry)
			if err != nil {
				return err
			}
			if job.OnComplete != nil {
				job.OnComplete(report)
			}
			return nil
		},
		onQueued: job.OnQueued,
		onStart:  job.OnStart,
		onError:  job.OnError,
		onCancel: job.OnCancel,
		onDone:   job.OnDone,
	})
}

// EnqueueDriverFixJob adds an approval-gated driver-fix generation job to the
// shared global crash-and-fix LLM scheduler. It returns false when the same
// snapshot crash's driver-fix generation is already queued or running.
func EnqueueDriverFixJob(ctx context.Context, job DriverFixQueueJob) (bool, error) {
	return globalCrashFixQueue.enqueue(ctx, crashFixQueueJob{
		key:         job.Key,
		kind:        CrashFixQueueKindDriverFix,
		snapshotDir: job.SnapshotDir,
		entry:       job.Entry,
		run: func(runCtx context.Context) error {
			result, err := GenerateDriverFixCandidate(runCtx, job.Config, job.SnapshotDir, job.Entry)
			if err != nil {
				if job.OnError != nil {
					job.OnError(result, err)
				}
				return nil
			}
			if job.OnComplete != nil {
				job.OnComplete(result)
			}
			return nil
		},
		onQueued: job.OnQueued,
		onStart:  job.OnStart,
		onCancel: job.OnCancel,
		onDone:   job.OnDone,
	})
}

func CrashFixQueueSnapshot() []CrashFixQueueEntry {
	return globalCrashFixQueue.snapshot()
}

func CrashAnalysisQueueSnapshot() []CrashAnalysisQueueEntry {
	return CrashFixQueueSnapshot()
}

func RemoveQueuedCrashFixJob(id string) (bool, error) {
	return globalCrashFixQueue.removeQueued(id)
}

func RemoveQueuedCrashAnalysis(id string) (bool, error) {
	return RemoveQueuedCrashFixJob(id)
}

// IsCrashFixJobQueuedOrRunning reports whether a queue key is currently active
// in the shared global crash-and-fix LLM scheduler.
func IsCrashFixJobQueuedOrRunning(key string) bool {
	return globalCrashFixQueue.isActive(key)
}

// IsCrashAnalysisQueuedOrRunning reports whether a crash-analysis job key is
// currently active in the shared global crash-and-fix LLM scheduler.
func IsCrashAnalysisQueuedOrRunning(key string) bool {
	return IsCrashFixJobQueuedOrRunning(key)
}

// IsDriverFixQueuedOrRunning reports whether a driver-fix job key is currently
// active in the shared global crash-and-fix LLM scheduler.
func IsDriverFixQueuedOrRunning(key string) bool {
	return IsCrashFixJobQueuedOrRunning(key)
}

func IsCrashOrFixQueuedOrRunning(snapshotDir, crashFile string) bool {
	return IsCrashFixJobQueuedOrRunning(CrashAnalysisJobKey(snapshotDir, crashFile)) ||
		IsCrashFixJobQueuedOrRunning(DriverFixJobKey(snapshotDir, crashFile))
}

func (s *crashFixQueueScheduler) isActive(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active[key]
}

func (s *crashFixQueueScheduler) enqueue(ctx context.Context, job crashFixQueueJob) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(job.kind) == "" {
		return false, fmt.Errorf("queue job kind is empty")
	}
	if strings.TrimSpace(job.snapshotDir) == "" {
		return false, fmt.Errorf("snapshot dir is empty")
	}
	file := filepath.Base(job.entry.File)
	if file == "." || file == string(filepath.Separator) || strings.TrimSpace(file) == "" {
		return false, fmt.Errorf("invalid crash file")
	}
	if job.run == nil {
		return false, fmt.Errorf("queue job runner is nil")
	}
	job.entry.File = file
	if strings.TrimSpace(job.key) == "" {
		job.key = crashFixQueueJobKey(job.kind, job.snapshotDir, file)
	}

	s.mu.Lock()
	if s.active[job.key] {
		s.mu.Unlock()
		return false, nil
	}
	s.active[job.key] = true
	s.queue = append(s.queue, crashFixQueueItem{ctx: ctx, job: job, queuedAt: time.Now()})
	if job.onQueued != nil {
		job.onQueued()
	}
	shouldStart := !s.running
	if shouldStart {
		s.running = true
	}
	s.mu.Unlock()

	if shouldStart {
		go s.worker()
	}
	return true, nil
}

func (s *crashFixQueueScheduler) snapshot() []CrashFixQueueEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]CrashFixQueueEntry, 0, len(s.queue)+1)
	if s.current != nil {
		items = append(items, crashFixQueueEntryFromItem(*s.current, "running", 0))
	}
	for index, item := range s.queue {
		items = append(items, crashFixQueueEntryFromItem(item, "queued", index+1))
	}
	return items
}

func crashFixQueueEntryFromItem(item crashFixQueueItem, status string, position int) CrashFixQueueEntry {
	return CrashFixQueueEntry{
		ID:          CrashFixQueueJobID(item.job.key),
		Kind:        item.job.kind,
		Status:      status,
		Position:    position,
		SnapshotDir: item.job.snapshotDir,
		File:        item.job.entry.File,
		Type:        item.job.entry.Type,
		QueuedAt:    item.queuedAt,
		StartedAt:   item.startedAt,
	}
}

func (s *crashFixQueueScheduler) removeQueued(id string) (bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return false, fmt.Errorf("queue item id is empty")
	}
	var removed crashFixQueueItem
	found := false

	s.mu.Lock()
	if s.current != nil && CrashFixQueueJobID(s.current.job.key) == id {
		s.mu.Unlock()
		return false, fmt.Errorf("queue item is already running")
	}
	for index, item := range s.queue {
		if CrashFixQueueJobID(item.job.key) != id {
			continue
		}
		removed = item
		copy(s.queue[index:], s.queue[index+1:])
		s.queue[len(s.queue)-1] = crashFixQueueItem{}
		s.queue = s.queue[:len(s.queue)-1]
		delete(s.active, item.job.key)
		found = true
		break
	}
	s.mu.Unlock()

	if !found {
		return false, nil
	}
	if removed.job.onCancel != nil {
		removed.job.onCancel()
	}
	if removed.job.onDone != nil {
		removed.job.onDone()
	}
	return true, nil
}

func (s *crashFixQueueScheduler) worker() {
	for {
		item, ok := s.next()
		if !ok {
			return
		}
		s.runJob(item)
	}
}

func (s *crashFixQueueScheduler) next() (crashFixQueueItem, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 0 {
		s.running = false
		return crashFixQueueItem{}, false
	}
	item := s.queue[0]
	copy(s.queue, s.queue[1:])
	s.queue[len(s.queue)-1] = crashFixQueueItem{}
	s.queue = s.queue[:len(s.queue)-1]
	return item, true
}

func (s *crashFixQueueScheduler) runJob(item crashFixQueueItem) {
	job := item.job
	var err error
	item.startedAt = time.Now()
	s.mu.Lock()
	s.current = &item
	s.mu.Unlock()

	if item.ctx.Err() != nil {
		err = item.ctx.Err()
	} else {
		if job.onStart != nil {
			job.onStart()
		}
		err = job.run(item.ctx)
	}

	if err != nil && job.onError != nil {
		job.onError(err)
	}

	s.mu.Lock()
	delete(s.active, job.key)
	if s.current != nil && s.current.job.key == job.key {
		s.current = nil
	}
	s.mu.Unlock()
	if job.onDone != nil {
		job.onDone()
	}
}
