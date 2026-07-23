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

type CrashAnalysisQueueEntry struct {
	ID          string    `json:"id"`
	Status      string    `json:"status"`
	Position    int       `json:"position"`
	SnapshotDir string    `json:"snapshot_dir"`
	File        string    `json:"file"`
	Type        string    `json:"type,omitempty"`
	QueuedAt    time.Time `json:"queued_at,omitempty"`
	StartedAt   time.Time `json:"started_at,omitempty"`
}

type crashAnalysisRunner func(context.Context, FuzzConfig, string, CrashAnalysisEntry) (CrashLLMReport, error)

type crashAnalysisQueueItem struct {
	ctx       context.Context
	job       CrashAnalysisJob
	queuedAt  time.Time
	startedAt time.Time
}

type crashAnalysisScheduler struct {
	mu      sync.Mutex
	queue   []crashAnalysisQueueItem
	current *crashAnalysisQueueItem
	active  map[string]bool
	running bool
	run     crashAnalysisRunner
}

var globalCrashAnalysisScheduler = newCrashAnalysisScheduler(AnalyzeUniqueCrashWithLLM)

func newCrashAnalysisScheduler(run crashAnalysisRunner) *crashAnalysisScheduler {
	if run == nil {
		run = AnalyzeUniqueCrashWithLLM
	}
	return &crashAnalysisScheduler{
		active: map[string]bool{},
		run:    run,
	}
}

// CrashAnalysisJobKey returns the stable queue key shared by runtime-triggered
// and manually-triggered analyses for the same snapshot crash artifact.
func CrashAnalysisJobKey(snapshotDir, crashFile string) string {
	return filepath.Clean(snapshotDir) + "\x00" + filepath.Base(crashFile)
}

func CrashAnalysisQueueJobID(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// EnqueueCrashAnalysis adds a unique-crash analysis job to the shared global
// scheduler. It returns false when the same snapshot crash is already queued or
// running.
func EnqueueCrashAnalysis(ctx context.Context, job CrashAnalysisJob) (bool, error) {
	return globalCrashAnalysisScheduler.enqueue(ctx, job)
}

func CrashAnalysisQueueSnapshot() []CrashAnalysisQueueEntry {
	return globalCrashAnalysisScheduler.snapshot()
}

func RemoveQueuedCrashAnalysis(id string) (bool, error) {
	return globalCrashAnalysisScheduler.removeQueued(id)
}

// IsCrashAnalysisQueuedOrRunning reports whether a job key is currently active
// in the shared global scheduler.
func IsCrashAnalysisQueuedOrRunning(key string) bool {
	return globalCrashAnalysisScheduler.isActive(key)
}

func (s *crashAnalysisScheduler) isActive(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active[key]
}

func (s *crashAnalysisScheduler) enqueue(ctx context.Context, job CrashAnalysisJob) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(job.SnapshotDir) == "" {
		return false, fmt.Errorf("snapshot dir is empty")
	}
	file := filepath.Base(job.Entry.File)
	if file == "." || file == string(filepath.Separator) || strings.TrimSpace(file) == "" {
		return false, fmt.Errorf("invalid crash file")
	}
	job.Entry.File = file
	if strings.TrimSpace(job.Key) == "" {
		job.Key = CrashAnalysisJobKey(job.SnapshotDir, file)
	}

	s.mu.Lock()
	if s.active[job.Key] {
		s.mu.Unlock()
		return false, nil
	}
	s.active[job.Key] = true
	s.queue = append(s.queue, crashAnalysisQueueItem{ctx: ctx, job: job, queuedAt: time.Now()})
	if job.OnQueued != nil {
		job.OnQueued()
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

func (s *crashAnalysisScheduler) snapshot() []CrashAnalysisQueueEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]CrashAnalysisQueueEntry, 0, len(s.queue)+1)
	if s.current != nil {
		items = append(items, queueEntryFromItem(*s.current, "running", 0))
	}
	for index, item := range s.queue {
		items = append(items, queueEntryFromItem(item, "queued", index+1))
	}
	return items
}

func queueEntryFromItem(item crashAnalysisQueueItem, status string, position int) CrashAnalysisQueueEntry {
	return CrashAnalysisQueueEntry{
		ID:          CrashAnalysisQueueJobID(item.job.Key),
		Status:      status,
		Position:    position,
		SnapshotDir: item.job.SnapshotDir,
		File:        item.job.Entry.File,
		Type:        item.job.Entry.Type,
		QueuedAt:    item.queuedAt,
		StartedAt:   item.startedAt,
	}
}

func (s *crashAnalysisScheduler) removeQueued(id string) (bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return false, fmt.Errorf("queue item id is empty")
	}
	var removed crashAnalysisQueueItem
	found := false

	s.mu.Lock()
	if s.current != nil && CrashAnalysisQueueJobID(s.current.job.Key) == id {
		s.mu.Unlock()
		return false, fmt.Errorf("crash analysis is already running")
	}
	for index, item := range s.queue {
		if CrashAnalysisQueueJobID(item.job.Key) != id {
			continue
		}
		removed = item
		copy(s.queue[index:], s.queue[index+1:])
		s.queue[len(s.queue)-1] = crashAnalysisQueueItem{}
		s.queue = s.queue[:len(s.queue)-1]
		delete(s.active, item.job.Key)
		found = true
		break
	}
	s.mu.Unlock()

	if !found {
		return false, nil
	}
	if removed.job.OnCancel != nil {
		removed.job.OnCancel()
	}
	if removed.job.OnDone != nil {
		removed.job.OnDone()
	}
	return true, nil
}

func (s *crashAnalysisScheduler) worker() {
	for {
		item, ok := s.next()
		if !ok {
			return
		}
		s.runJob(item)
	}
}

func (s *crashAnalysisScheduler) next() (crashAnalysisQueueItem, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue) == 0 {
		s.running = false
		return crashAnalysisQueueItem{}, false
	}
	item := s.queue[0]
	copy(s.queue, s.queue[1:])
	s.queue[len(s.queue)-1] = crashAnalysisQueueItem{}
	s.queue = s.queue[:len(s.queue)-1]
	return item, true
}

func (s *crashAnalysisScheduler) runJob(item crashAnalysisQueueItem) {
	job := item.job
	var report CrashLLMReport
	var err error
	item.startedAt = time.Now()
	s.mu.Lock()
	s.current = &item
	s.mu.Unlock()

	if item.ctx.Err() != nil {
		err = item.ctx.Err()
	} else {
		if job.OnStart != nil {
			job.OnStart()
		}
		report, err = s.run(item.ctx, job.Config, job.SnapshotDir, job.Entry)
	}

	if err != nil {
		if job.OnError != nil {
			job.OnError(err)
		}
	} else if job.OnComplete != nil {
		job.OnComplete(report)
	}

	s.mu.Lock()
	delete(s.active, job.Key)
	if s.current != nil && s.current.job.Key == job.Key {
		s.current = nil
	}
	s.mu.Unlock()
	if job.OnDone != nil {
		job.OnDone()
	}
}
