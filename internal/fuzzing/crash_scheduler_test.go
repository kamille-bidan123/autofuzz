package fuzzing

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestCrashAnalysisSchedulerDeduplicatesQueuedOrRunningJob(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	var runs atomic.Int32
	scheduler := newCrashAnalysisScheduler(func(ctx context.Context, cfg FuzzConfig, snapshotDir string, entry CrashAnalysisEntry) (CrashLLMReport, error) {
		runs.Add(1)
		close(started)
		select {
		case <-ctx.Done():
			return CrashLLMReport{}, ctx.Err()
		case <-release:
			return CrashLLMReport{Classification: "unknown"}, nil
		}
	})
	job := CrashAnalysisJob{
		SnapshotDir: t.TempDir(),
		Entry:       CrashAnalysisEntry{File: "crash-a"},
		OnDone:      func() { close(done) },
	}

	queued, err := scheduler.enqueue(context.Background(), job)
	if err != nil {
		t.Fatalf("first enqueue returned error: %v", err)
	}
	if !queued {
		t.Fatal("first enqueue returned false, want true")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}

	queued, err = scheduler.enqueue(context.Background(), job)
	if err != nil {
		t.Fatalf("duplicate enqueue returned error: %v", err)
	}
	if queued {
		t.Fatal("duplicate enqueue returned true, want false")
	}

	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not finish")
	}
	if got := runs.Load(); got != 1 {
		t.Fatalf("runs = %d, want 1", got)
	}
}

func TestCrashAnalysisSchedulerAllowsRequeueAfterCompletion(t *testing.T) {
	var runs atomic.Int32
	scheduler := newCrashAnalysisScheduler(func(ctx context.Context, cfg FuzzConfig, snapshotDir string, entry CrashAnalysisEntry) (CrashLLMReport, error) {
		runs.Add(1)
		return CrashLLMReport{Classification: "unknown"}, nil
	})
	job := CrashAnalysisJob{
		SnapshotDir: t.TempDir(),
		Entry:       CrashAnalysisEntry{File: "crash-a"},
	}

	doneFirst := make(chan struct{})
	job.OnDone = func() { close(doneFirst) }
	queued, err := scheduler.enqueue(context.Background(), job)
	if err != nil || !queued {
		t.Fatalf("first enqueue = (%v, %v), want (true, nil)", queued, err)
	}
	select {
	case <-doneFirst:
	case <-time.After(time.Second):
		t.Fatal("first job did not finish")
	}

	doneSecond := make(chan struct{})
	job.OnDone = func() { close(doneSecond) }
	queued, err = scheduler.enqueue(context.Background(), job)
	if err != nil || !queued {
		t.Fatalf("second enqueue = (%v, %v), want (true, nil)", queued, err)
	}
	select {
	case <-doneSecond:
	case <-time.After(time.Second):
		t.Fatal("second job did not finish")
	}
	if got := runs.Load(); got != 2 {
		t.Fatalf("runs = %d, want 2", got)
	}
}

func TestCrashAnalysisSchedulerSnapshotAndRemoveQueued(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	doneRunning := make(chan struct{})
	cancelQueued := make(chan struct{})
	doneQueued := make(chan struct{})
	scheduler := newCrashAnalysisScheduler(func(ctx context.Context, cfg FuzzConfig, snapshotDir string, entry CrashAnalysisEntry) (CrashLLMReport, error) {
		close(started)
		select {
		case <-ctx.Done():
			return CrashLLMReport{}, ctx.Err()
		case <-release:
			return CrashLLMReport{Classification: "unknown"}, nil
		}
	})
	snapDir := t.TempDir()
	runningJob := CrashAnalysisJob{
		SnapshotDir: snapDir,
		Entry:       CrashAnalysisEntry{File: "crash-running", Type: "leak"},
		OnDone:      func() { close(doneRunning) },
	}
	queuedJob := CrashAnalysisJob{
		SnapshotDir: snapDir,
		Entry:       CrashAnalysisEntry{File: "crash-queued", Type: "heap-buffer-overflow"},
		OnCancel:    func() { close(cancelQueued) },
		OnDone:      func() { close(doneQueued) },
	}

	if queued, err := scheduler.enqueue(context.Background(), runningJob); err != nil || !queued {
		t.Fatalf("running enqueue = (%v, %v), want (true, nil)", queued, err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("running job did not start")
	}
	if queued, err := scheduler.enqueue(context.Background(), queuedJob); err != nil || !queued {
		t.Fatalf("queued enqueue = (%v, %v), want (true, nil)", queued, err)
	}

	items := scheduler.snapshot()
	if len(items) != 2 {
		t.Fatalf("snapshot length = %d, want 2: %#v", len(items), items)
	}
	if items[0].Status != "running" || items[0].File != "crash-running" {
		t.Fatalf("first snapshot item = %#v, want running crash-running", items[0])
	}
	if items[1].Status != "queued" || items[1].File != "crash-queued" {
		t.Fatalf("second snapshot item = %#v, want queued crash-queued", items[1])
	}

	removed, err := scheduler.removeQueued(items[1].ID)
	if err != nil || !removed {
		t.Fatalf("remove queued = (%v, %v), want (true, nil)", removed, err)
	}
	select {
	case <-cancelQueued:
	case <-time.After(time.Second):
		t.Fatal("queued job cancel callback was not called")
	}
	select {
	case <-doneQueued:
	case <-time.After(time.Second):
		t.Fatal("queued job done callback was not called")
	}
	items = scheduler.snapshot()
	if len(items) != 1 || items[0].Status != "running" || items[0].File != "crash-running" {
		t.Fatalf("snapshot after remove = %#v, want only running job", items)
	}

	close(release)
	select {
	case <-doneRunning:
	case <-time.After(time.Second):
		t.Fatal("running job did not finish")
	}
}
