package fuzzing

import (
	"context"
	"testing"
	"time"
)

func TestCrashFixQueueDeduplicatesQueuedOrRunningJob(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	runs := 0
	scheduler := newCrashFixQueueScheduler()
	job := crashFixQueueJob{
		kind:        CrashFixQueueKindCrashAnalysis,
		snapshotDir: t.TempDir(),
		entry:       CrashAnalysisEntry{File: "crash-a"},
		run: func(ctx context.Context) error {
			runs++
			close(started)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
				return nil
			}
		},
		onDone: func() { close(done) },
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
	if runs != 1 {
		t.Fatalf("runs = %d, want 1", runs)
	}
}

func TestCrashFixQueueAllowsRequeueAfterCompletion(t *testing.T) {
	runs := 0
	scheduler := newCrashFixQueueScheduler()
	job := crashFixQueueJob{
		kind:        CrashFixQueueKindCrashAnalysis,
		snapshotDir: t.TempDir(),
		entry:       CrashAnalysisEntry{File: "crash-a"},
		run: func(ctx context.Context) error {
			runs++
			return nil
		},
	}

	doneFirst := make(chan struct{})
	job.onDone = func() { close(doneFirst) }
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
	job.onDone = func() { close(doneSecond) }
	queued, err = scheduler.enqueue(context.Background(), job)
	if err != nil || !queued {
		t.Fatalf("second enqueue = (%v, %v), want (true, nil)", queued, err)
	}
	select {
	case <-doneSecond:
	case <-time.After(time.Second):
		t.Fatal("second job did not finish")
	}
	if runs != 2 {
		t.Fatalf("runs = %d, want 2", runs)
	}
}

func TestCrashFixQueueSnapshotAndRemoveQueued(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	doneRunning := make(chan struct{})
	cancelQueued := make(chan struct{})
	doneQueued := make(chan struct{})
	scheduler := newCrashFixQueueScheduler()
	snapDir := t.TempDir()
	runningJob := crashFixQueueJob{
		kind:        CrashFixQueueKindCrashAnalysis,
		snapshotDir: snapDir,
		entry:       CrashAnalysisEntry{File: "crash-running", Type: "leak"},
		run: func(ctx context.Context) error {
			close(started)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
				return nil
			}
		},
		onDone: func() { close(doneRunning) },
	}
	queuedJob := crashFixQueueJob{
		kind:        CrashFixQueueKindDriverFix,
		snapshotDir: snapDir,
		entry:       CrashAnalysisEntry{File: "crash-queued", Type: "heap-buffer-overflow"},
		run:         func(ctx context.Context) error { return nil },
		onCancel:    func() { close(cancelQueued) },
		onDone:      func() { close(doneQueued) },
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
	if items[0].Status != "running" || items[0].File != "crash-running" || items[0].Kind != CrashFixQueueKindCrashAnalysis {
		t.Fatalf("first snapshot item = %#v, want running crash-analysis crash-running", items[0])
	}
	if items[1].Status != "queued" || items[1].File != "crash-queued" || items[1].Kind != CrashFixQueueKindDriverFix {
		t.Fatalf("second snapshot item = %#v, want queued driver-fix crash-queued", items[1])
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
	if len(items) != 1 || items[0].Status != "running" || items[0].File != "crash-running" || items[0].Kind != CrashFixQueueKindCrashAnalysis {
		t.Fatalf("snapshot after remove = %#v, want only running job", items)
	}

	close(release)
	select {
	case <-doneRunning:
	case <-time.After(time.Second):
		t.Fatal("running job did not finish")
	}
}

func TestCrashFixQueueAllowsDistinctKindsForSameCrash(t *testing.T) {
	scheduler := newCrashFixQueueScheduler()
	snapDir := t.TempDir()
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	analysisJob := crashFixQueueJob{
		kind:        CrashFixQueueKindCrashAnalysis,
		snapshotDir: snapDir,
		entry:       CrashAnalysisEntry{File: "crash-a"},
		run: func(ctx context.Context) error {
			close(started)
			<-release
			return nil
		},
		onDone: func() { close(done) },
	}
	fixJob := crashFixQueueJob{
		kind:        CrashFixQueueKindDriverFix,
		snapshotDir: snapDir,
		entry:       CrashAnalysisEntry{File: "crash-a"},
		run:         func(ctx context.Context) error { return nil },
	}

	if CrashAnalysisJobKey(snapDir, "crash-a") == DriverFixJobKey(snapDir, "crash-a") {
		t.Fatal("crash analysis and driver fix queue keys should be distinct")
	}
	if queued, err := scheduler.enqueue(context.Background(), analysisJob); err != nil || !queued {
		t.Fatalf("analysis enqueue = (%v, %v), want (true, nil)", queued, err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("analysis job did not start")
	}
	if queued, err := scheduler.enqueue(context.Background(), fixJob); err != nil || !queued {
		t.Fatalf("driver-fix enqueue = (%v, %v), want (true, nil)", queued, err)
	}

	items := scheduler.snapshot()
	if len(items) != 2 {
		t.Fatalf("snapshot length = %d, want 2: %#v", len(items), items)
	}
	if items[0].Kind != CrashFixQueueKindCrashAnalysis || items[1].Kind != CrashFixQueueKindDriverFix {
		t.Fatalf("unexpected queue kinds: %#v", items)
	}

	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("analysis job did not finish")
	}
}
