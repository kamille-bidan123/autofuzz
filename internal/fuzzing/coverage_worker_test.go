package fuzzing

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

func TestCoverageWorkerSerializesRequiredRequests(t *testing.T) {
	previousExecManager := coverageExecManager
	coverageExecManager = newCoverageExecutor()
	defer func() { coverageExecManager = previousExecManager }()

	previousStatusExport := coverageStatusExportFunc
	defer func() { coverageStatusExportFunc = previousStatusExport }()

	var running int32
	var maxRunning int32
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	coverageStatusExportFunc = func(ctx context.Context, profdataPath, binaryPath, sourceDir, buildDir, taskDir, driverDir string) (CoverageStatus, error) {
		current := atomic.AddInt32(&running, 1)
		for {
			peak := atomic.LoadInt32(&maxRunning)
			if current <= peak || atomic.CompareAndSwapInt32(&maxRunning, peak, current) {
				break
			}
		}
		started <- struct{}{}
		<-release
		atomic.AddInt32(&running, -1)
		return CoverageStatus{Summary: CoverageSummary{ExecutedFunctions: 1}}, nil
	}

	errs := make(chan error, 2)
	go func() {
		_, err := collectCoverageStatusContext(context.Background(), "required-1", "bin", "src", "build", "", "")
		errs <- err
	}()
	go func() {
		_, err := collectCoverageStatusContext(context.Background(), "required-2", "bin", "src", "build", "", "")
		errs <- err
	}()

	<-started
	close(release)

	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("required request %d failed: %v", i+1, err)
		}
	}
	if got := atomic.LoadInt32(&maxRunning); got != 1 {
		t.Fatalf("max concurrent required executions = %d, want 1", got)
	}
}

func TestCoverageWorkerCoalescesPendingRefreshRequests(t *testing.T) {
	previousExecManager := coverageExecManager
	coverageExecManager = newCoverageExecutor()
	defer func() { coverageExecManager = previousExecManager }()

	var mu sync.Mutex
	callCount := 0
	requiredStarted := make(chan struct{}, 1)
	releaseRequired := make(chan struct{})

	requiredItem := coverageExecManager.submitRequired(context.Background(), coverageRequestMetadata{}, func(ctx context.Context) coverageWorkResult {
		requiredStarted <- struct{}{}
		<-releaseRequired
		return coverageWorkResult{}
	})

	<-requiredStarted

	refreshRun := func(ctx context.Context) coverageWorkResult {
		mu.Lock()
		callCount++
		mu.Unlock()
		return coverageWorkResult{
			status: CoverageStatus{Summary: CoverageSummary{ExecutedFunctions: 7}},
		}
	}

	item1 := coverageExecManager.submitRefresh("same-key", coverageRequestMetadata{}, refreshRun)
	item2 := coverageExecManager.submitRefresh("same-key", coverageRequestMetadata{}, refreshRun)
	if item1 != item2 {
		t.Fatal("pending refresh requests with the same key should share one queued work item")
	}

	close(releaseRequired)

	if _, err := waitCoverageStatus(context.Background(), requiredItem); err != nil {
		t.Fatalf("required request failed: %v", err)
	}
	status1, err := waitCoverageStatus(context.Background(), item1)
	if err != nil {
		t.Fatalf("first refresh wait failed: %v", err)
	}
	status2, err := waitCoverageStatus(context.Background(), item2)
	if err != nil {
		t.Fatalf("second refresh wait failed: %v", err)
	}
	if status1.Summary.ExecutedFunctions != 7 || status2.Summary.ExecutedFunctions != 7 {
		t.Fatalf("unexpected refresh results: first=%#v second=%#v", status1.Summary, status2.Summary)
	}

	mu.Lock()
	defer mu.Unlock()
	if callCount != 1 {
		t.Fatalf("refresh executor call count = %d, want 1", callCount)
	}
}
