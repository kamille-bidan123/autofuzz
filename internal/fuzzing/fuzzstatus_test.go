package fuzzing

import (
	"testing"
)

func TestFuzzStatusTracker(t *testing.T) {
	tracker := NewFuzzStatusTracker()

	lines := []string{
		"Running 1 inputs times... each input for at least 1s.",
		"INFO: Seed: 1, Server: 1",
		"INFO: Loaded 1 modules   (1877 inline 8-bit counters): 1877",
		"INFO: -fork=1: 1 job(s)",
		"#256	INITED cov: 1821 ft: 1821 corp: 1/1b exec/s: 0 rss: 6mb",
		"#512	cov: 1821 ft: 1821 corp: 1/1b exec/s: 0 rss: 6mb",
		"#1024	cov: 1821 ft: 1821 corp: 1/1b exec/s: 0 rss: 6mb",
		"#1582575: cov: 1900 ft: 1900 corp: 579 exec/s: 77415 oom/timeout/crash: 0/0/0 time: 20s job: 5 dft_time: 0",
		"#2186736: cov: 1900 ft: 1900 corp: 579 exec/s: 86308 oom/timeout/crash: 0/0/0 time: 27s job: 6 dft_time: 0",
	}

	for _, line := range lines {
		tracker.ProcessLine(line)
	}

	status := tracker.Snapshot()

	if status.InitialCov != 1821 {
		t.Errorf("expected initial cov 1821, got %d", status.InitialCov)
	}
	if status.FinalCov != 1900 {
		t.Errorf("expected final cov 1900, got %d", status.FinalCov)
	}
	if status.ExecutedUnits != 2186736 {
		t.Errorf("expected executed 2186736, got %d", status.ExecutedUnits)
	}
	if status.DurationSeconds != 27 {
		t.Errorf("expected duration 27s, got %d", status.DurationSeconds)
	}
}

func TestFuzzStatusTrackerForkMode(t *testing.T) {
	tracker := NewFuzzStatusTracker()

	lines := []string{
		"#119994: cov: 1908 ft: 1908 corp: 579 exec/s: 59997 oom/timeout/crash: 0/0/0 time: 2s job: 1 dft_time: 0",
		"#339332: cov: 1908 ft: 1908 corp: 579 exec/s: 73112 oom/timeout/crash: 0/0/0 time: 5s job: 2 dft_time: 0",
		"#9657559: cov: 1908 ft: 1908 corp: 579 exec/s: 86483 oom/timeout/crash: 0/0/0 time: 120s job: 14 dft_time: 0",
	}

	for _, line := range lines {
		tracker.ProcessLine(line)
	}

	status := tracker.Snapshot()

	if status.InitialCov != 1908 {
		t.Errorf("expected initial cov 1908 (from first fork-mode line), got %d", status.InitialCov)
	}
	if status.FinalCov != 1908 {
		t.Errorf("expected final cov 1908, got %d", status.FinalCov)
	}
	if status.ExecutedUnits != 9657559 {
		t.Errorf("expected executed 9657559, got %d", status.ExecutedUnits)
	}
	if status.DurationSeconds != 120 {
		t.Errorf("expected duration 120s, got %d", status.DurationSeconds)
	}
}

func TestParseFuzzStatusFromLog(t *testing.T) {
	log := `Running 1 inputs times... each input for at least 1s.
#256	INITED cov: 1821 ft: 1821 corp: 1/1b exec/s: 0 rss: 6mb
#512	cov: 1942 ft: 1942 corp: 1/1b exec/s: 0 rss: 6mb
#1024	cov: 1942 ft: 1942 corp: 1/1b exec/s: 0 rss: 6mb
`
	status := ParseFuzzStatusFromLog(log)

	if status.InitialCov != 1821 {
		t.Errorf("expected initial cov 1821, got %d", status.InitialCov)
	}
	if status.FinalCov != 1942 {
		t.Errorf("expected final cov 1942, got %d", status.FinalCov)
	}
	if status.ExecutedUnits != 1024 {
		t.Errorf("expected executed 1024, got %d", status.ExecutedUnits)
	}
}
