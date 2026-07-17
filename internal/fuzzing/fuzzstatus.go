package fuzzing

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// FuzzStatus holds the runtime state of a single libFuzzer process.
type FuzzStatus struct {
	DurationSeconds        int64 `json:"duration_seconds"`
	ExecutedUnits          int64 `json:"executed_units"`
	InitialCov             int64 `json:"initial_cov"`
	FinalCov               int64 `json:"final_cov"`
	SecondsSinceLastCov    int64 `json:"seconds_since_last_cov"`
	ExecutionsSinceLastCov int64 `json:"executions_since_last_cov"`
}

// fuzzStatusLine is one parsed line of libFuzzer stderr output.
type fuzzStatusLine struct {
	seconds  int64
	executed int64
	cov      int64
	features int64
}

var statusLineRe = regexp.MustCompile(
	`stat::number_of_executed_units:\s*(\d+).*?stat::avg_executions_per_second:\s*(\d+).*?stat::new_units_added:\s*(\d+).*?stat::seconds_since_start:\s*(\d+).*?stat::unique_cov:\s*(\d+)`,
)

// simplified line pattern for fork mode: "#123456: cov: 789 ft: 1011 corp: 1/2 ... time: 20s ... job: 5
var covLineRe = regexp.MustCompile(
	`#(\d+):\s*cov:\s*(\d+)\s+ft:\s*(\d+)(?:\s+corp:\s*\S+\s+)?exec/s:\s*(\d+).*?time:\s*(\d+)s`,
)

// also match non-fork mode: "#123456  cov: 789 ft: 1011 ...
var covLineReLegacy = regexp.MustCompile(
	`#(\d+)\s+cov:\s*(\d+)\s+ft:\s*(\d+)`,
)

// initedLineRe matches the INITED line: "INITED cov: 123 ..." or "#123: INITED cov: 123 ..."
var initedLineRe = regexp.MustCompile(`INITED.*?cov:\s*(\d+)`)

// FuzzStatusTracker continuously parses libFuzzer stderr lines and
// retains the information needed to produce a FuzzStatus snapshot.
type FuzzStatusTracker struct {
	startTime time.Time

	initialCov           int64
	initialCovSet        bool
	lastCovValue         int64
	lastCovTime          time.Time
	lastCovExecutedUnits int64

	latestStatusLine fuzzStatusLine
	hasStatusLine    bool
}

func NewFuzzStatusTracker() *FuzzStatusTracker {
	return &FuzzStatusTracker{
		startTime:   time.Now(),
		lastCovTime: time.Now(),
	}
}

// ProcessLine handles one line of libFuzzer stderr output.
func (t *FuzzStatusTracker) ProcessLine(line string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return
	}

	// Try INITED line first (non-fork mode): "INITED cov: 123 ..." or "#256 INITED cov: 123 ..."
	if !t.initialCovSet {
		if m := initedLineRe.FindStringSubmatch(trimmed); m != nil {
			cov, _ := strconv.ParseInt(m[1], 10, 64)
			t.initialCov = cov
			t.initialCovSet = true
			t.lastCovValue = cov
			t.lastCovTime = time.Now()
			t.lastCovExecutedUnits = 0
			return
		}
	}

	// Try fork-mode format: #123456: cov: 789 ft: 1011 ... exec/s: ... time: 20s ... job: 5
	if m := covLineRe.FindStringSubmatch(trimmed); m != nil {
		executed, _ := strconv.ParseInt(m[1], 10, 64)
		cov, _ := strconv.ParseInt(m[2], 10, 64)
		seconds, _ := strconv.ParseInt(m[5], 10, 64)
		t.latestStatusLine = fuzzStatusLine{
			seconds:  seconds,
			executed: executed,
			cov:      cov,
		}
		t.hasStatusLine = true

		// In fork mode, the first cov line serves as initial_cov
		if !t.initialCovSet {
			t.initialCov = cov
			t.initialCovSet = true
			t.lastCovValue = cov
			t.lastCovTime = time.Now()
			t.lastCovExecutedUnits = executed
			return
		}
		if cov > t.lastCovValue {
			t.lastCovValue = cov
			t.lastCovTime = time.Now()
			t.lastCovExecutedUnits = executed
		}
		return
	}

	// Try legacy format: #123456  cov: 789 ft: 1011 ...
	if m := covLineReLegacy.FindStringSubmatch(trimmed); m != nil {
		executed, _ := strconv.ParseInt(m[1], 10, 64)
		cov, _ := strconv.ParseInt(m[2], 10, 64)
		t.latestStatusLine = fuzzStatusLine{
			executed: executed,
			cov:      cov,
		}
		t.hasStatusLine = true

		if !t.initialCovSet {
			t.initialCov = cov
			t.initialCovSet = true
			t.lastCovValue = cov
			t.lastCovTime = time.Now()
			t.lastCovExecutedUnits = executed
			return
		}
		if cov > t.lastCovValue {
			t.lastCovValue = cov
			t.lastCovTime = time.Now()
			t.lastCovExecutedUnits = executed
		}
		return
	}

	if m := statusLineRe.FindStringSubmatch(trimmed); m != nil {
		executed, _ := strconv.ParseInt(m[1], 10, 64)
		seconds, _ := strconv.ParseInt(m[4], 10, 64)
		cov, _ := strconv.ParseInt(m[5], 10, 64)
		t.latestStatusLine = fuzzStatusLine{
			seconds:  seconds,
			executed: executed,
			cov:      cov,
		}
		t.hasStatusLine = true
		if !t.initialCovSet {
			t.initialCov = cov
			t.initialCovSet = true
		}
		if cov > t.lastCovValue {
			t.lastCovValue = cov
			t.lastCovTime = time.Now()
			t.lastCovExecutedUnits = executed
		}
	}
}

// Snapshot produces a FuzzStatus from the current tracker state.
func (t *FuzzStatusTracker) Snapshot() FuzzStatus {
	status := FuzzStatus{
		InitialCov: t.initialCov,
	}
	if t.hasStatusLine {
		status.ExecutedUnits = t.latestStatusLine.executed
		status.FinalCov = t.latestStatusLine.cov
		if t.latestStatusLine.seconds > 0 {
			status.DurationSeconds = t.latestStatusLine.seconds
		}
	}
	if status.DurationSeconds == 0 {
		status.DurationSeconds = int64(time.Since(t.startTime).Seconds())
	}
	if !t.lastCovTime.IsZero() {
		status.SecondsSinceLastCov = int64(time.Since(t.lastCovTime).Seconds())
	}
	status.ExecutionsSinceLastCov = t.latestStatusLine.executed - t.lastCovExecutedUnits
	if status.ExecutionsSinceLastCov < 0 {
		status.ExecutionsSinceLastCov = 0
	}
	return status
}

// ParseFuzzStatusFromLog reads a complete libFuzzer stderr log file and
// returns a best-effort FuzzStatus. This is used when re-parsing log files.
func ParseFuzzStatusFromLog(content string) FuzzStatus {
	tracker := NewFuzzStatusTracker()
	for _, line := range strings.Split(content, "\n") {
		tracker.ProcessLine(line)
	}
	return tracker.Snapshot()
}

func (s FuzzStatus) String() string {
	return fmt.Sprintf("duration=%ds executed=%d initial_cov=%d final_cov=%d since_last_cov=%ds/%d execs",
		s.DurationSeconds, s.ExecutedUnits, s.InitialCov, s.FinalCov,
		s.SecondsSinceLastCov, s.ExecutionsSinceLastCov)
}
