package runner

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRunInputStreamingForwardsLinesAndPreservesLogs(t *testing.T) {
	logDir := t.TempDir()
	var stdoutLines []string
	var stderrLines []string
	run := Runner{}
	result, err := run.RunInputStreaming(
		context.Background(), logDir, "stream", logDir, nil, "",
		func(line string) { stdoutLines = append(stdoutLines, line) },
		func(line string) { stderrLines = append(stderrLines, line) },
		"sh", "-c", "printf 'one\\ntwo'; printf 'problem\\n' >&2",
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code = %d", result.ExitCode)
	}
	if !reflect.DeepEqual(stdoutLines, []string{"one", "two"}) {
		t.Fatalf("stdout lines = %#v", stdoutLines)
	}
	if !reflect.DeepEqual(stderrLines, []string{"problem"}) {
		t.Fatalf("stderr lines = %#v", stderrLines)
	}
	stdout, err := os.ReadFile(filepath.Join(logDir, "stream.stdout.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(stdout) != "one\ntwo" {
		t.Fatalf("stdout log = %q", stdout)
	}
}
