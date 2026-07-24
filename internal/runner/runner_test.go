package runner

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func TestRunForwardsCommandAndCarriageReturnProgress(t *testing.T) {
	logDir := t.TempDir()
	type receivedLine struct {
		command string
		stream  string
		line    string
	}
	var lines []receivedLine
	run := Runner{OnLine: func(command, stream, line string) {
		lines = append(lines, receivedLine{command: command, stream: stream, line: line})
	}}
	_, err := run.Run(
		context.Background(), logDir, "promefuzz", logDir, nil,
		"sh", "-c", "printf 'step 1\\rstep 2\\r\\ndone\\n'",
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(lines) != 4 {
		t.Fatalf("received lines = %#v", lines)
	}
	if lines[0].command != "promefuzz" || lines[0].stream != "command" ||
		!strings.Contains(lines[0].line, `argv="sh" "-c"`) {
		t.Fatalf("command event = %#v", lines[0])
	}
	for index, want := range []string{"step 1\r", "step 2", "done"} {
		got := lines[index+1]
		if got.stream != "stdout" || got.line != want {
			t.Fatalf("output event %d = %#v, want %q", index, got, want)
		}
	}
}

func TestLineWriterForwardsTqdmStyleCarriageProgress(t *testing.T) {
	var lines []string
	writer := &lineWriter{callback: func(line string) {
		lines = append(lines, line)
	}}
	if _, err := writer.Write([]byte("\rLoading 0%")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("\rLoading 8%")); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("\n")); err != nil {
		t.Fatal(err)
	}
	if want := []string{"\r", "Loading 0%\r", "\r", "Loading 8%\r", "\n"}; !reflect.DeepEqual(lines, want) {
		t.Fatalf("progress lines = %#v, want %#v", lines, want)
	}
}
