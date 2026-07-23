package buildagent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"autofuzz/internal/runner"
)

func TestValidateReport(t *testing.T) {
	root := t.TempDir()
	build := filepath.Join(root, "build")
	install := filepath.Join(root, "install")
	if err := os.MkdirAll(install, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(build, 0o755); err != nil {
		t.Fatal(err)
	}
	compile := filepath.Join(build, "compile_commands.json")
	if err := os.WriteFile(compile, []byte(`[{"command":"clang -fsanitize=address -c sample.c"}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	library := filepath.Join(install, "libsample.a")
	if err := os.WriteFile(library, []byte("archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := ValidateReport(Report{BuildSystem: "cmake", Language: "c", BuildDir: "build", InstallDir: "install", CompileCommandsPath: "build/compile_commands.json", StaticLibraries: []string{"install/libsample.a"}}, root)
	if err != nil {
		t.Fatal(err)
	}
	if result.CompileCommands != compile || len(result.StaticLibraries) != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestBuildStreamsCodexJSONEvents(t *testing.T) {
	root := t.TempDir()
	for _, directory := range []string{"source", "build", "install"} {
		if err := os.MkdirAll(filepath.Join(root, directory), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "build", "compile_commands.json"), []byte(`[{"command":"clang -fsanitize=address -c sample.c"}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "install", "libsample.a"), []byte("archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeCodex := filepath.Join(root, "fake-codex")
	script := `#!/bin/sh
output=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--output-last-message" ]; then
    output="$2"
    shift 2
    continue
  fi
  shift
done
printf '%s\n' '{"type":"thread.started","thread_id":"test-thread"}'
printf '%s\n' '{"analysis_summary":"built by fake Codex","build_system":"cmake","language":"c","build_dir":"build","install_dir":"install","compile_commands_path":"build/compile_commands.json","static_libraries":["install/libsample.a"],"evidence":["test"]}' > "$output"
`
	if err := os.WriteFile(fakeCodex, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	logDir := filepath.Join(root, "logs")
	var events []json.RawMessage
	client := Client{
		Command: fakeCodex + " -p off", Timeout: 5 * time.Second, Runner: runner.Runner{},
		EventSink: func(event json.RawMessage) { events = append(events, event) },
	}
	result, err := client.Build(context.Background(), Request{
		SourceDir: filepath.Join(root, "source"), TargetDir: root, Jobs: 1, LogDir: logDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Report.AnalysisSummary != "built by fake Codex" || len(events) != 1 {
		t.Fatalf("unexpected result/events: %#v %#v", result.Report, events)
	}
	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(events[0], &envelope); err != nil || envelope.Type != "thread.started" {
		t.Fatalf("unexpected Codex event: %s", events[0])
	}
	commandLog, err := os.ReadFile(filepath.Join(logDir, "codex.command.log"))
	if err != nil {
		t.Fatal(err)
	}
	commandText := string(commandLog)
	if !strings.Contains(commandText, `"-p" "off"`) || !strings.Contains(commandText, `"--json"`) {
		t.Fatalf("Codex command did not include expected args: %s", commandText)
	}
}

func TestValidateReportRejectsEscape(t *testing.T) {
	_, err := ValidateReport(Report{BuildSystem: "cmake", Language: "c", BuildDir: "../outside"}, t.TempDir())
	if err == nil {
		t.Fatal("expected path escape to be rejected")
	}
}
