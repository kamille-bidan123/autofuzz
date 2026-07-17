package promefuzz

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"autofuzz/internal/runner"
)

func TestAssessAPI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.json")
	data := `{"/src/api.h":{"open":[{"loc":"a"}],"close":[{"loc":"b"}]}}`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	assessment, err := AssessAPI(path)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Count != 2 || len(assessment.FunctionNames) != 2 {
		t.Fatalf("unexpected assessment: %#v", assessment)
	}
}

func TestGenerateAllCoverArguments(t *testing.T) {
	root := t.TempDir()
	fakePython := filepath.Join(root, "fake-python")
	if err := os.WriteFile(fakePython, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	client := Client{
		Root: root, Python: fakePython, ConfigPath: filepath.Join(root, "config.toml"),
		Runner: runner.Runner{}, LogsDir: filepath.Join(root, "logs"),
	}
	if err := client.GenerateAllCover(context.Background(), filepath.Join(root, "library.toml"), 7, true); err != nil {
		t.Fatal(err)
	}
	commandLog, err := os.ReadFile(filepath.Join(root, "logs", "generate", "promefuzz.command.log"))
	if err != nil {
		t.Fatal(err)
	}
	command := string(commandLog)
	for _, expected := range []string{`"--task"`, `"allcover"`, `"--pool-size"`, `"7"`, `"--clear-state"`} {
		if !strings.Contains(command, expected) {
			t.Fatalf("generate command is missing %s: %s", expected, command)
		}
	}
	if strings.Contains(command, `"given"`) {
		t.Fatalf("generate command still uses given: %s", command)
	}
}

func TestGenerateAllCoverResumeKeepsState(t *testing.T) {
	root := t.TempDir()
	fakePython := filepath.Join(root, "fake-python")
	if err := os.WriteFile(fakePython, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	client := Client{Root: root, Python: fakePython, Runner: runner.Runner{}, LogsDir: filepath.Join(root, "logs")}
	if err := client.GenerateAllCover(context.Background(), "library.toml", 3, false); err != nil {
		t.Fatal(err)
	}
	commandLog, err := os.ReadFile(filepath.Join(root, "logs", "generate", "promefuzz.command.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(commandLog), `"--clear-state"`) {
		t.Fatalf("resume command unexpectedly clears state: %s", commandLog)
	}
}
