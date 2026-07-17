package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"autofuzz/internal/runner"
	"autofuzz/internal/state"
)

func TestVerifyDriverChecksEveryGeneratedBuildScript(t *testing.T) {
	root := t.TempDir()
	driverDir := filepath.Join(root, "out", "fuzz_driver")
	if err := os.MkdirAll(driverDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(driverDir, "fixture"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, number := range []string{"1", "2"} {
		script := "#!/bin/sh\ncp fixture fuzz_driver_" + number + "\n"
		path := filepath.Join(driverDir, "build_fuzz_driver_"+number+".sh")
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	autoAgent := &Agent{
		Runner: runner.Runner{}, LogsDir: filepath.Join(root, "logs"),
		State: &state.RunState{OutputPath: filepath.Join(root, "out")},
	}
	if err := autoAgent.verifyDriver(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"build-001.command.log", "smoke-001.command.log",
		"build-002.command.log", "smoke-002.command.log",
	} {
		if _, err := os.Stat(filepath.Join(root, "logs", "verify", name)); err != nil {
			t.Fatalf("missing verification log %s: %v", name, err)
		}
	}
}
