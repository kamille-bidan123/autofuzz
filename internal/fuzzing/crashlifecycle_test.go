package fuzzing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCopyFilePreservesMode(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "cov_driver")
	dst := filepath.Join(dir, "snap", "cov_driver")
	if err := os.WriteFile(src, []byte("binary-bytes"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile failed: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "binary-bytes" {
		t.Fatalf("content mismatch: %q", got)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	// Executable bit must be preserved so crash replay
	// (snapDir/cov_synthesized_driver -runs=1 <crash>) works without chmod.
	if info.Mode().Perm()&0o100 == 0 {
		t.Fatalf("executable bit lost: mode=%#o", info.Mode().Perm())
	}
}

func TestCopyFileMissingSource(t *testing.T) {
	if err := copyFile(filepath.Join(t.TempDir(), "nope"), filepath.Join(t.TempDir(), "dst")); err == nil {
		t.Fatal("expected error for missing source")
	}
}

func TestTrimASanReport(t *testing.T) {
	short := "ERROR: AddressSanitizer: heap-buffer-overflow\nSUMMARY: AddressSanitizer"
	if got := trimASanReport(short); got != short {
		t.Fatalf("short report changed: %q", got)
	}
	long := strings.Repeat("A", maxASanReportBytes+20)
	got := trimASanReport(long)
	if len(got) <= maxASanReportBytes || !strings.Contains(got, "truncated") {
		t.Fatalf("long report was not truncated with marker: len=%d", len(got))
	}
}

func TestCrashReplayEnvUnsetsDebugInfodURLs(t *testing.T) {
	env := crashReplayEnv([]string{
		"PATH=/usr/bin",
		"DEBUGINFOD_URLS=https://debuginfod.example/",
		"ASAN_OPTIONS=detect_leaks=1",
	})

	for _, kv := range env {
		if strings.HasPrefix(kv, "DEBUGINFOD_URLS=") {
			t.Fatalf("DEBUGINFOD_URLS was not unset: %v", env)
		}
	}
	if !containsEnv(env, "LLVM_PROFILE_FILE=/dev/null") {
		t.Fatalf("LLVM_PROFILE_FILE not set for replay: %v", env)
	}
	if !containsEnv(env, "ASAN_OPTIONS=detect_leaks=1") {
		t.Fatalf("unrelated ASAN_OPTIONS was not preserved: %v", env)
	}
}

func TestParseASanTypeRecognizesLeakSanitizer(t *testing.T) {
	stderr := "==3==ERROR: LeakSanitizer: detected memory leaks"
	if got := parseASanType(stderr); got != "leak" {
		t.Fatalf("parseASanType() = %q, want leak", got)
	}
}

func containsEnv(env []string, want string) bool {
	for _, kv := range env {
		if kv == want {
			return true
		}
	}
	return false
}
