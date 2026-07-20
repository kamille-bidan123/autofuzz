package fuzzing

import (
	"os"
	"path/filepath"
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
