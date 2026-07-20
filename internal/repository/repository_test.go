package repository

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProjectName(t *testing.T) {
	tests := map[string]string{
		"https://github.com/DaveGamble/cJSON.git":      "cJSON",
		"https://github.com/c-ares/c-ares":             "c-ares",
		"git@github.com:libexpat/libexpat.git":         "libexpat",
		"https://gitcode.com/testorg/sample-repo.git": "sample-repo",
		"https://gitcode.com/testorg/sample-repo":      "sample-repo",
		"git@gitcode.com:testorg/sample-repo.git":      "sample-repo",
	}
	for input, expected := range tests {
		actual, err := ProjectName(input)
		if err != nil || actual != expected {
			t.Fatalf("ProjectName(%q) = %q, %v", input, actual, err)
		}
	}
	if _, err := ProjectName("https://example.com/a/b"); err == nil {
		t.Fatal("non-GitHub URL was accepted")
	}
}

func TestCopyLocal(t *testing.T) {
	input := filepath.Join(t.TempDir(), "sample")
	output := filepath.Join(t.TempDir(), "copy")
	if err := os.MkdirAll(filepath.Join(input, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(input, "sample.c"), []byte("int x;"), 0o644); err != nil {
		t.Fatal(err)
	}
	hash, err := CopyLocal(input, output)
	if err != nil || len(hash) != 64 {
		t.Fatalf("CopyLocal hash=%q err=%v", hash, err)
	}
	if _, err := os.Stat(filepath.Join(output, "sample.c")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(output, ".git")); !os.IsNotExist(err) {
		t.Fatal(".git was copied")
	}
}
