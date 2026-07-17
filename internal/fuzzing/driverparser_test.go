package fuzzing

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadEntrySource(t *testing.T) {
	tmp := t.TempDir()
	entryPath := filepath.Join(tmp, "entry.c")
	content := `// This is the entry of 1 fuzz drivers:
// 1
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) { return 0; }
`
	if err := os.WriteFile(entryPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	source, err := ReadEntrySource(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if source != content {
		t.Errorf("entry source mismatch")
	}
}
