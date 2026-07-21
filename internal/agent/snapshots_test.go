package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadAnalysisBySeqAssociatesUpdateWithNextVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fuzzing-history.jsonl")
	history := "" +
		`{"seq":3,"regenerated":false,"analysis":{"analysis":"准备修改"}}` + "\n" +
		`{"seq":3,"regenerated":true,"analysis":{"analysis":"v4 的实际修改"}}` + "\n" +
		`{"seq":4,"regenerated":false,"analysis":{"analysis":"没有修改"}}` + "\n"
	if err := os.WriteFile(path, []byte(history), 0o644); err != nil {
		t.Fatal(err)
	}

	got := readAnalysisBySeq(path)
	if got[4] != "v4 的实际修改" {
		t.Fatalf("v4 analysis = %q", got[4])
	}
	if _, exists := got[3]; exists {
		t.Fatalf("v3 unexpectedly has update analysis %q", got[3])
	}
	if _, exists := got[5]; exists {
		t.Fatalf("v5 unexpectedly has update analysis %q", got[5])
	}
}
