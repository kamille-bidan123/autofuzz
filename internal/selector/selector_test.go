package selector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSelectLifecycleFromOrderSet(t *testing.T) {
	root := t.TempDir()
	preprocess := filepath.Join(root, "preprocessor")
	if err := os.MkdirAll(preprocess, 0o755); err != nil {
		t.Fatal(err)
	}
	data := `{
      "OrderSet 1":{"apis":["lib_open at a.c:1 in a.h","lib_read at a.c:2 in a.h","lib_close at a.c:3 in a.h"]},
      "OrderSet 2":{"apis":["lib_get at a.c:4 in a.h","lib_set at a.c:5 in a.h"]}
    }`
	if err := os.WriteFile(filepath.Join(preprocess, "call_order.json"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	selected, err := Select(root, []string{"lib_open", "lib_read", "lib_close", "lib_get", "lib_set"}, 6)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 3 || selected[0] != "lib_open" || selected[2] != "lib_close" {
		t.Fatalf("unexpected selection: %#v", selected)
	}
}
