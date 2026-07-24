package fuzzing

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectAPICoverageUsesGeneratedAndLatestSnapshotDrivers(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "out")
	if err := os.MkdirAll(filepath.Join(output, "preprocessor"), 0o755); err != nil {
		t.Fatal(err)
	}
	state := map[string]string{"output_path": output}
	stateData, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(root, "agent-state.json"), stateData, 0o644); err != nil {
		t.Fatal(err)
	}
	apiJSON := `{
  "/tmp/sample.h": {
    "sample_context_create": [{"loc": "/tmp/sample.c:1:1", "decl_loc": "/tmp/sample.h:1:1"}],
    "sample_context_destroy": [{"loc": "/tmp/sample.c:2:1", "decl_loc": "/tmp/sample.h:2:1"}],
    "sample_context_get": [{"loc": "/tmp/sample.c:3:1", "decl_loc": "/tmp/sample.h:3:1"}],
    "sample_context_set": [{"loc": "/tmp/sample.c:4:1", "decl_loc": "/tmp/sample.h:4:1"}]
  }
}`
	if err := os.WriteFile(filepath.Join(output, "preprocessor", "api.json"), []byte(apiJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	driverDir := filepath.Join(output, "fuzz_driver")
	if err := os.MkdirAll(driverDir, 0o755); err != nil {
		t.Fatal(err)
	}
	driver1 := `// sample_context_get(Data) appears only in comments.
const char *name = "sample_context_set(Data)";
int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned long Size) {
  sample_context_create();
  sample_context_destroy(0);
  return 0;
}`
	if err := os.WriteFile(filepath.Join(driverDir, "fuzz_driver_1.c"), []byte(driver1), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshotDriverDir := filepath.Join(root, "logs", "fuzzing", "driver-targets", "driver-0002", "v002", "driver")
	if err := os.MkdirAll(snapshotDriverDir, 0o755); err != nil {
		t.Fatal(err)
	}
	driver2 := `int LLVMFuzzerTestOneInput(const unsigned char *Data, unsigned long Size) {
  sample_context_get(0, "k");
  return 0;
}`
	if err := os.WriteFile(filepath.Join(snapshotDriverDir, "fuzz_driver_2.c"), []byte(driver2), 0o644); err != nil {
		t.Fatal(err)
	}

	report, err := CollectAPICoverage(root)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Available || report.TotalAPIs != 4 || report.CoveredAPIs != 3 || report.DriverCount != 2 {
		t.Fatalf("unexpected report summary: %#v", report)
	}
	entries := map[string]APICoverageEntry{}
	for _, entry := range report.APIs {
		entries[entry.Name] = entry
	}
	for _, name := range []string{"sample_context_create", "sample_context_destroy"} {
		if len(entries[name].Drivers) != 1 || entries[name].Drivers[0].DriverID != 1 {
			t.Fatalf("%s covered by unexpected drivers: %#v", name, entries[name].Drivers)
		}
	}
	if len(entries["sample_context_get"].Drivers) != 1 || entries["sample_context_get"].Drivers[0].DriverID != 2 || entries["sample_context_get"].Drivers[0].Seq != 2 {
		t.Fatalf("sample_context_get covered by unexpected drivers: %#v", entries["sample_context_get"].Drivers)
	}
	if entries["sample_context_set"].Covered {
		t.Fatalf("sample_context_set should not be covered by comment/string matches: %#v", entries["sample_context_set"])
	}
}
