package fuzzing

import (
	"fmt"
	"os"
	"path/filepath"
)

// ReadEntrySource reads the entry.c or entry.cpp file from the synthesized
// directory. This is the merged driver source code shown to the analyzer.
func ReadEntrySource(synthesizedDir string) (string, error) {
	for _, name := range []string{"entry.cpp", "entry.c"} {
		path := filepath.Join(synthesizedDir, name)
		if data, err := os.ReadFile(path); err == nil {
			return string(data), nil
		}
	}
	return "", fmt.Errorf("no entry.c or entry.cpp found in %s", synthesizedDir)
}
