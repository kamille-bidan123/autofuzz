package webui

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type registryEntry struct {
	ID            string     `json:"id"`
	Workspace     string     `json:"workspace"`
	Name          string     `json:"name"`
	RepositoryURL string     `json:"repository_url"`
	TaskKind      string     `json:"task_kind,omitempty"`
	ParentTaskID  string     `json:"parent_task_id,omitempty"`
	CreatedAt     string     `json:"created_at"`
	UpdatedAt     string     `json:"updated_at,omitempty"`
	Status        string     `json:"status,omitempty"`
	Request       RunRequest `json:"request,omitempty"`
}

var registryMu sync.Mutex

func taskRegistryPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".autofuzz", "tasks.jsonl")
}

func upsertTaskRegistry(entry registryEntry) error {
	registryMu.Lock()
	defer registryMu.Unlock()
	entries := readTaskRegistryFile()
	found := false
	for index := range entries {
		if entries[index].ID == entry.ID {
			entries[index] = entry
			found = true
			break
		}
	}
	if !found {
		entries = append(entries, entry)
	}
	return writeTaskRegistryFile(entries)
}

func updateTaskRegistryStatus(id, status string) {
	registryMu.Lock()
	defer registryMu.Unlock()
	entries := readTaskRegistryFile()
	for index := range entries {
		if entries[index].ID != id {
			continue
		}
		entries[index].Status = status
		entries[index].UpdatedAt = time.Now().Format(time.RFC3339)
		_ = writeTaskRegistryFile(entries)
		return
	}
}

func removeTaskFromRegistry(id string) error {
	registryMu.Lock()
	defer registryMu.Unlock()
	entries := readTaskRegistryFile()
	kept := entries[:0]
	for _, entry := range entries {
		if entry.ID != id {
			kept = append(kept, entry)
		}
	}
	return writeTaskRegistryFile(kept)
}

func readTaskRegistry() []registryEntry {
	registryMu.Lock()
	defer registryMu.Unlock()
	return readTaskRegistryFile()
}

func readTaskRegistryFile() []registryEntry {
	data, err := os.ReadFile(taskRegistryPath())
	if err != nil {
		return nil
	}
	var entries []registryEntry
	for _, line := range splitLines(data) {
		if len(line) == 0 {
			continue
		}
		var entry registryEntry
		if json.Unmarshal(line, &entry) != nil || entry.ID == "" {
			continue
		}
		if entry.Request.RepositoryURL == "" {
			request := DefaultRunRequest()
			request.RepositoryURL = entry.RepositoryURL
			request.Workspace = entry.Workspace
			entry.Request = request
		}
		entries = append(entries, entry)
	}
	return entries
}

func writeTaskRegistryFile(entries []registryEntry) error {
	path := taskRegistryPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data := make([]byte, 0, len(entries)*256)
	for _, entry := range entries {
		line, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		data = append(data, line...)
		data = append(data, '\n')
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o644); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func registryEntryByID(id string) (registryEntry, bool) {
	for _, entry := range readTaskRegistry() {
		if entry.ID == id {
			return entry, true
		}
	}
	return registryEntry{}, false
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for index, character := range data {
		if character == '\n' {
			lines = append(lines, data[start:index])
			start = index + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}
