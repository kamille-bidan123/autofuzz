package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestBrowseRoot(t *testing.T) {
	tmp := t.TempDir()
	sub := filepath.Join(tmp, "subdir")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "file.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, ".hidden"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	server := NewServer(NewManager(context.Background()))
	request := httptest.NewRequest(http.MethodGet, "/api/browse?path="+tmp, nil)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}

	var result browseResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}

	if result.Path != tmp {
		t.Errorf("expected path %s, got %s", tmp, result.Path)
	}
	if !result.IsDir {
		t.Error("expected is_dir=true")
	}
	if !result.Exists {
		t.Error("expected exists=true")
	}
	if len(result.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(result.Entries))
	}
	// sub should come first (dirs first)
	if result.Entries[0].Name != "subdir" || !result.Entries[0].IsDir {
		t.Errorf("expected first entry to be subdir, got %+v", result.Entries[0])
	}
	if result.Entries[1].Name != "file.txt" || result.Entries[1].IsDir {
		t.Errorf("expected second entry to be file.txt, got %+v", result.Entries[1])
	}
}

func TestBrowseEmptyPathReturnsHome(t *testing.T) {
	server := NewServer(NewManager(context.Background()))
	request := httptest.NewRequest(http.MethodGet, "/api/browse", nil)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	var result browseResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Path == "" {
		t.Error("expected non-empty path for empty query")
	}
}

func TestBrowseNonexistentFallsBackToParent(t *testing.T) {
	tmp := t.TempDir()
	nonexistent := filepath.Join(tmp, "does_not_exist")

	server := NewServer(NewManager(context.Background()))
	request := httptest.NewRequest(http.MethodGet, "/api/browse?path="+nonexistent, nil)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	var result browseResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	// Should fall back to parent (tmp)
	if result.Path != tmp {
		t.Errorf("expected path %s, got %s", tmp, result.Path)
	}
}
