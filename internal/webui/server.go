package webui

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"autofuzz/internal/runevent"
)

//go:embed static/*
var staticFiles embed.FS

type Server struct {
	manager *Manager
	mux     *http.ServeMux
}

func NewServer(manager *Manager) *Server {
	server := &Server{manager: manager, mux: http.NewServeMux()}
	server.mux.HandleFunc("GET /", server.index)
	server.mux.HandleFunc("GET /api/defaults", server.defaults)
	server.mux.HandleFunc("GET /api/browse", server.browse)
	server.mux.HandleFunc("POST /api/runs", server.startRun)
	server.mux.HandleFunc("GET /api/runs/{id}", server.runSnapshot)
	server.mux.HandleFunc("GET /api/runs/{id}/events", server.runEvents)
	server.mux.HandleFunc("POST /api/runs/{id}/cancel", server.cancelRun)
	server.mux.HandleFunc("POST /api/runs/{id}/trigger-fuzz", server.triggerFuzz)
	server.mux.HandleFunc("GET /api/runs/{id}/coverage", server.coverage)
	server.mux.HandleFunc("GET /api/runs/{id}/snapshots", server.snapshots)
	server.mux.HandleFunc("GET /static/vendor/", server.serveVendor)
	return server
}

func (s *Server) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("X-Frame-Options", "DENY")
	response.Header().Set("Referrer-Policy", "no-referrer")
	s.mux.ServeHTTP(response, request)
}

func (s *Server) index(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		http.NotFound(response, request)
		return
	}
	data, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		http.Error(response, err.Error(), http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = response.Write(data)
}

func (s *Server) serveVendor(response http.ResponseWriter, request *http.Request) {
	path := "static/" + strings.TrimPrefix(request.URL.Path, "/static/")
	data, err := staticFiles.ReadFile(path)
	if err != nil {
		http.NotFound(response, request)
		return
	}
	switch filepath.Ext(path) {
	case ".js":
		response.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case ".css":
		response.Header().Set("Content-Type", "text/css; charset=utf-8")
	default:
		response.Header().Set("Content-Type", "application/octet-stream")
	}
	_, _ = response.Write(data)
}

func (s *Server) defaults(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, DefaultRunRequest())
}

type dirEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	IsDir bool   `json:"is_dir"`
}

type browseResult struct {
	Path    string     `json:"path"`
	IsDir   bool       `json:"is_dir"`
	Exists  bool       `json:"exists"`
	Entries []dirEntry `json:"entries"`
}

func (s *Server) browse(response http.ResponseWriter, request *http.Request) {
	query := request.URL.Query().Get("path")
	if query == "" {
		homeDir := homeDirectory()
		query = homeDir
	}

	query = filepath.Clean(query)

	result := browseResult{Path: query}

	info, err := os.Stat(query)
	if err != nil {
		// Path doesn't exist; try the parent directory
		parent := filepath.Dir(query)
		if parent == query {
			writeJSON(response, http.StatusOK, result)
			return
		}
		result.Path = parent
		info, err = os.Stat(parent)
		if err != nil {
			writeJSON(response, http.StatusOK, browseResult{Path: homeDirectory()})
			return
		}
		query = parent
	}

	result.IsDir = info.IsDir()
	result.Exists = true

	if !info.IsDir() {
		// It's a file; return its parent dir's listing
		query = filepath.Dir(query)
		result.Path = query
	}

	entries, err := os.ReadDir(query)
	if err != nil {
		writeJSON(response, http.StatusOK, result)
		return
	}

	var visible []dirEntry
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		fullPath := filepath.Join(query, name)
		visible = append(visible, dirEntry{
			Name:  name,
			Path:  fullPath,
			IsDir: entry.IsDir(),
		})
	}
	sort.Slice(visible, func(i, j int) bool {
		if visible[i].IsDir != visible[j].IsDir {
			return visible[i].IsDir
		}
		return visible[i].Name < visible[j].Name
	})

	result.Entries = visible
	writeJSON(response, http.StatusOK, result)
}

func homeDirectory() string {
	if currentUser, err := user.Current(); err == nil && currentUser.HomeDir != "" {
		return currentUser.HomeDir
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home
	}
	return "/"
}

func (s *Server) startRun(response http.ResponseWriter, request *http.Request) {
	defer request.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	var input RunRequest
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}
	task, err := s.manager.Start(input)
	if err != nil {
		writeError(response, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(response, http.StatusAccepted, task.Snapshot())
}

func (s *Server) runSnapshot(response http.ResponseWriter, request *http.Request) {
	task, exists := s.manager.Get(request.PathValue("id"))
	if !exists {
		writeError(response, http.StatusNotFound, "task not found")
		return
	}
	writeJSON(response, http.StatusOK, task.Snapshot())
}

func (s *Server) cancelRun(response http.ResponseWriter, request *http.Request) {
	if err := s.manager.Cancel(request.PathValue("id")); err != nil {
		writeError(response, http.StatusConflict, err.Error())
		return
	}
	writeJSON(response, http.StatusAccepted, map[string]string{"status": "cancelling"})
}

func (s *Server) triggerFuzz(response http.ResponseWriter, request *http.Request) {
	if err := s.manager.TriggerFuzzAnalysis(request.PathValue("id")); err != nil {
		writeError(response, http.StatusConflict, err.Error())
		return
	}
	writeJSON(response, http.StatusAccepted, map[string]string{"status": "triggered"})
}

func (s *Server) coverage(response http.ResponseWriter, request *http.Request) {
	data := s.manager.CoverageData(request.PathValue("id"))
	if data == nil {
		writeJSON(response, http.StatusOK, map[string]any{"available": false})
		return
	}
	writeJSON(response, http.StatusOK, data)
}

func (s *Server) snapshots(response http.ResponseWriter, request *http.Request) {
	data := s.manager.SnapshotComparison(request.PathValue("id"))
	if data == nil {
		writeJSON(response, http.StatusOK, []any{})
		return
	}
	writeJSON(response, http.StatusOK, data)
}

func (s *Server) runEvents(response http.ResponseWriter, request *http.Request) {
	task, exists := s.manager.Get(request.PathValue("id"))
	if !exists {
		writeError(response, http.StatusNotFound, "task not found")
		return
	}
	flusher, ok := response.(http.Flusher)
	if !ok {
		writeError(response, http.StatusInternalServerError, "streaming is unavailable")
		return
	}
	response.Header().Set("Content-Type", "text/event-stream")
	response.Header().Set("Cache-Control", "no-cache")
	response.Header().Set("Connection", "keep-alive")
	response.Header().Set("X-Accel-Buffering", "no")

	var afterSequence uint64
	if lastEventID := request.Header.Get("Last-Event-ID"); lastEventID != "" {
		afterSequence, _ = strconv.ParseUint(lastEventID, 10, 64)
	}
	history, channel, finished := task.subscribe(afterSequence)
	for _, event := range history {
		if !writeSSE(response, event) {
			if channel != nil {
				task.unsubscribe(channel)
			}
			return
		}
	}
	flusher.Flush()
	if finished {
		return
	}
	defer task.unsubscribe(channel)
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-request.Context().Done():
			return
		case event, open := <-channel:
			if !open {
				return
			}
			if !writeSSE(response, event) {
				return
			}
			flusher.Flush()
		case <-ticker.C:
			_, _ = fmt.Fprint(response, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func writeSSE(writer io.Writer, event runevent.Event) bool {
	data, err := json.Marshal(event)
	if err != nil {
		return false
	}
	_, err = fmt.Fprintf(writer, "id: %d\nevent: autofuzz\ndata: %s\n\n", event.Sequence, strings.ReplaceAll(string(data), "\n", ""))
	return err == nil
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func writeError(response http.ResponseWriter, status int, message string) {
	writeJSON(response, status, map[string]string{"error": message})
}
