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
	server.mux.HandleFunc("GET /api/overview", server.overview)
	server.mux.HandleFunc("POST /api/runs", server.createRun)
	server.mux.HandleFunc("GET /api/runs", server.listRuns)
	server.mux.HandleFunc("GET /api/runs/{id}", server.runSnapshot)
	server.mux.HandleFunc("POST /api/runs/{id}/start", server.startRun)
	server.mux.HandleFunc("GET /api/runs/{id}/events", server.runEvents)
	server.mux.HandleFunc("GET /api/runs/{id}/history", server.runHistory)
	server.mux.HandleFunc("GET /api/runs/{id}/fuzz-flow", server.fuzzFlow)
	server.mux.HandleFunc("POST /api/runs/{id}/cancel", server.cancelRun)
	server.mux.HandleFunc("POST /api/runs/{id}/trigger-fuzz", server.triggerFuzz)
	server.mux.HandleFunc("GET /api/runs/{id}/coverage", server.coverage)
	server.mux.HandleFunc("GET /api/runs/{id}/coverage/function-sources", server.coverageFunctionSources)
	server.mux.HandleFunc("GET /api/runs/{id}/snapshots", server.snapshots)
	server.mux.HandleFunc("GET /api/runs/{id}/unique-crashes", server.uniqueCrashes)
	server.mux.HandleFunc("GET /api/runs/{id}/crash-analysis-queue", server.crashAnalysisQueue)
	server.mux.HandleFunc("DELETE /api/runs/{id}/crash-analysis-queue", server.removeCrashAnalysisQueueItem)
	server.mux.HandleFunc("GET /api/runs/{id}/crash-reports", server.crashReports)
	server.mux.HandleFunc("POST /api/runs/{id}/crash-reports/analyze", server.analyzeCrashReport)
	server.mux.HandleFunc("GET /api/runs/{id}/snapshots/{seq}/diff", server.snapshotDiff)
	server.mux.HandleFunc("DELETE /api/runs/{id}", server.deleteRun)
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

func (s *Server) createRun(response http.ResponseWriter, request *http.Request) {
	defer request.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	var input RunRequest
	if err := decoder.Decode(&input); err != nil {
		writeError(response, http.StatusBadRequest, "invalid request: "+err.Error())
		return
	}
	snapshot, err := s.manager.Create(input)
	if err != nil {
		writeError(response, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(response, http.StatusCreated, snapshot)
}

func (s *Server) startRun(response http.ResponseWriter, request *http.Request) {
	task, err := s.manager.StartTask(request.PathValue("id"))
	if err != nil {
		writeError(response, http.StatusConflict, err.Error())
		return
	}
	writeJSON(response, http.StatusAccepted, task.Snapshot())
}

func (s *Server) runSnapshot(response http.ResponseWriter, request *http.Request) {
	task, exists := s.manager.Get(request.PathValue("id"))
	if exists {
		writeJSON(response, http.StatusOK, task.Snapshot())
		return
	}
	snap := s.manager.HistoricalSnapshot(request.PathValue("id"))
	if snap == nil {
		writeError(response, http.StatusNotFound, "task not found")
		return
	}
	writeJSON(response, http.StatusOK, snap)
}

func (s *Server) listRuns(response http.ResponseWriter, request *http.Request) {
	writeJSON(response, http.StatusOK, s.manager.List())
}

func (s *Server) overview(response http.ResponseWriter, request *http.Request) {
	writeJSON(response, http.StatusOK, s.manager.Overview())
}

func (s *Server) deleteRun(response http.ResponseWriter, request *http.Request) {
	if err := s.manager.Delete(request.PathValue("id")); err != nil {
		writeError(response, http.StatusConflict, err.Error())
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) cancelRun(response http.ResponseWriter, request *http.Request) {
	if err := s.manager.Cancel(request.PathValue("id")); err != nil {
		writeError(response, http.StatusConflict, err.Error())
		return
	}
	writeJSON(response, http.StatusAccepted, map[string]string{"status": "stopping"})
}

func (s *Server) triggerFuzz(response http.ResponseWriter, request *http.Request) {
	if err := s.manager.TriggerFuzzAnalysis(request.PathValue("id")); err != nil {
		writeError(response, http.StatusConflict, err.Error())
		return
	}
	writeJSON(response, http.StatusAccepted, map[string]string{"status": "triggered"})
}

func (s *Server) coverage(response http.ResponseWriter, request *http.Request) {
	driverID, _ := strconv.Atoi(request.URL.Query().Get("target_id"))
	if driverID == 0 {
		driverID, _ = strconv.Atoi(request.URL.Query().Get("driver_id"))
	}
	data := s.manager.CoverageData(request.PathValue("id"), driverID)
	if data == nil {
		writeJSON(response, http.StatusOK, map[string]any{"available": false})
		return
	}
	writeJSON(response, http.StatusOK, data)
}

func (s *Server) coverageFunctionSources(response http.ResponseWriter, request *http.Request) {
	driverID, _ := strconv.Atoi(request.URL.Query().Get("target_id"))
	if driverID == 0 {
		driverID, _ = strconv.Atoi(request.URL.Query().Get("driver_id"))
	}
	data, err := s.manager.CoverageFunctionSources(request.PathValue("id"), driverID)
	if err != nil {
		writeError(response, http.StatusNotFound, err.Error())
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

func (s *Server) uniqueCrashes(response http.ResponseWriter, request *http.Request) {
	result, err := s.manager.UniqueCrashes(request.PathValue("id"))
	if err != nil {
		writeError(response, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (s *Server) crashAnalysisQueue(response http.ResponseWriter, request *http.Request) {
	result, err := s.manager.CrashAnalysisQueue(request.PathValue("id"))
	if err != nil {
		writeError(response, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (s *Server) removeCrashAnalysisQueueItem(response http.ResponseWriter, request *http.Request) {
	itemID := request.URL.Query().Get("item_id")
	if strings.TrimSpace(itemID) == "" {
		writeError(response, http.StatusBadRequest, "missing queue item id")
		return
	}
	if err := s.manager.RemoveCrashAnalysisQueueItem(request.PathValue("id"), itemID); err != nil {
		writeError(response, http.StatusConflict, err.Error())
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"status": "removed"})
}

func (s *Server) crashReports(response http.ResponseWriter, request *http.Request) {
	driverID, _ := strconv.Atoi(request.URL.Query().Get("driver_id"))
	seq, _ := strconv.Atoi(request.URL.Query().Get("seq"))
	if seq <= 0 {
		writeError(response, http.StatusBadRequest, "invalid snapshot version")
		return
	}
	result, err := s.manager.CrashReports(request.PathValue("id"), driverID, seq)
	if err != nil {
		writeError(response, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (s *Server) analyzeCrashReport(response http.ResponseWriter, request *http.Request) {
	driverID, _ := strconv.Atoi(request.URL.Query().Get("driver_id"))
	seq, _ := strconv.Atoi(request.URL.Query().Get("seq"))
	crashFile := request.URL.Query().Get("file")
	if seq <= 0 {
		writeError(response, http.StatusBadRequest, "invalid snapshot version")
		return
	}
	if strings.TrimSpace(crashFile) == "" {
		writeError(response, http.StatusBadRequest, "missing crash file")
		return
	}
	if err := s.manager.TriggerCrashReportAnalysis(request.PathValue("id"), driverID, seq, crashFile); err != nil {
		writeError(response, http.StatusConflict, err.Error())
		return
	}
	writeJSON(response, http.StatusAccepted, map[string]string{"status": "started"})
}

func (s *Server) snapshotDiff(response http.ResponseWriter, request *http.Request) {
	sequence, err := strconv.Atoi(request.PathValue("seq"))
	if err != nil || sequence <= 1 {
		writeError(response, http.StatusBadRequest, "invalid driver version")
		return
	}
	driverID, _ := strconv.Atoi(request.URL.Query().Get("driver_id"))
	result, err := s.manager.DriverDiff(request.PathValue("id"), driverID, sequence)
	if err != nil {
		writeError(response, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (s *Server) runHistory(response http.ResponseWriter, request *http.Request) {
	data := s.manager.HistoricalHistory(request.PathValue("id"))
	writeJSON(response, http.StatusOK, data)
}

func (s *Server) fuzzFlow(response http.ResponseWriter, request *http.Request) {
	limit, _ := strconv.Atoi(request.URL.Query().Get("limit"))
	writeJSON(response, http.StatusOK, s.manager.FuzzFlowData(request.PathValue("id"), limit))
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
	history, channel, finished := task.subscribe(afterSequence, s.manager.hasActiveCrashAnalysis(request.PathValue("id")))
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
