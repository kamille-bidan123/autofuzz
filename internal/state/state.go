package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type Stage string

const (
	StageInit         Stage = "init"
	StageCloned       Stage = "cloned"
	StageBuilt        Stage = "built"
	StageConfigured   Stage = "configured"
	StagePreprocessed Stage = "preprocessed"
	StageComprehended Stage = "comprehended"
	StageGenerated    Stage = "generated"
	StageVerified     Stage = "verified"
	StageFuzzing      Stage = "fuzzing"
	StageBlocked      Stage = "blocked"
	StageFailed       Stage = "failed"
)

var stageOrder = map[Stage]int{
	StageInit: 0, StageCloned: 1, StageBuilt: 2,
	StageConfigured: 3, StagePreprocessed: 4, StageComprehended: 5,
	StageGenerated: 6, StageVerified: 7, StageFuzzing: 8,
}

func (s Stage) AtLeast(other Stage) bool {
	return stageOrder[s] >= stageOrder[other]
}

var orderedStages = []Stage{
	StageInit, StageCloned, StageBuilt, StageConfigured,
	StagePreprocessed, StageComprehended, StageGenerated, StageVerified, StageFuzzing,
}

type BuildAttempt struct {
	Name       string    `json:"name"`
	Builder    string    `json:"builder"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Success    bool      `json:"success"`
	LogDir     string    `json:"log_dir"`
	Error      string    `json:"error,omitempty"`
}

type ErrorRecord struct {
	Stage     Stage     `json:"stage"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

type RunState struct {
	Version             int            `json:"version"`
	Stage               Stage          `json:"stage"`
	RepositoryURL       string         `json:"repository_url"`
	SourceKind          string         `json:"source_kind,omitempty"`
	Ref                 string         `json:"ref,omitempty"`
	Commit              string         `json:"commit,omitempty"`
	ProjectName         string         `json:"project_name"`
	SourceDir           string         `json:"source_dir"`
	BuildSystem         string         `json:"build_system,omitempty"`
	Language            string         `json:"language,omitempty"`
	BuildDir            string         `json:"build_dir,omitempty"`
	InstallDir          string         `json:"install_dir,omitempty"`
	CompileCommandsPath string         `json:"compile_commands_path,omitempty"`
	StaticLibraries     []string       `json:"static_libraries,omitempty"`
	HeaderPaths         []string       `json:"header_paths,omitempty"`
	ConsumerPaths       []string       `json:"consumer_paths,omitempty"`
	BuildReportPath     string         `json:"build_report_path,omitempty"`
	LibraryReportPath   string         `json:"library_report_path,omitempty"`
	BuildMethod         string         `json:"build_method,omitempty"`
	LibraryConfigPath   string         `json:"library_config_path,omitempty"`
	OutputPath          string         `json:"output_path,omitempty"`
	GenerationTask      string         `json:"generation_task,omitempty"`
	GeneratedDrivers    []string       `json:"generated_drivers,omitempty"`
	BuildAttempts       []BuildAttempt `json:"build_attempts,omitempty"`
	Errors              []ErrorRecord  `json:"errors,omitempty"`
	Warnings            []string       `json:"warnings,omitempty"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
}

func New(repositoryURL, ref, projectName, sourceDir string) *RunState {
	now := time.Now()
	return &RunState{
		Version: 1, Stage: StageInit, RepositoryURL: repositoryURL, Ref: ref,
		ProjectName: projectName, SourceDir: sourceDir, CreatedAt: now, UpdatedAt: now,
	}
}

func Load(path string) (*RunState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result RunState
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decode state: %w", err)
	}
	if result.Version != 1 {
		return nil, fmt.Errorf("unsupported state version %d", result.Version)
	}
	return &result, nil
}

func (s *RunState) Save(path string) error {
	s.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func (s *RunState) RecordError(stage Stage, err error) {
	s.Errors = append(s.Errors, ErrorRecord{Stage: stage, Message: err.Error(), Timestamp: time.Now()})
}

// RestoreResumeStage turns a terminal status into the last stage known to have
// completed. The failed/blocked operation itself will then be retried.
func (s *RunState) RestoreResumeStage() error {
	if s.Stage != StageBlocked && s.Stage != StageFailed {
		return nil
	}
	if len(s.Errors) == 0 {
		return fmt.Errorf("state is %s but contains no error record", s.Stage)
	}
	attempted := s.Errors[len(s.Errors)-1].Stage
	for index, candidate := range orderedStages {
		if candidate == attempted {
			if index == 0 {
				s.Stage = StageInit
			} else {
				s.Stage = orderedStages[index-1]
			}
			return nil
		}
	}
	return fmt.Errorf("cannot resume unknown failed stage %q", attempted)
}
