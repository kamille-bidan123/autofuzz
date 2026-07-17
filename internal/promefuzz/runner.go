package promefuzz

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"autofuzz/internal/runner"
)

type Client struct {
	Root       string
	Python     string
	ConfigPath string
	Runner     runner.Runner
	LogsDir    string
}

type APIAssessment struct {
	Count         int
	HeaderCounts  map[string]int
	FunctionNames []string
}

func (c Client) Preprocess(ctx context.Context, libraryConfig string, poolSize, attempt int) (APIAssessment, error) {
	logDir := filepath.Join(c.LogsDir, fmt.Sprintf("preprocess-%02d", attempt))
	commandCtx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	_, err := c.Runner.Run(commandCtx, logDir, "promefuzz", c.Root, unbufferedPython,
		c.Python, "PromeFuzz.py", "--config", c.ConfigPath, "-F", libraryConfig,
		"preprocess", "--pool-size", fmt.Sprintf("%d", poolSize))
	if err != nil {
		return APIAssessment{}, err
	}
	outputPath, err := libraryOutputPath(libraryConfig)
	if err != nil {
		return APIAssessment{}, err
	}
	return AssessAPI(filepath.Join(outputPath, "preprocessor", "api.json"))
}

func (c Client) Comprehend(ctx context.Context, libraryConfig string, poolSize int) error {
	for _, task := range []string{"funcpurp", "funcrel"} {
		commandCtx, cancel := context.WithTimeout(ctx, 8*time.Hour)
		_, err := c.Runner.Run(commandCtx, filepath.Join(c.LogsDir, "comprehend-"+task), "promefuzz", c.Root, unbufferedPython,
			c.Python, "PromeFuzz.py", "--config", c.ConfigPath, "-F", libraryConfig,
			"comprehend", "--task", task, "--pool-size", fmt.Sprintf("%d", poolSize))
		cancel()
		if err != nil {
			return fmt.Errorf("comprehend %s: %w", task, err)
		}
	}
	return nil
}

func (c Client) GenerateAllCover(ctx context.Context, libraryConfig string, poolSize int, clearState bool) error {
	args := []string{c.Python, "PromeFuzz.py", "--config", c.ConfigPath, "-F", libraryConfig,
		"generate", "--task", "allcover", "--pool-size", fmt.Sprintf("%d", poolSize)}
	if clearState {
		args = append(args, "--clear-state")
	}
	commandCtx, cancel := context.WithTimeout(ctx, 4*time.Hour)
	defer cancel()
	_, err := c.Runner.Run(commandCtx, filepath.Join(c.LogsDir, "generate"), "promefuzz", c.Root, unbufferedPython, args...)
	return err
}

var unbufferedPython = []string{"PYTHONUNBUFFERED=1"}

func AssessAPI(path string) (APIAssessment, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return APIAssessment{}, err
	}
	var raw map[string]map[string][]struct {
		Location string `json:"loc"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return APIAssessment{}, fmt.Errorf("parse api.json: %w", err)
	}
	assessment := APIAssessment{HeaderCounts: map[string]int{}}
	nameSet := map[string]bool{}
	for header, functions := range raw {
		for name, locations := range functions {
			count := len(locations)
			assessment.Count += count
			assessment.HeaderCounts[header] += count
			nameSet[name] = true
		}
	}
	for name := range nameSet {
		assessment.FunctionNames = append(assessment.FunctionNames, name)
	}
	sort.Strings(assessment.FunctionNames)
	if assessment.Count == 0 {
		return assessment, fmt.Errorf("PromeFuzz extracted zero API functions")
	}
	return assessment, nil
}

// libraryOutputPath reads the generated, deliberately simple TOML without a TOML dependency.
func libraryOutputPath(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "output_path = ") {
			var value string
			if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "output_path = "))), &value); err != nil {
				return "", err
			}
			return value, nil
		}
	}
	return "", fmt.Errorf("output_path not found in %s", path)
}
