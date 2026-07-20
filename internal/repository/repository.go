package repository

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"autofuzz/internal/runner"
)

var sshGit = regexp.MustCompile(`^git@(github\.com|gitcode\.com):([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?$`)

var allowedGitHosts = map[string]bool{
	"github.com":  true,
	"gitcode.com": true,
}

func NormalizeInput(input string) (string, string, error) {
	if info, err := os.Stat(input); err == nil && info.IsDir() {
		absolute, err := filepath.Abs(input)
		if err != nil {
			return "", "", err
		}
		return absolute, "local", nil
	}
	if _, err := ProjectName(input); err != nil {
		return "", "", err
	}
	return input, "git", nil
}

func ProjectName(rawURL string) (string, error) {
	if info, err := os.Stat(rawURL); err == nil && info.IsDir() {
		absolute, err := filepath.Abs(rawURL)
		if err != nil {
			return "", err
		}
		return filepath.Base(absolute), nil
	}
	if match := sshGit.FindStringSubmatch(rawURL); match != nil {
		return strings.TrimSuffix(match[3], ".git"), nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("only github.com and gitcode.com repository URLs are supported")
	}
	host := parsed.Hostname()
	if !allowedGitHosts[host] {
		return "", fmt.Errorf("only github.com and gitcode.com repository URLs are supported")
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("expected %s URL in owner/repository form", host)
	}
	return strings.TrimSuffix(parts[1], ".git"), nil
}

func Prepare(ctx context.Context, commandRunner runner.Runner, input, kind, ref, sourceDir, logDir string) (string, error) {
	if kind == "local" {
		return CopyLocal(input, sourceDir)
	}
	return Clone(ctx, commandRunner, input, ref, sourceDir, logDir)
}

func CopyLocal(input, sourceDir string) (string, error) {
	if info, err := os.Stat(sourceDir); err == nil && info.IsDir() {
		return TreeHash(sourceDir)
	}
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		return "", err
	}
	err := filepath.WalkDir(input, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(input, path)
		if err != nil || relative == "." {
			return err
		}
		name := strings.ToLower(entry.Name())
		if entry.IsDir() && (name == ".git" || name == "build" || name == "build_asan" || name == "autofuzz-work") {
			return filepath.SkipDir
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		destination := filepath.Join(sourceDir, relative)
		if entry.IsDir() {
			return os.MkdirAll(destination, 0o755)
		}
		return copyFile(path, destination, entry)
	})
	if err != nil {
		return "", err
	}
	return TreeHash(sourceDir)
}

func copyFile(source, destination string, entry fs.DirEntry) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	info, err := entry.Info()
	if err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func TreeHash(root string) (string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(files)
	hash := sha256.New()
	for _, path := range files {
		relative, _ := filepath.Rel(root, path)
		_, _ = io.WriteString(hash, relative+"\x00")
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		_, err = io.Copy(hash, file)
		_ = file.Close()
		if err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func Clone(ctx context.Context, commandRunner runner.Runner, rawURL, ref, sourceDir, logDir string) (string, error) {
	if info, err := os.Stat(filepath.Join(sourceDir, ".git")); err == nil && info.IsDir() {
		return Commit(ctx, commandRunner, sourceDir, logDir)
	}
	if _, err := os.Stat(sourceDir); err == nil {
		return "", fmt.Errorf("source directory exists but is not a git checkout: %s", sourceDir)
	}
	args := []string{"git", "clone", "--depth", "1", "--no-recurse-submodules"}
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, rawURL, sourceDir)
	cloneCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if _, err := commandRunner.Run(cloneCtx, logDir, "clone", filepath.Dir(sourceDir), nil, args...); err != nil {
		return "", err
	}
	return Commit(ctx, commandRunner, sourceDir, logDir)
}

func Commit(ctx context.Context, commandRunner runner.Runner, sourceDir, logDir string) (string, error) {
	commitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := commandRunner.Run(commitCtx, logDir, "commit", sourceDir, nil, "git", "rev-parse", "HEAD"); err != nil {
		return "", err
	}
	data, err := os.ReadFile(filepath.Join(logDir, "commit.stdout.log"))
	if err != nil {
		return "", err
	}
	commit := strings.TrimSpace(string(data))
	if len(commit) != 40 {
		return "", fmt.Errorf("unexpected commit hash %q", commit)
	}
	return commit, nil
}
