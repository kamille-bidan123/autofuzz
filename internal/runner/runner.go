package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type Result struct {
	Argv       []string
	Dir        string
	ExitCode   int
	Duration   time.Duration
	StdoutPath string
	StderrPath string
	TimedOut   bool
}

type Runner struct {
	Verbose bool
	OnLine  func(command, stream, line string)
}

func (r Runner) Run(ctx context.Context, logDir, name, dir string, env []string, argv ...string) (Result, error) {
	return r.RunInput(ctx, logDir, name, dir, env, "", argv...)
}

func (r Runner) RunInput(ctx context.Context, logDir, name, dir string, env []string, input string, argv ...string) (Result, error) {
	return r.RunInputStreaming(ctx, logDir, name, dir, env, input, nil, nil, argv...)
}

// RunInputStreaming runs a command while preserving the normal log files and
// forwarding complete stdout/stderr lines to optional per-call callbacks.
func (r Runner) RunInputStreaming(
	ctx context.Context,
	logDir, name, dir string,
	env []string,
	input string,
	onStdout, onStderr func(string),
	argv ...string,
) (Result, error) {
	result := Result{Argv: append([]string(nil), argv...), Dir: dir, ExitCode: -1}
	if len(argv) == 0 {
		return result, errors.New("empty command")
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return result, err
	}
	result.StdoutPath = filepath.Join(logDir, name+".stdout.log")
	result.StderrPath = filepath.Join(logDir, name+".stderr.log")
	stdout, err := os.Create(result.StdoutPath)
	if err != nil {
		return result, err
	}
	defer stdout.Close()
	stderr, err := os.Create(result.StderrPath)
	if err != nil {
		return result, err
	}
	defer stderr.Close()

	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	command.Dir = dir
	command.Env = append(os.Environ(), env...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if input != "" {
		command.Stdin = strings.NewReader(input)
	}
	stdoutWriters := []io.Writer{stdout}
	stderrWriters := []io.Writer{stderr}
	if r.Verbose {
		stdoutWriters = append(stdoutWriters, os.Stdout)
		stderrWriters = append(stderrWriters, os.Stderr)
	}
	stdoutLines := &lineWriter{writers: stdoutWriters, callback: combineLineCallbacks(name, "stdout", r.OnLine, onStdout)}
	stderrLines := &lineWriter{writers: stderrWriters, callback: combineLineCallbacks(name, "stderr", r.OnLine, onStderr)}
	command.Stdout = stdoutLines
	command.Stderr = stderrLines

	metadata := fmt.Sprintf("cwd: %s\nargv: %s\n", dir, quoteArgv(argv))
	_ = os.WriteFile(filepath.Join(logDir, name+".command.log"), []byte(metadata), 0o644)

	started := time.Now()
	err = command.Start()
	if err == nil {
		err = command.Wait()
	}
	stdoutLines.Flush()
	stderrLines.Flush()
	result.Duration = time.Since(started)
	if command.ProcessState != nil {
		result.ExitCode = command.ProcessState.ExitCode()
	}
	// On any context error (timeout OR cancel), kill the entire process group
	// (Setpgid puts the command in its own group). exec.CommandContext only
	// kills the direct child, leaving fork workers / merge subprocesses as
	// orphaned CPU hogs. Killing the group prevents that.
	if ctx.Err() != nil && command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	if ctx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		return result, fmt.Errorf("command timed out after %s", result.Duration.Round(time.Second))
	}
	if ctx.Err() == context.Canceled {
		return result, fmt.Errorf("command cancelled")
	}
	if err != nil {
		return result, fmt.Errorf("command failed with exit code %d: %w", result.ExitCode, err)
	}
	return result, nil
}

func combineLineCallbacks(command, stream string, global func(string, string, string), local func(string)) func(string) {
	if global == nil && local == nil {
		return nil
	}
	return func(line string) {
		if global != nil {
			global(command, stream, line)
		}
		if local != nil {
			local(line)
		}
	}
}

type lineWriter struct {
	writers  []io.Writer
	callback func(string)
	pending  []byte
}

func (w *lineWriter) Write(data []byte) (int, error) {
	for _, writer := range w.writers {
		if _, err := writer.Write(data); err != nil {
			return 0, err
		}
	}
	if w.callback == nil {
		return len(data), nil
	}
	w.pending = append(w.pending, data...)
	for {
		index := strings.IndexByte(string(w.pending), '\n')
		if index < 0 {
			break
		}
		line := strings.TrimSuffix(string(w.pending[:index]), "\r")
		w.pending = w.pending[index+1:]
		w.callback(line)
	}
	return len(data), nil
}

func (w *lineWriter) Flush() {
	if w.callback != nil && len(w.pending) > 0 {
		w.callback(strings.TrimSuffix(string(w.pending), "\r"))
	}
	w.pending = nil
}

func quoteArgv(argv []string) string {
	quoted := make([]string, len(argv))
	for i, arg := range argv {
		quoted[i] = fmt.Sprintf("%q", arg)
	}
	return strings.Join(quoted, " ")
}
