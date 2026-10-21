package sandbox

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"

	"github.com/multica-ai/multica/server/pkg/agent"
)

// stderrLimit bounds how much worker stderr is kept for diagnostics.
const stderrLimit = 4 << 10

// IPCBackend runs a task attempt as a sandboxed worker process and adapts its
// frames into the agent.Backend interface.
//
// It is a normal backend to the daemon's execution path: the drain loop, the
// idle watchdog, the result mapping and the retry logic all stay where they
// are. Nothing above this type needs to know that the agent now runs in a
// different process tree.
type IPCBackend struct {
	Provider string
	Config   Config
	// Launch builds the worker command. The daemon supplies the bwrap
	// launcher; a test supplies a plain process.
	Launch func() (*exec.Cmd, error)
}

var _ agent.Backend = (*IPCBackend)(nil)

// Execute starts the worker, writes the manifest and returns a session that
// streams the worker's frames.
func (b *IPCBackend) Execute(ctx context.Context, prompt string, opts agent.ExecOptions) (*agent.Session, error) {
	if b == nil || b.Launch == nil {
		return nil, errors.New("sandbox: no worker launcher is configured")
	}
	spec := ConvertExecOptions(opts)
	// The checkout is mounted at a fixed path inside the boundary, so the
	// host path the daemon knows does not exist in there.
	spec.Cwd = CheckoutPath
	// A hook relay names the daemon binary by its host path. Inside the
	// boundary that binary lives at the worker mount instead.
	if len(spec.CursorHookCommand) > 0 {
		spec.CursorHookCommand = append([]string(nil), spec.CursorHookCommand...)
		spec.CursorHookCommand[0] = sandboxWorker
	}
	manifest := Manifest{
		TaskID:    b.Config.TaskID,
		AttemptID: b.Config.TaskID,
		Provider:  b.Provider,
		Prompt:    prompt,
		Config:    b.Config,
		Exec:      spec,
	}

	cmd, err := b.Launch()
	if err != nil {
		return nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("sandbox: open the worker stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("sandbox: open the worker stdout: %w", err)
	}
	stderr := &boundedBuffer{limit: stderrLimit}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("sandbox: start the worker: %w", err)
	}

	if err := WriteManifest(stdin, manifest); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, err
	}
	if err := stdin.Close(); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("sandbox: close the worker stdin: %w", err)
	}

	messages := make(chan agent.Message, 64)
	result := make(chan agent.Result, 1)
	go func() {
		b.drain(ctx, cmd, stdout, stderr, messages, result)
	}()
	return &agent.Session{Messages: messages, Result: result}, nil
}

// drain reads frames until the worker reports a result or exits.
//
// Every failure path sends exactly one result and closes both channels: a
// worker that dies silently must fail the run rather than leave it waiting
// forever.
func (b *IPCBackend) drain(
	ctx context.Context,
	cmd *exec.Cmd,
	stdout io.Reader,
	stderr *boundedBuffer,
	messages chan<- agent.Message,
	result chan<- agent.Result,
) {
	defer close(messages)
	defer close(result)

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			// Cancelling the attempt kills the whole worker tree: bwrap
			// was started with --die-with-parent, so the sandboxed
			// processes go with it.
			_ = cmd.Process.Kill()
		case <-stop:
		}
	}()

	finish := func(res agent.Result) {
		if res.Error == "" {
			if tail := stderr.String(); tail != "" {
				res.Error = tail
			}
		}
		result <- res
	}

	reader := bufio.NewReaderSize(stdout, 64<<10)
	for {
		frame, err := ReadFrame(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				_ = cmd.Wait()
				finish(agent.Result{Status: "failed", Error: describeFailure(errNoResult, stderr)})
				return
			}
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			finish(agent.Result{Status: "failed", Error: describeFailure(err, stderr)})
			return
		}
		switch frame.Type {
		case FrameMessage:
			messages <- *frame.Message
		case FrameResult:
			finish(*frame.Result)
			_ = cmd.Wait()
			return
		case FrameError:
			_ = cmd.Wait()
			finish(agent.Result{Status: "failed", Error: describeFailure(errors.New(frame.Error), stderr)})
			return
		}
	}
}

func describeFailure(err error, stderr *boundedBuffer) string {
	message := err.Error()
	if tail := stderr.String(); tail != "" {
		message += ": " + tail
	}
	return message
}

// boundedBuffer keeps the first `limit` bytes written to it.
//
// It is a ring only in the sense that it stops growing: stderr is diagnostic
// context for a failure, not a transcript, and an agent that logs for an hour
// must not consume the supervisor's memory.
type boundedBuffer struct {
	mu        sync.Mutex
	limit     int
	buffer    []byte
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - len(b.buffer)
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		b.buffer = append(b.buffer, p[:remaining]...)
		b.truncated = true
		return len(p), nil
	}
	b.buffer = append(b.buffer, p...)
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.buffer) == 0 {
		return ""
	}
	text := string(b.buffer)
	if b.truncated {
		text += " [truncated]"
	}
	return text
}
