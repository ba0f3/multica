package sandbox

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/multica-ai/multica/server/pkg/agent"
)

// stderrLimit bounds how much worker stderr is kept for diagnostics.
const stderrLimit = 4 << 10

// IPCBackend runs a task attempt as a sandboxed worker process and adapts its
// frames into the agent.Backend interface.
type IPCBackend struct {
	Provider string
	Config   Config
	// Launch builds the worker command. The daemon supplies docker or bwrap;
	// tests supply a plain process.
	Launch func() (*exec.Cmd, error)
	// KeepStdinOpen keeps stdin open after the manifest for bidirectional
	// Session IPC. Unit tests that use shell fake workers leave this false.
	KeepStdinOpen bool
	// StopAttempt stops the outer execution boundary (for example docker kill).
	StopAttempt func()
	// ClaudeSettingsPath is the in-container path of the task-local Claude
	// --settings file, when the launcher bind-mounted it at a path that differs
	// from the host path carried in ExecOptions.ClaudeSettingsPath. When set, it
	// replaces the host path in the manifest so the worker only ever sees the
	// mounted container path. bwrap mounts the host file at its own path, so it
	// leaves this empty.
	ClaudeSettingsPath string
}

var _ agent.Backend = (*IPCBackend)(nil)

// Execute starts the worker, writes the manifest and returns a session that
// streams the worker's frames.
func (b *IPCBackend) Execute(ctx context.Context, prompt string, opts agent.ExecOptions) (*agent.Session, error) {
	if b == nil || b.Launch == nil {
		return nil, errors.New("sandbox: no worker launcher is configured")
	}
	spec := ConvertExecOptions(opts)
	spec.Cwd = CheckoutPath
	if b.ClaudeSettingsPath != "" {
		// The launcher bound the host settings file at a fixed container path;
		// the manifest must name that path, never the host path it was copied
		// from. This keeps the host layout out of the container manifest.
		spec.ClaudeSettingsPath = b.ClaudeSettingsPath
	}
	if len(spec.CursorHookCommand) > 0 {
		spec.CursorHookCommand = append([]string(nil), spec.CursorHookCommand...)
		spec.CursorHookCommand[0] = sandboxWorker
	}
	attemptID := b.Config.AttemptID
	if attemptID == "" {
		attemptID = b.Config.TaskID
	}
	manifest := Manifest{
		TaskID:    b.Config.TaskID,
		AttemptID: attemptID,
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
	if !b.KeepStdinOpen {
		if err := stdin.Close(); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return nil, fmt.Errorf("sandbox: close the worker stdin: %w", err)
		}
		stdin = nil
	}

	messages := make(chan agent.Message, 64)
	result := make(chan agent.Result, 1)
	controlFrames := make(chan Frame, 8)
	go func() {
		b.drain(ctx, cmd, stdout, stderr, controlFrames, messages, result)
	}()

	session := &agent.Session{Messages: messages, Result: result}
	if stdin != nil {
		attachSupervisorHooks(ctx, stdin, controlFrames, session, opts)
	}
	return session, nil
}

func attachSupervisorHooks(
	ctx context.Context,
	stdin io.Writer,
	controlFrames <-chan Frame,
	session *agent.Session,
	opts agent.ExecOptions,
) {
	readResponse := func(callCtx context.Context, expect FrameType) (Frame, error) {
		for {
			select {
			case frame, ok := <-controlFrames:
				if !ok {
					return Frame{}, errors.New("sandbox: control channel closed")
				}
				if frame.Type == FrameError {
					return frame, errors.New(frame.Error)
				}
				if frame.Type == expect {
					return frame, nil
				}
			case <-callCtx.Done():
				return Frame{}, callCtx.Err()
			case <-ctx.Done():
				return Frame{}, ctx.Err()
			}
		}
	}

	if opts.EnableTaskSupplement {
		session.Supplement = func(callCtx context.Context, text string) error {
			_, err := supervisorControl(callCtx, stdin, readResponse, Frame{
				Type: FrameSupplementRequest,
				Text: text,
			}, FrameSupplementReadyResponse)
			return err
		}
		session.SupplementReady = func() bool {
			frame, err := supervisorControl(ctx, stdin, readResponse, Frame{Type: FrameSupplementReadyQuery}, FrameSupplementReadyResponse)
			if err != nil {
				return false
			}
			return frame.Bool
		}
	}
	session.ToolActivity = func() (int32, time.Duration) {
		frame, err := supervisorControl(ctx, stdin, readResponse, Frame{Type: FrameToolActivityQuery}, FrameToolActivityResponse)
		if err != nil {
			return 0, 0
		}
		return frame.Int32, time.Duration(frame.DurationS) * time.Second
	}
	session.InterruptBackgroundTools = func() bool {
		frame, err := supervisorControl(ctx, stdin, readResponse, Frame{Type: FrameInterruptBackground}, FrameInterruptResult)
		if err != nil {
			return false
		}
		return frame.Bool
	}
	session.TerminalObserved = func() bool {
		frame, err := supervisorControl(ctx, stdin, readResponse, Frame{Type: FrameTerminalObservedQuery}, FrameTerminalObservedResponse)
		if err != nil {
			return false
		}
		return frame.Bool
	}
}

func (b *IPCBackend) drain(
	ctx context.Context,
	cmd *exec.Cmd,
	stdout io.Reader,
	stderr *boundedBuffer,
	controlFrames chan<- Frame,
	messages chan<- agent.Message,
	result chan<- agent.Result,
) {
	defer close(messages)
	defer close(result)
	defer close(controlFrames)

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			if b.StopAttempt != nil {
				b.StopAttempt()
			}
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
			if b.StopAttempt != nil {
				b.StopAttempt()
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
		case FrameSupplementReadyResponse, FrameToolActivityResponse, FrameInterruptResult, FrameTerminalObservedResponse:
			select {
			case controlFrames <- frame:
			default:
			}
		default:
			// Ignore unexpected worker frames; protocol errors fail the run
			// only when they prevent reaching a terminal result.
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
