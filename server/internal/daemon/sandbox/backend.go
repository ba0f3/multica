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
	StopAttempt func() error
	// AfterReap removes attempt-owned storage after all processes stop.
	AfterReap func() error
	// Start optionally pins native process ownership until cleanup and reap.
	Start         func(*exec.Cmd) (release func(), err error)
	OnWorkerReady func()
	OnCLIStarted  func()
	WorkerCwd     string
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	spec := ConvertExecOptions(opts)
	spec.Cwd = CheckoutPath
	if b.WorkerCwd != "" {
		spec.Cwd = b.WorkerCwd
	}
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
	// A descendant may inherit stderr after the launcher exits. Boundary cleanup
	// stops the attempt; an inherited pipe must not hold cmd.Wait indefinitely.
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = time.Second
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
	start := b.Start
	if start == nil {
		start = func(cmd *exec.Cmd) (func(), error) { return func() {}, cmd.Start() }
	}
	release, err := start(cmd)
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		if b.StopAttempt != nil {
			_ = b.StopAttempt()
		}
		return nil, fmt.Errorf("sandbox: start the worker: %w", err)
	}
	var cleanupOnce sync.Once
	var cleanupErr error
	cleanup := func() error {
		cleanupOnce.Do(func() {
			if b.StopAttempt != nil {
				cleanupErr = b.StopAttempt()
			}
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			_ = stdin.Close()
			_ = stdout.Close()
			if b.AfterReap != nil {
				cleanupErr = errors.Join(cleanupErr, b.AfterReap())
			}
			if release != nil {
				release()
			}
		})
		return cleanupErr
	}
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = cleanup()
		case <-stopped:
		}
	}()
	if err := WriteManifest(stdin, manifest); err != nil {
		_ = cleanup()
		close(stopped)
		return nil, err
	}
	controlStdin := stdin
	if !b.KeepStdinOpen {
		if err := stdin.Close(); err != nil {
			_ = cleanup()
			close(stopped)
			return nil, fmt.Errorf("sandbox: close the worker stdin: %w", err)
		}
		controlStdin = nil
	}

	messages := make(chan agent.Message, 64)
	result := make(chan agent.Result, 1)
	controlFrames := make(chan Frame, 8)
	go func() {
		defer close(stopped)
		b.drain(ctx, stdout, stderr, controlFrames, messages, result, cleanup, opts.OnCLIStarted)
	}()

	session := &agent.Session{Messages: messages, Result: result}
	if controlStdin != nil {
		attachSupervisorHooks(ctx, controlStdin, controlFrames, session, opts)
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
	stdout io.Reader,
	stderr *boundedBuffer,
	controlFrames chan<- Frame,
	messages chan<- agent.Message,
	result chan<- agent.Result,
	cleanup func() error,
	onCLIStarted func(),
) {
	defer close(messages)
	defer close(result)
	defer close(controlFrames)

	finish := func(res agent.Result) {
		if err := cleanup(); err != nil {
			res.Status = "failed"
			res.Error = fmt.Sprintf("%s; sandbox cleanup: %v", res.Error, err)
		}
		if res.Error == "" {
			if tail := stderr.String(); tail != "" {
				res.Error = tail
			}
		}
		result <- res
	}

	var readyOnce, cliOnce sync.Once
	reader := bufio.NewReaderSize(stdout, 64<<10)
	for {
		frame, err := ReadFrame(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				finish(agent.Result{Status: "failed", Error: describeFailure(errNoResult, stderr)})
				return
			}
			finish(agent.Result{Status: "failed", Error: describeFailure(err, stderr)})
			return
		}
		switch frame.Type {
		case FrameWorkerReady:
			readyOnce.Do(func() {
				if b.OnWorkerReady != nil {
					b.OnWorkerReady()
				}
			})
		case FrameCLIStarted:
			cliOnce.Do(func() {
				if b.OnCLIStarted != nil {
					b.OnCLIStarted()
				}
				if onCLIStarted != nil {
					onCLIStarted()
				}
			})
		case FrameMessage:
			select {
			case messages <- *frame.Message:
			case <-ctx.Done():
				finish(agent.Result{Status: "failed", Error: ctx.Err().Error()})
				return
			}
		case FrameResult:
			finish(*frame.Result)
			return
		case FrameError:
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
