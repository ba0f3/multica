package sandbox

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/pkg/agent"
)

// newShellWorker builds a Launch function that runs a shell script as the
// worker. The script is the sandbox boundary's stand-in: the backend only
// knows it speaks frames over stdout.
func newShellWorker(t *testing.T, script string) func() (*exec.Cmd, error) {
	t.Helper()
	return func() (*exec.Cmd, error) {
		return exec.Command("sh", "-c", script), nil
	}
}

func newTestBackend(t *testing.T, script string) *IPCBackend {
	t.Helper()
	return &IPCBackend{
		Provider: "claude",
		Config: Config{
			ExecutablePath: "/usr/local/bin/claude",
			TaskID:         "task-1",
			RuntimeID:      "runtime-1",
		},
		Launch: newShellWorker(t, script),
	}
}

func collect(t *testing.T, session *agent.Session) ([]agent.Message, agent.Result) {
	t.Helper()
	var messages []agent.Message
	deadline := time.After(15 * time.Second)
	for {
		select {
		case message, ok := <-session.Messages:
			if !ok {
				session.Messages = nil
				continue
			}
			messages = append(messages, message)
		case result, ok := <-session.Result:
			if !ok {
				t.Fatal("the result channel closed without a result")
			}
			return messages, result
		case <-deadline:
			t.Fatal("timed out waiting for the worker")
		}
	}
}

func TestIPCBackendForwardsMessagesAndTheResult(t *testing.T) {
	// The worker reads and discards the manifest, then reports one text
	// message and a completed result.
	script := `read _
printf '%s\n' '{"type":"message","message":{"Type":"text","Content":"working"}}'
printf '%s\n' '{"type":"result","result":{"Status":"completed","Output":"done"}}'`
	backend := newTestBackend(t, script)

	session, err := backend.Execute(context.Background(), "do the thing", agent.ExecOptions{Cwd: "/workspace/repo"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	messages, result := collect(t, session)

	if len(messages) != 1 || messages[0].Content != "working" {
		t.Fatalf("messages = %+v, want one text message", messages)
	}
	if result.Status != "completed" || result.Output != "done" {
		t.Fatalf("result = %+v", result)
	}
}

func TestIPCBackendFailsWhenTheWorkerExitsWithoutAResult(t *testing.T) {
	backend := newTestBackend(t, `read _; exit 3`)

	session, err := backend.Execute(context.Background(), "prompt", agent.ExecOptions{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	_, result := collect(t, session)
	if result.Status != "failed" {
		t.Fatalf("status = %q, want failed", result.Status)
	}
}

func TestIPCBackendFailsOnAnInvalidFrame(t *testing.T) {
	backend := newTestBackend(t, `read _; printf '%s\n' 'not a frame'`)

	session, err := backend.Execute(context.Background(), "prompt", agent.ExecOptions{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	_, result := collect(t, session)
	if result.Status != "failed" || !strings.Contains(result.Error, "frame") {
		t.Fatalf("result = %+v, want a failed run that names the frame", result)
	}
}

func TestIPCBackendReportsAWorkerErrorFrame(t *testing.T) {
	backend := newTestBackend(t, `read _; printf '%s\n' '{"type":"error","error":"backend unavailable"}'`)

	session, err := backend.Execute(context.Background(), "prompt", agent.ExecOptions{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	_, result := collect(t, session)
	if result.Status != "failed" || !strings.Contains(result.Error, "backend unavailable") {
		t.Fatalf("result = %+v", result)
	}
}

func TestIPCBackendKillsTheWorkerWhenTheAttemptIsCancelled(t *testing.T) {
	// The worker outlives the context; the backend must kill it rather than
	// leave the sandboxed tree running after the task was cancelled.
	backend := newTestBackend(t, `read _; sleep 60`)

	ctx, cancel := context.WithCancel(context.Background())
	session, err := backend.Execute(ctx, "prompt", agent.ExecOptions{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	cancel()

	deadline := time.After(10 * time.Second)
	select {
	case <-session.Result:
	case <-deadline:
		t.Fatal("the worker was not stopped after the attempt was cancelled")
	}
}

func TestIPCBackendCleanupDoesNotWaitForInheritedStderr(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	backend := newTestBackend(t, `read _; sleep 60 >&2 & child=$!; printf '%s' "$child" > `+pidFile+`; printf '%s\n' '{"type":"worker_ready"}'; wait`)
	ready := make(chan struct{})
	backend.OnWorkerReady = func() { close(ready) }
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	session, err := backend.Execute(ctx, "prompt", agent.ExecOptions{})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("fixture worker did not become ready")
	}
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatal(err)
	}
	child, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Kill()
	cancel()
	select {
	case <-session.Result:
	case <-time.After(3 * time.Second):
		t.Fatal("cleanup waited for a descendant's inherited stderr pipe")
	}
}

func TestIPCBackendRequiresALauncher(t *testing.T) {
	backend := &IPCBackend{}
	if _, err := backend.Execute(context.Background(), "prompt", agent.ExecOptions{}); err == nil {
		t.Fatal("Execute succeeded without a launcher")
	}
}

func TestRunWorkerRejectsAMalformedManifest(t *testing.T) {
	if err := RunWorker(context.Background(), strings.NewReader("not a manifest\n"), &strings.Builder{}); err == nil {
		t.Fatal("RunWorker accepted a malformed manifest")
	}
}

func TestBoundedBufferStopsGrowing(t *testing.T) {
	buffer := &boundedBuffer{limit: 8}
	for _, chunk := range []string{"aaaa", "bbbb", "cccc"} {
		if _, err := buffer.Write([]byte(chunk)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if got := buffer.String(); !strings.HasPrefix(got, "aaaabbbb") || !strings.Contains(got, "truncated") {
		t.Fatalf("buffer = %q, want the first 8 bytes plus a truncation marker", got)
	}
}

func TestIPCBackendRunsInTheMountedCheckout(t *testing.T) {
	// The worker stores the manifest it received and then completes, so the
	// test can prove the host cwd was translated to the mounted path.
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	script := "cat > " + manifestPath + "\n" +
		`printf '%s\n' '{"type":"result","result":{"Status":"completed","Output":"done"}}'`
	backend := newTestBackend(t, script)

	session, err := backend.Execute(context.Background(), "prompt", agent.ExecOptions{Cwd: "/host/workspaces/task-1/workdir"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	_, result := collect(t, session)
	if result.Status != "completed" {
		t.Fatalf("result = %+v", result)
	}

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read the manifest the worker received: %v", err)
	}
	manifest, err := ReadManifest(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decode the manifest: %v", err)
	}
	if manifest.Exec.Cwd != CheckoutPath {
		t.Fatalf("cwd = %q, want %q", manifest.Exec.Cwd, CheckoutPath)
	}
}

func TestIPCBackendRepointsTheHookRelayAtTheSandboxWorker(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.json")
	script := "cat > " + manifestPath + "\n" +
		`printf '%s\n' '{"type":"result","result":{"Status":"completed","Output":"done"}}'`
	backend := newTestBackend(t, script)

	session, err := backend.Execute(context.Background(), "prompt", agent.ExecOptions{
		CursorHookCommand: []string{"/home/someone/.local/bin/multica", "__cursor_hook"},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	collect(t, session)

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read the manifest: %v", err)
	}
	manifest, err := ReadManifest(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decode the manifest: %v", err)
	}
	if len(manifest.Exec.CursorHookCommand) != 2 {
		t.Fatalf("hook command = %v", manifest.Exec.CursorHookCommand)
	}
	if manifest.Exec.CursorHookCommand[0] != sandboxWorker {
		t.Fatalf("hook binary = %q, want %q", manifest.Exec.CursorHookCommand[0], sandboxWorker)
	}
	if manifest.Exec.CursorHookCommand[1] != "__cursor_hook" {
		t.Fatalf("hook argument = %q, want it preserved", manifest.Exec.CursorHookCommand[1])
	}
}

func TestIPCNativeAttemptEventsAndCleanupPrecedeResult(t *testing.T) {
	for _, terminal := range []string{`{"type":"result","result":{"Status":"completed"}}`, `{"type":"error","error":"failed"}`, `invalid`, ``} {
		t.Run(terminal, func(t *testing.T) {
			var events []string
			var mu sync.Mutex
			add := func(s string) { mu.Lock(); defer mu.Unlock(); events = append(events, s) }
			backend := newTestBackend(t, `read _
printf '%s\n' '{"type":"worker_ready"}' '{"type":"cli_started"}' '{"type":"cli_started"}'
printf '%s\n' '`+terminal+`'`)
			backend.OnWorkerReady = func() { add("ready") }
			backend.OnCLIStarted = func() { add("cli") }
			backend.Start = func(cmd *exec.Cmd) (func(), error) {
				if err := cmd.Start(); err != nil {
					return nil, err
				}
				return func() { add("released") }, nil
			}
			backend.StopAttempt = func() error { add("stopped"); return nil }
			session, err := backend.Execute(t.Context(), "hello", agent.ExecOptions{})
			if err != nil {
				t.Fatal(err)
			}
			_, _ = collect(t, session)
			mu.Lock()
			defer mu.Unlock()
			if got := strings.Join(events, ","); got != "ready,cli,stopped,released" {
				t.Fatalf("lifecycle=%s", got)
			}
		})
	}
}

func TestIPCNativeAttemptCancellationCleansBeforeResult(t *testing.T) {
	backend := newTestBackend(t, `read _; exec sleep 30`)
	var stopped atomic.Bool
	backend.StopAttempt = func() error { stopped.Store(true); return nil }
	ctx, cancel := context.WithCancel(t.Context())
	session, err := backend.Execute(ctx, "hello", agent.ExecOptions{})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	_, _ = collect(t, session)
	if !stopped.Load() {
		t.Fatal("result delivered before cleanup")
	}
}

func TestWorkerReadyPrecedesFailedCLISpawn(t *testing.T) {
	var out bytes.Buffer
	manifest := Manifest{TaskID: "task", AttemptID: "attempt", Provider: "cursor", Prompt: "hello", Config: Config{ExecutablePath: filepath.Join(t.TempDir(), "absent")}}
	if err := runManifest(t.Context(), manifest, &out, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(&out)
	first, err := ReadFrame(reader)
	if err != nil || first.Type != FrameWorkerReady {
		t.Fatalf("first=%+v, %v", first, err)
	}
	second, err := ReadFrame(reader)
	if err != nil || second.Type != FrameError {
		t.Fatalf("failed spawn=%+v, %v", second, err)
	}
}

func TestIPCBackendOriginalCwdAndCleanupFailure(t *testing.T) {
	cwd := t.TempDir()
	manifestPath := filepath.Join(cwd, "manifest")
	backend := newTestBackend(t, `read line; printf '%s' "$line" > "$MANIFEST_PATH"; printf '%s\n' '{"type":"result","result":{"Status":"completed"}}'`)
	launch := backend.Launch
	backend.Launch = func() (*exec.Cmd, error) {
		cmd, err := launch()
		if err == nil {
			cmd.Env = append(os.Environ(), "MANIFEST_PATH="+manifestPath)
		}
		return cmd, err
	}
	backend.WorkerCwd = cwd
	backend.StopAttempt = func() error { return errors.New("controller unavailable") }
	session, err := backend.Execute(t.Context(), "hello", agent.ExecOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, result := collect(t, session)
	if result.Status != "failed" || !strings.Contains(result.Error, "controller unavailable") {
		t.Fatalf("cleanup failure lost: %+v", result)
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ReadManifest(bytes.NewReader(append(data, '\n')))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Exec.Cwd != cwd {
		t.Fatalf("cwd=%s", manifest.Exec.Cwd)
	}
}

func TestIPCBackendAlreadyCanceledDoesNotLaunch(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	launched := false
	backend := &IPCBackend{Provider: "cursor", Launch: func() (*exec.Cmd, error) { launched = true; return exec.Command("/bin/true"), nil }}
	_, err := backend.Execute(ctx, "canceled", agent.ExecOptions{})
	if !errors.Is(err, context.Canceled) || launched {
		t.Fatalf("canceled attempt reached launch: launched=%v error=%v", launched, err)
	}
}
