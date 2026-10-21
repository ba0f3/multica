package sandbox

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	script := `cat >/dev/null
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
	backend := newTestBackend(t, `cat >/dev/null; exit 3`)

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
	backend := newTestBackend(t, `cat >/dev/null; printf '%s\n' 'not a frame'`)

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
	backend := newTestBackend(t, `cat >/dev/null; printf '%s\n' '{"type":"error","error":"backend unavailable"}'`)

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
	backend := newTestBackend(t, `cat >/dev/null; sleep 60`)

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
