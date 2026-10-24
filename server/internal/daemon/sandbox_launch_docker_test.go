package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/daemon/execenv"
	"github.com/multica-ai/multica/server/internal/daemon/sandbox"
	"github.com/multica-ai/multica/server/pkg/agent"
)

func TestDockerBackendBuildsRunWithPrivateMounts(t *testing.T) {
	env, fakeCodex, joined := dockerBackendArgv(t)
	for _, want := range []string{
		"run", "--rm", "-i",
		"--name", sandbox.SanitizeContainerName("attempt-docker-1"),
		"-v", env.WorkDir + ":" + sandbox.CheckoutPath + ":rw",
		"-v", filepath.Join(env.RootDir, "home") + ":" + sandbox.HomePath + ":rw",
		"-v", fakeCodex + ":/usr/local/bin/codex:ro",
		"multica/task-worker:test",
		sandbox.WorkerArg,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("docker argv missing %q:\n%s", want, joined)
		}
	}
}

// TestDockerBackendDoesNotBindHostWorkingDirectory guards the empty
// OpenclawConfigPath case: filepath.Dir("") is ".", and a relative docker
// bind source resolves against the daemon's working directory. On a systemd
// user unit that is the daemon user's home, which would hand every worker a
// read-write mount of ~/.ssh and ~/.multica.
func TestDockerBackendDoesNotBindHostWorkingDirectory(t *testing.T) {
	_, _, joined := dockerBackendArgv(t)
	lines := strings.Split(joined, "\n")
	for i, line := range lines {
		if line != "-v" || i+1 >= len(lines) {
			continue
		}
		bind := lines[i+1]
		source := bind
		if idx := strings.Index(bind, ":"); idx >= 0 {
			source = bind[:idx]
		}
		if source == "." {
			t.Fatalf("docker bind %q mounts the daemon working directory", bind)
		}
		if strings.Contains(bind, sandbox.HomePath+"/.openclaw") {
			t.Fatalf("docker bind %q mounts openclaw state into the worker", bind)
		}
	}
}

// dockerBackendArgv runs one codex attempt through a fake docker CLI and
// returns the execution environment, mounted agent binary, and captured argv.
func dockerBackendArgv(t *testing.T) (*execenv.Environment, string, string) {
	t.Helper()
	record := filepath.Join(t.TempDir(), "argv")
	fakeDocker := filepath.Join(t.TempDir(), "docker")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + record + "\nwhile [ $# -gt 0 ]; do case \"$1\" in multica/task-worker:test) shift; break;; *) shift;; esac; done\nread _\nprintf '%s\\n' '{\"type\":\"result\",\"result\":{\"Status\":\"completed\",\"Output\":\"ok\"}}'\n"
	if err := os.WriteFile(fakeDocker, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	daemon := newSandboxTestDaemon(t, "bwrap")
	daemon.cfg.TaskSandboxBackend = "docker"
	daemon.cfg.DockerCLIPath = fakeDocker
	daemon.cfg.DockerTaskImage = "multica/task-worker:test"
	env := newSandboxTestEnv(t)

	fakeCodex := filepath.Join(t.TempDir(), "codex")
	if err := os.WriteFile(fakeCodex, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write fake codex: %v", err)
	}
	backend, err := daemon.sandboxedBackend("codex", agent.Config{
		TaskID:         "task-1",
		ExecutablePath: fakeCodex,
	}, env, "", "", "attempt-docker-1")
	if err != nil {
		t.Fatalf("sandboxedBackend: %v", err)
	}
	if backend == nil {
		t.Fatal("expected docker backend")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := backend.Execute(ctx, "prompt", agent.ExecOptions{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	_, result := collectSandboxSession(ctx, t, session)
	if result.Status != "completed" {
		t.Fatalf("result = %+v", result)
	}

	raw, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	return env, fakeCodex, string(raw)
}

func collectSandboxSession(ctx context.Context, t *testing.T, session *agent.Session) ([]agent.Message, agent.Result) {
	t.Helper()
	var messages []agent.Message
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
				t.Fatal("result channel closed")
			}
			return messages, result
		case <-ctx.Done():
			t.Fatal("timed out waiting for worker result")
		}
	}
}

func TestProtectedModeFailsClosedWithoutSandbox(t *testing.T) {
	daemon := &Daemon{logger: newDiscardLogger()}
	daemon.cfg.TaskProtectedMode = true
	backend, err := daemon.sandboxedBackend("codex", agent.Config{}, newSandboxTestEnv(t), "", "", "attempt-1")
	if err == nil {
		t.Fatal("expected protected mode to refuse host execution")
	}
	if backend != nil {
		t.Fatal("backend should be nil")
	}
}
