package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/daemon/sandbox"
	"github.com/multica-ai/multica/server/pkg/agent"
)

func TestDockerBackendBuildsRunWithPrivateMounts(t *testing.T) {
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

	backend, err := daemon.sandboxedBackend("codex", agent.Config{TaskID: "task-1"}, env, "", "", "attempt-docker-1")
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
	joined := string(raw)
	for _, want := range []string{
		"run", "--rm", "-i",
		"--name", sandbox.SanitizeContainerName("attempt-docker-1"),
		"-v", env.WorkDir + ":" + sandbox.CheckoutPath + ":rw",
		"-v", filepath.Join(env.RootDir, "home") + ":" + sandbox.HomePath + ":rw",
		"multica/task-worker:test",
		sandbox.WorkerArg,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("docker argv missing %q:\n%s", want, joined)
		}
	}
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
