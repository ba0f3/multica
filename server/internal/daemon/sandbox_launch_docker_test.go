package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/daemon/execenv"
	"github.com/multica-ai/multica/server/internal/daemon/sandbox"
	"github.com/multica-ai/multica/server/internal/daemon/workercheckout"
	"github.com/multica-ai/multica/server/pkg/agent"
)

func TestDockerBackendBuildsRunWithPrivateMounts(t *testing.T) {
	env, fakeCodex, joined := dockerBackendArgv(t, nil, nil)
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
	_, _, joined := dockerBackendArgv(t, nil, nil)
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
func dockerBackendArgv(t *testing.T, repos []workercheckout.Entry, extraCachePaths []string) (*execenv.Environment, string, string) {
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
	}, env, "", "", "attempt-docker-1", repos, extraCachePaths)
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
	backend, err := daemon.sandboxedBackend("codex", agent.Config{}, newSandboxTestEnv(t), "", "", "attempt-1", nil, nil)
	if err == nil {
		t.Fatal("expected protected mode to refuse host execution")
	}
	if backend != nil {
		t.Fatal("backend should be nil")
	}
}

// dockerBinds extracts the values of every `-v` flag from the newline-joined
// fake docker argv.
func dockerBinds(joined string) []string {
	lines := strings.Split(joined, "\n")
	var binds []string
	for i := 0; i < len(lines); i++ {
		if lines[i] == "-v" && i+1 < len(lines) {
			binds = append(binds, lines[i+1])
			i++
		}
	}
	return binds
}

// dockerEnv extracts the KEY=VALUE pairs of every `-e` flag from the
// newline-joined fake docker argv.
func dockerEnv(joined string) map[string]string {
	lines := strings.Split(joined, "\n")
	env := map[string]string{}
	for i := 0; i < len(lines); i++ {
		if lines[i] == "-e" && i+1 < len(lines) {
			kv := lines[i+1]
			if idx := strings.Index(kv, "="); idx >= 0 {
				env[kv[:idx]] = kv[idx+1:]
			}
			i++
		}
	}
	return env
}

func TestDockerBackendMountsRepoCacheReadOnly(t *testing.T) {
	reposRoot := t.TempDir()
	cacheA := filepath.Join(reposRoot, "workspace-1", "repo-a")
	cacheB := filepath.Join(reposRoot, "workspace-1", "repo-b")
	sibling := filepath.Join(reposRoot, "workspace-1", "repo-sibling")
	for _, dir := range []string{cacheA, cacheB, sibling} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
	}

	env, _, joined := dockerBackendArgv(t, []workercheckout.Entry{
		{URL: "https://example.com/a", CachePath: cacheA},
		{URL: "https://example.com/b", CachePath: cacheB},
	}, nil)

	binds := dockerBinds(joined)
	joinedBinds := strings.Join(binds, "\n")
	for _, want := range []string{
		cacheA + ":" + cacheA + ":ro",
		cacheB + ":" + cacheB + ":ro",
		filepath.Join(env.RootDir, workercheckout.ManifestFileName) + ":" + sandbox.RepoManifestPath + ":ro",
	} {
		if !strings.Contains(joinedBinds, want) {
			t.Errorf("docker argv missing bind %q:\n%s", want, joinedBinds)
		}
	}
	if strings.Contains(joinedBinds, sibling+":") {
		t.Errorf("a sibling repo under .repos was mounted:\n%s", joinedBinds)
	}
	if strings.Contains(joinedBinds, reposRoot+":") {
		t.Errorf("the whole .repos tree was mounted:\n%s", joinedBinds)
	}
}

func TestDockerBackendRejectsRepoCacheOverlappingWorkdir(t *testing.T) {
	env := newSandboxTestEnv(t)
	homeDir := filepath.Join(env.RootDir, "home")
	tempDir := filepath.Join(env.RootDir, "tmp")

	fakeDocker := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(fakeDocker, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	daemon := newSandboxTestDaemon(t, "bwrap")
	daemon.cfg.TaskSandboxBackend = "docker"
	daemon.cfg.DockerCLIPath = fakeDocker
	daemon.cfg.DockerTaskImage = "multica/task-worker:test"

	for _, cachePath := range []string{
		env.WorkDir,                          // equals the workdir
		filepath.Join(env.WorkDir, "nested"), // inside the workdir
		filepath.Dir(env.WorkDir),            // contains the workdir
		homeDir,                              // equals the home
		tempDir,                              // equals the temp
		env.MulticaConfigRoot,                // equals the config root
	} {
		_, err := daemon.sandboxedBackend("codex", agent.Config{TaskID: "task-1"}, env, "", "", "attempt-1",
			[]workercheckout.Entry{{URL: "https://example.com/a", CachePath: cachePath}}, nil)
		if err == nil {
			t.Errorf("cache path %q overlapping a sandbox root was accepted", cachePath)
			continue
		}
		if !errors.Is(err, errSandboxUnavailable) {
			t.Errorf("cache path %q: err = %v, want errSandboxUnavailable", cachePath, err)
		}
	}
}

func TestIsolatedMarkersReachDockerEnv(t *testing.T) {
	_, _, joined := dockerBackendArgv(t, nil, nil)
	env := dockerEnv(joined)
	if env["MULTICA_HOST_REPO_CHECKOUT"] != "disabled" {
		t.Errorf("MULTICA_HOST_REPO_CHECKOUT = %q, want disabled", env["MULTICA_HOST_REPO_CHECKOUT"])
	}
	if env["MULTICA_ISOLATED_TOOL_BOUNDARY"] != "1" {
		t.Errorf("MULTICA_ISOLATED_TOOL_BOUNDARY = %q, want 1", env["MULTICA_ISOLATED_TOOL_BOUNDARY"])
	}
}
