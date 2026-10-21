package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/daemon/sandbox"
	agentpkg "github.com/multica-ai/multica/server/pkg/agent"
)

// TestTaskIsolationE2E_DefaultConfigEnablesDockerSandbox pins the product default:
// operators get isolated attempts without setting MULTICA_TASK_SANDBOX.
func TestTaskIsolationE2E_DefaultConfigEnablesDockerSandbox(t *testing.T) {
	stageFakeAgent(t)
	t.Setenv("MULTICA_TASK_SANDBOX", "")
	t.Setenv("MULTICA_TASK_PROTECTED", "")

	cfg, err := LoadConfig(Overrides{
		ServerURL:      "http://localhost:8080",
		WorkspacesRoot: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !cfg.SandboxEnabled || cfg.TaskSandboxBackend != "docker" {
		t.Fatalf("cfg sandbox = enabled %v backend %q, want enabled true backend docker",
			cfg.SandboxEnabled, cfg.TaskSandboxBackend)
	}

	t.Setenv("MULTICA_TASK_SANDBOX", "false")
	cfg, err = LoadConfig(Overrides{
		ServerURL:      "http://localhost:8080",
		WorkspacesRoot: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("LoadConfig opt-out: %v", err)
	}
	if cfg.SandboxEnabled {
		t.Fatal("MULTICA_TASK_SANDBOX=false must disable the sandbox")
	}
}

// TestTaskIsolationE2E_OpenCodeWorkerArgv runs the real sandbox worker with a
// fake OpenCode 2.x CLI and asserts isolated argv rules survive the manifest
// boundary.
func TestTaskIsolationE2E_OpenCodeWorkerArgv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell fixture")
	}

	argvLog := filepath.Join(t.TempDir(), "opencode-argv.log")
	fakeOpenCode := filepath.Join(t.TempDir(), "opencode")
	script := `#!/bin/sh
echo "$*" >> "` + argvLog + `"
printf '{"type":"step_start","sessionID":"ses","part":{}}\n'
printf '{"type":"text","sessionID":"ses","part":{"text":"ok"}}\n'
printf '{"type":"step_finish","sessionID":"ses","part":{"reason":"stop","tokens":{"input":1,"output":1}}}\n'
`
	if err := os.WriteFile(fakeOpenCode, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake opencode: %v", err)
	}

	manifest := sandbox.Manifest{
		Provider: "opencode",
		Prompt:   "hello",
		Config: sandbox.Config{
			ExecutablePath: fakeOpenCode,
			CLIVersion:     "opencode v2.0.10",
			BuiltinRuntime: true,
			TaskID:         "task-isolation-e2e",
		},
		Exec: sandbox.ConvertExecOptions(agentpkg.ExecOptions{
			Cwd:                  t.TempDir(),
			Timeout:              30 * time.Second,
			IsolatedToolBoundary: true,
		}),
	}

	var out strings.Builder
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := sandbox.RunWorker(ctx, manifestReader(manifest), &out); err != nil {
		t.Fatalf("RunWorker: %v\nstderr frames: %s", err, out.String())
	}

	raw, err := os.ReadFile(argvLog)
	if err != nil {
		t.Fatalf("read argv log: %v", err)
	}
	joined := string(raw)
	if strings.Contains(joined, "--server") {
		t.Fatalf("unexpected --server in argv log: %s", joined)
	}
	if !strings.Contains(joined, "--standalone") {
		t.Fatalf("expected --standalone for isolated OpenCode 2.x, argv log: %s", joined)
	}
}

// TestTaskIsolationE2E_OpenCodeRejectsExternalServerInWorker is the negative
// path for custom_args that try to escape to a host-side OpenCode service.
func TestTaskIsolationE2E_OpenCodeRejectsExternalServerInWorker(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell fixture")
	}
	fakeOpenCode := filepath.Join(t.TempDir(), "opencode")
	if err := os.WriteFile(fakeOpenCode, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake opencode: %v", err)
	}

	manifest := sandbox.Manifest{
		Provider: "opencode",
		Prompt:   "hello",
		Config: sandbox.Config{
			ExecutablePath: fakeOpenCode,
			CLIVersion:     "opencode v2.0.10",
			BuiltinRuntime: true,
		},
		Exec: sandbox.ConvertExecOptions(agentpkg.ExecOptions{
			Cwd:                  t.TempDir(),
			CustomArgs:           []string{"--server", "http://127.0.0.1:4096"},
			IsolatedToolBoundary: true,
			Timeout:              5 * time.Second,
		}),
	}

	var out strings.Builder
	if err := sandbox.RunWorker(context.Background(), manifestReader(manifest), &out); err != nil {
		t.Fatalf("RunWorker: %v", err)
	}
	frame, err := sandbox.ReadFrame(bufio.NewReader(strings.NewReader(out.String())))
	if err != nil {
		t.Fatalf("read worker frame: %v", err)
	}
	if frame.Type != sandbox.FrameError || !strings.Contains(frame.Error, "not allowed") {
		t.Fatalf("expected isolated --server refusal, frame = %+v", frame)
	}
}

// TestTaskIsolationE2E_OpenCodeRealFreeTier is an optional smoke test against a
// real OpenCode install (free tier). It only checks argv wiring, not model spend.
func TestTaskIsolationE2E_OpenCodeRealFreeTier(t *testing.T) {
	if os.Getenv("MULTICA_RUN_REAL_AGENT_SMOKE") != "1" {
		t.Skip("set MULTICA_RUN_REAL_AGENT_SMOKE=1 to run real OpenCode isolation smoke")
	}
	if runtime.GOOS == "windows" {
		t.Skip("argv wrapper is POSIX-only")
	}

	argvLog := filepath.Join(t.TempDir(), "opencode-real-argv.log")
	real, err := exec.LookPath("opencode")
	if err != nil {
		t.Skip("opencode not on PATH")
	}

	wrapper := filepath.Join(t.TempDir(), "opencode-wrap")
	script := `#!/bin/sh
echo "$*" >> "` + argvLog + `"
exec "` + real + `" "$@"
`
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatalf("write wrapper: %v", err)
	}

	versionOut, err := exec.Command(real, "--version").CombinedOutput()
	if err != nil {
		t.Skipf("opencode --version failed: %v", err)
	}
	version := strings.TrimSpace(string(versionOut))
	if !strings.Contains(version, "2.") && !strings.Contains(version, "v2") {
		t.Skipf("real smoke expects OpenCode 2.x for --standalone, got %q", version)
	}

	backend, err := agentpkg.New("opencode", agentpkg.Config{
		ExecutablePath: wrapper,
		CLIVersion:     version,
		BuiltinRuntime: true,
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("new opencode backend: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, execErr := backend.Execute(ctx, "say ok", agentpkg.ExecOptions{
		Cwd:                  t.TempDir(),
		IsolatedToolBoundary: true,
		Timeout:              10 * time.Second,
	})
	if execErr != nil && !errors.Is(execErr, context.DeadlineExceeded) {
		// Auth or network issues are acceptable for a wiring smoke; argv must still be captured.
		t.Logf("Execute ended early (continuing argv check): %v", execErr)
	}

	raw, err := os.ReadFile(argvLog)
	if err != nil || len(raw) == 0 {
		t.Fatalf("wrapper did not capture argv (opencode may not have started): %v", err)
	}
	if !strings.Contains(string(raw), "--standalone") {
		t.Fatalf("expected --standalone in real argv log: %s", raw)
	}
}

func manifestReader(manifest sandbox.Manifest) *strings.Reader {
	encoded, err := json.Marshal(manifest)
	if err != nil {
		panic(err)
	}
	return strings.NewReader(string(encoded) + "\n")
}
