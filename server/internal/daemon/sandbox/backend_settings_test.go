package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/multica-ai/multica/server/pkg/agent"
)

// TestIPCBackendRewritesClaudeSettingsPath verifies that a launcher-provided
// container path replaces the host path in the manifest, so the host layout
// never crosses the boundary.
func TestIPCBackendRewritesClaudeSettingsPath(t *testing.T) {
	hostPath := "/host/root/claude-runtime-skill-settings.json"
	containerPath := ClaudeSettingsPath

	backend := &IPCBackend{
		Provider:           "claude",
		ClaudeSettingsPath: containerPath,
		Config: Config{
			TaskID: "task-1",
		},
		Launch: manifestEchoWorker(t),
	}

	session, err := backend.Execute(t.Context(), "prompt", agent.ExecOptions{ClaudeSettingsPath: hostPath})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	result := waitForResult(t, session)
	if !strings.Contains(result, containerPath) {
		t.Fatalf("manifest did not carry the container settings path: %q", result)
	}
	if strings.Contains(result, hostPath) {
		t.Fatalf("manifest leaked the host settings path: %q", result)
	}
}

// TestIPCBackendLeavesSettingsPathUnchangedWhenNoOverride pins that bwrap
// (which mounts the host file at its own path) keeps the ExecOptions value.
func TestIPCBackendLeavesSettingsPathUnchangedWhenNoOverride(t *testing.T) {
	hostPath := "/host/root/claude-runtime-skill-settings.json"

	backend := &IPCBackend{
		Provider: "claude",
		Config: Config{
			TaskID: "task-1",
		},
		Launch: manifestEchoWorker(t),
	}

	session, err := backend.Execute(t.Context(), "prompt", agent.ExecOptions{ClaudeSettingsPath: hostPath})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	result := waitForResult(t, session)
	if !strings.Contains(result, hostPath) {
		t.Fatalf("manifest should keep the host settings path when not overridden: %q", result)
	}
}

// manifestEchoWorker returns a launcher for a fake worker that reads one
// manifest line, extracts claude_settings_path, and reports it in the result
// frame's Output field.
func manifestEchoWorker(t *testing.T) func() (*exec.Cmd, error) {
	t.Helper()
	script := `#!/bin/sh
read line
path=$(printf '%s' "$line" | sed -n 's/.*"claude_settings_path":"\([^"]*\)".*/\1/p')
printf '%s\n' "{\"type\":\"result\",\"result\":{\"Status\":\"completed\",\"Output\":\"$path\"}}"
`
	worker := filepath.Join(t.TempDir(), "worker")
	if err := os.WriteFile(worker, []byte(script), 0o755); err != nil {
		t.Fatalf("write worker: %v", err)
	}
	return func() (*exec.Cmd, error) {
		return exec.Command(worker), nil
	}
}

func waitForResult(t *testing.T, session *agent.Session) string {
	t.Helper()
	select {
	case res := <-session.Result:
		return res.Output
	case <-session.Messages:
		t.Fatal("unexpected message before result")
		return ""
	}
}
