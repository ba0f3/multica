package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/multica-ai/multica/server/pkg/agent"
)

// TestBwrapSmokeRunsAWorkerInTheBoundary is an opt-in smoke test that starts
// a real bwrap and asserts the boundary's two promises: the task's own mounts
// are writable, and the host home and sibling tasks are not reachable.
func TestBwrapSmokeRunsAWorkerInTheBoundary(t *testing.T) {
	if os.Getenv("MULTICA_BWRAP_SMOKE") != "1" {
		t.Skip("set MULTICA_BWRAP_SMOKE=1 to run the real bwrap smoke test")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skipf("bwrap is not installed: %v", err)
	}
	root := t.TempDir()
	workspaces := filepath.Join(root, "workspaces")
	taskRoot := filepath.Join(workspaces, "task-1")
	checkout := filepath.Join(taskRoot, "workdir")
	home := filepath.Join(taskRoot, "home")
	temp := filepath.Join(taskRoot, "tmp")
	for _, dir := range []string{checkout, home, temp} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(checkout, "visible.txt"), []byte("inside"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A fake host home: the boundary must let the CLI read its config but not
	// the credential stores.
	hostHome := filepath.Join(root, "host-home")
	for _, dir := range []string{
		filepath.Join(hostHome, ".ssh"),
		filepath.Join(hostHome, ".multica"),
		filepath.Join(hostHome, ".claude"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	files := map[string]string{
		filepath.Join(hostHome, ".ssh", "id_ed25519"):       "PRIVATE KEY",
		filepath.Join(hostHome, ".multica", "config.json"):  `{"token":"session"}`,
		filepath.Join(hostHome, ".claude", "settings.json"): "provider-config",
		filepath.Join(hostHome, ".bashrc"):                  "shell-config",
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	// A sibling task and a host secret the boundary must not expose.
	sibling := filepath.Join(workspaces, "task-2", "workdir")
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatalf("mkdir sibling: %v", err)
	}
	hostSecret := filepath.Join(root, "host-secret.txt")
	if err := os.WriteFile(hostSecret, []byte("host secret"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	probe := `#!/bin/sh
{
  echo "pwd=$(pwd)"
  echo "home=$HOME"
  echo "uid=$(id -u)"
  echo "file=$(cat visible.txt)"
  echo "can_write=$(echo written > probe.txt && echo yes || echo no)"
  echo "secret=$(cat ` + hostSecret + ` 2>/dev/null || echo BLOCKED)"
  echo "siblings=$(ls ` + workspaces + ` 2>/dev/null || echo BLOCKED)"
  echo "ssh=$(ls -A ` + filepath.Join(hostHome, ".ssh") + ` 2>/dev/null | wc -l)"
  echo "multica=$(cat ` + filepath.Join(hostHome, ".multica", "config.json") + ` 2>/dev/null || echo BLOCKED)"
  echo "claude=$(cat ` + filepath.Join(hostHome, ".claude", "settings.json") + ` 2>/dev/null || echo MISSING)"
  echo "bashrc=$(cat ` + filepath.Join(hostHome, ".bashrc") + ` 2>/dev/null || echo MISSING)"
  (echo x > ` + filepath.Join(hostHome, "written-by-sandbox") + `) 2>/dev/null || echo "home_write=DENIED"
} > probe-report.txt
printf '%s\n' '{"type":"result","result":{"Status":"completed","Output":"ok"}}'
`
	script := filepath.Join(root, "worker.sh")
	if err := os.WriteFile(script, []byte(probe), 0o755); err != nil {
		t.Fatalf("write worker: %v", err)
	}

	policy := Policy{
		TaskRoot:     taskRoot,
		HomeDir:      home,
		ReadOnlyHome: hostHome,
		HiddenHomePaths: []string{
			filepath.Join(hostHome, ".ssh"),
			filepath.Join(hostHome, ".multica"),
		},
		TempDir:        temp,
		CheckoutDir:    checkout,
		RuntimeRoots:   []string{"/usr", "/bin", "/lib", "/lib64", "/etc"},
		ForbiddenRoots: []string{workspaces},
		Env:            map[string]string{},
	}
	args, err := BuildArgs(policy, script)
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	// The smoke worker is the script itself, not the multica worker entrypoint.
	args = args[:len(args)-1]

	backend := &IPCBackend{
		Provider: "shell",
		Config:   Config{TaskID: "task-1"},
		Launch:   func() (*exec.Cmd, error) { return exec.Command("bwrap", args...), nil },
	}
	session, err := backend.Execute(context.Background(), "prompt", agent.ExecOptions{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	result := <-session.Result
	if result.Status != "completed" {
		t.Fatalf("the worker did not complete: %+v", result)
	}

	raw, err := os.ReadFile(filepath.Join(checkout, "probe-report.txt"))
	if err != nil {
		t.Fatalf("read the probe report: %v", err)
	}
	report := string(raw)
	t.Logf("probe:\n%s", report)

	for _, want := range []string{
		"pwd=" + CheckoutPath,
		"home=" + hostHome,
		"file=inside",
		"can_write=yes",
		"secret=BLOCKED",
		"siblings=BLOCKED",
		// The SSH key and the application token are gone, the provider
		// config and the rest of the home are readable, and the home itself
		// cannot be written.
		"ssh=0",
		"multica=BLOCKED",
		"claude=provider-config",
		"bashrc=shell-config",
		"home_write=DENIED",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("probe report is missing %q:\n%s", want, report)
		}
	}
}
