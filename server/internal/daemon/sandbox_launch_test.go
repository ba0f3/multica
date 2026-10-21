package daemon

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/multica-ai/multica/server/internal/daemon/execenv"
	"github.com/multica-ai/multica/server/internal/daemon/sandbox"
	"github.com/multica-ai/multica/server/pkg/agent"
)

func newDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newSandboxTestEnv builds an execution environment rooted in a temp dir.
func newSandboxTestEnv(t *testing.T) *execenv.Environment {
	t.Helper()
	root := t.TempDir()
	checkout := filepath.Join(root, "workdir")
	configRoot := filepath.Join(root, "config")
	for _, dir := range []string{checkout, configRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
	}
	return &execenv.Environment{
		RootDir:           root,
		WorkDir:           checkout,
		MulticaConfigRoot: configRoot,
	}
}

func newSandboxTestDaemon(t *testing.T, bwrapPath string) *Daemon {
	t.Helper()
	daemon := &Daemon{logger: newDiscardLogger()}
	daemon.cfg.SandboxEnabled = true
	daemon.cfg.BwrapPath = bwrapPath
	// The worker executable has to exist: it is mounted into the boundary.
	self := filepath.Join(t.TempDir(), "multica")
	if err := os.WriteFile(self, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write the worker executable: %v", err)
	}
	daemon.cfg.SandboxSelfPath = self
	daemon.cfg.WorkspacesRoot = t.TempDir()
	daemon.cfg.Profile = ""
	return daemon
}

func TestSandboxBackendIsNilWhenTheSandboxIsDisabled(t *testing.T) {
	daemon := &Daemon{logger: newDiscardLogger()}
	backend, err := daemon.sandboxedBackend("claude", agent.Config{}, newSandboxTestEnv(t), "", "", "attempt-1")
	if err != nil {
		t.Fatalf("sandboxedBackend: %v", err)
	}
	if backend != nil {
		t.Fatal("a backend was returned although the sandbox is disabled")
	}
}

func TestSandboxRejectsUnsupportedProvider(t *testing.T) {
	daemon := newSandboxTestDaemon(t, filepath.Join(t.TempDir(), "bwrap"))
	backend, err := daemon.sandboxedBackend("claude", agent.Config{}, newSandboxTestEnv(t), "", "", "attempt-1")
	if err == nil {
		t.Fatal("expected unsupported provider to be rejected")
	}
	if !errors.Is(err, errSandboxUnavailable) {
		t.Fatalf("err = %v, want %v", err, errSandboxUnavailable)
	}
	if backend != nil {
		t.Fatal("backend returned for unsupported provider")
	}
	if !strings.Contains(err.Error(), "codex, cursor, opencode") {
		t.Fatalf("error should name supported providers: %v", err)
	}
}

func TestSandboxBackendFailsClosedWhenBwrapIsMissing(t *testing.T) {
	daemon := newSandboxTestDaemon(t, filepath.Join(t.TempDir(), "no-such-bwrap"))

	backend, err := daemon.sandboxedBackend("codex", agent.Config{}, newSandboxTestEnv(t), "", "", "attempt-1")
	if err == nil {
		t.Fatal("the daemon accepted a sandbox it cannot build")
	}
	if !errors.Is(err, errSandboxUnavailable) {
		t.Fatalf("err = %v, want %v", err, errSandboxUnavailable)
	}
	if backend != nil {
		t.Fatal("a backend was returned for an unbuildable sandbox")
	}
	if reason := taskRunFailureReason(err); reason != "sandbox_unavailable" {
		t.Fatalf("failure reason = %q, want sandbox_unavailable", reason)
	}
}

func TestSandboxBackendUsesBwrapWithTheTaskBoundary(t *testing.T) {
	// A fake bwrap that records its arguments and exits. The command the
	// backend builds is what matters here, not the sandbox kernel.
	record := filepath.Join(t.TempDir(), "argv")
	bwrap := filepath.Join(t.TempDir(), "bwrap")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + record + "\nread _\nexit 0\n"
	if err := os.WriteFile(bwrap, []byte(script), 0o755); err != nil {
		t.Fatalf("write the fake bwrap: %v", err)
	}
	daemon := newSandboxTestDaemon(t, bwrap)
	env := newSandboxTestEnv(t)

	backend, err := daemon.sandboxedBackend("codex", agent.Config{TaskID: "task-1"}, env, "", "", "attempt-1")
	if err != nil {
		t.Fatalf("sandboxedBackend: %v", err)
	}
	if backend == nil {
		t.Fatal("no backend was returned although the sandbox is enabled")
	}

	session, err := backend.Execute(t.Context(), "prompt", agent.ExecOptions{Cwd: env.WorkDir})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// The fake exits immediately; wait for the backend to report the failure.
	select {
	case <-session.Result:
	case <-session.Messages:
	}

	raw, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("the fake bwrap did not run: %v", err)
	}
	argv := strings.Split(strings.TrimSpace(string(raw)), "\n")
	joined := strings.Join(argv, " ")
	for _, want := range []string{
		"--unshare-user",
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
		"--die-with-parent",
		"--clearenv",
		"--chdir " + "/workspace/repo",
		sandbox.WorkerArg,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("bwrap argv is missing %q:\n%s", want, joined)
		}
	}
	// The host home must never be mounted: the whole point of the boundary.
	if home, homeErr := os.UserHomeDir(); homeErr == nil && home != "" {
		if strings.Contains(joined, "--bind "+home) {
			t.Errorf("the host home is mounted into the sandbox:\n%s", joined)
		}
	}
}

func TestSandboxForbidsTheProfileTreeButAllowsANamedPerTaskPath(t *testing.T) {
	profileRoot := t.TempDir()
	taskPath := filepath.Join(profileRoot, "hermes-state", "agent-1")
	if err := os.MkdirAll(taskPath, 0o755); err != nil {
		t.Fatalf("create the per-task path: %v", err)
	}

	// The profile as a whole holds every attempt's sockets and credentials,
	// so it is forbidden as a mount source...
	roots := sandboxForbiddenRoots(t.TempDir(), profileRoot)
	found := false
	for _, root := range roots {
		if root == profileRoot {
			found = true
		}
	}
	if !found {
		t.Fatalf("the profile directory is missing from the forbidden roots: %v", roots)
	}

	// ...but the exact per-task path the daemon built for THIS attempt is
	// named, so it can be mounted.
	env := newSandboxTestEnv(t)
	env.HermesHome = taskPath
	bwrap := filepath.Join(t.TempDir(), "bwrap")
	if err := os.WriteFile(bwrap, []byte("#!/bin/sh\nread _\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write the fake bwrap: %v", err)
	}
	daemon := newSandboxTestDaemon(t, bwrap)
	if _, err := daemon.sandboxedBackend("codex", agent.Config{}, env, profileRoot, "", "attempt-1"); err != nil {
		t.Fatalf("a named per-task path under the profile was refused: %v", err)
	}
}

func TestSandboxBackendMountsTheSigningSocket(t *testing.T) {
	record := filepath.Join(t.TempDir(), "argv")
	bwrap := filepath.Join(t.TempDir(), "bwrap")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + record + "\nread _\nexit 0\n"
	if err := os.WriteFile(bwrap, []byte(script), 0o755); err != nil {
		t.Fatalf("write the fake bwrap: %v", err)
	}
	daemon := newSandboxTestDaemon(t, bwrap)
	env := newSandboxTestEnv(t)

	socket := filepath.Join(env.RootDir, "git-agent", "ssh-agent.sock")
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		t.Fatalf("create socket dir: %v", err)
	}
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatalf("create socket: %v", err)
	}

	backend, err := daemon.sandboxedBackend("codex", agent.Config{TaskID: "task-1"}, env, "", socket, "attempt-1")
	if err != nil {
		t.Fatalf("sandboxedBackend: %v", err)
	}
	session, err := backend.Execute(t.Context(), "prompt", agent.ExecOptions{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	select {
	case <-session.Result:
	case <-session.Messages:
	}

	raw, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("the fake bwrap did not run: %v", err)
	}
	joined := strings.Join(strings.Split(strings.TrimSpace(string(raw)), "\n"), " ")
	if !strings.Contains(joined, "--bind "+socket+" /run/multica/ssh-agent.sock") {
		t.Errorf("the signing socket is not mounted:\n%s", joined)
	}
	// bwrap names one variable per flag: --setenv SSH_AUTH_SOCK <path>.
	if !strings.Contains(joined, "--setenv SSH_AUTH_SOCK /run/multica/ssh-agent.sock") {
		t.Errorf("SSH_AUTH_SOCK does not point at the mounted socket:\n%s", joined)
	}
}

func TestSandboxForbiddenRootsIncludesTheWorkspacesRootAndTheHome(t *testing.T) {
	daemon := newSandboxTestDaemon(t, "bwrap")
	roots := sandboxForbiddenRoots(daemon.cfg.WorkspacesRoot, "")
	if len(roots) == 0 {
		t.Fatal("no forbidden root was returned")
	}
	found := false
	for _, root := range roots {
		if root == daemon.cfg.WorkspacesRoot {
			found = true
		}
	}
	if !found {
		t.Fatalf("the workspaces root is missing from %v", roots)
	}
}

func TestSandboxAgentEnvNamesTheInSandboxPaths(t *testing.T) {
	hostTmp := filepath.Join(t.TempDir(), "tmp")
	env := sandboxAgentEnv(map[string]string{
		"HOME":                "/home/someone",
		"TMPDIR":              hostTmp,
		"PATH":                "/home/someone/.nvm/versions/node/v20/bin:/usr/bin",
		"CLAUDE_CODE_TMPDIR":  hostTmp,
		"MULTICA_CONFIG_ROOT": "/host/config",
	}, "/home/someone")

	// The provider CLI keeps reading its configuration from the real home,
	// which is mounted read-only; only the credential stores are hidden.
	if env["HOME"] != "/home/someone" {
		t.Errorf("HOME = %q, want the mounted read-only home", env["HOME"])
	}
	for _, key := range []string{"TMPDIR", "TMP", "TEMP", "CLAUDE_CODE_TMPDIR"} {
		if env[key] != sandbox.TempPath {
			t.Errorf("%s = %q, want %q", key, env[key], sandbox.TempPath)
		}
	}
	if strings.Contains(env["PATH"], "/home/") {
		t.Errorf("PATH still points into the host home: %q", env["PATH"])
	}
	// A per-task config path is mounted at its original path, so it is not
	// rewritten.
	if env["MULTICA_CONFIG_ROOT"] != "/host/config" {
		t.Errorf("MULTICA_CONFIG_ROOT = %q, want it unchanged", env["MULTICA_CONFIG_ROOT"])
	}
}

func TestSandboxBinaryRootsIncludesTheSymlinkAndItsTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "package", "cli.js")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("create target: %v", err)
	}
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write target: %v", err)
	}
	linkDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatalf("create link dir: %v", err)
	}
	link := filepath.Join(linkDir, "claude")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	roots := sandboxBinaryRoots(link)
	if len(roots) != 2 {
		t.Fatalf("roots = %v, want the link directory and the target directory", roots)
	}
	joined := strings.Join(roots, "\n")
	if !strings.Contains(joined, linkDir) || !strings.Contains(joined, filepath.Dir(target)) {
		t.Fatalf("roots = %v, want both %q and %q", roots, linkDir, filepath.Dir(target))
	}
}

func TestSandboxHiddenHomePathsCoverTheCredentials(t *testing.T) {
	home := t.TempDir()
	profile := filepath.Join(home, ".multica")
	paths := sandboxHiddenHomePaths(home, profile)
	joined := strings.Join(paths, "\n")
	for _, want := range []string{
		filepath.Join(home, ".ssh"),
		profile,
		filepath.Join(home, ".git-credentials"),
		filepath.Join(home, ".netrc"),
		filepath.Join(home, ".config", "git", "credentials"),
		filepath.Join(home, ".config", "gh"),
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the credential path %q is not hidden", want)
		}
	}
	// A provider's own configuration must stay readable: hiding it is what
	// breaks the CLI for no security gain.
	for _, keep := range []string{
		filepath.Join(home, ".claude"),
		filepath.Join(home, ".codex"),
		filepath.Join(home, ".config", "nvim"),
	} {
		if strings.Contains(joined, keep) {
			t.Errorf("%q is hidden, but a provider may need it", keep)
		}
	}
}

func TestSandboxHiddenHomePathsHonourOperatorAdditions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("MULTICA_SANDBOX_HIDE", filepath.Join(home, ".aws")+", "+filepath.Join(home, ".kube"))
	paths := sandboxHiddenHomePaths(home, "")
	joined := strings.Join(paths, "\n")
	if !strings.Contains(joined, filepath.Join(home, ".aws")) {
		t.Error("an operator addition was ignored")
	}
	if !strings.Contains(joined, filepath.Join(home, ".kube")) {
		t.Error("an operator addition with surrounding spaces was ignored")
	}
}
