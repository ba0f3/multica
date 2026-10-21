// Package sandbox runs one task attempt inside a bubblewrap boundary.
//
// The supervisor (the daemon) stays outside; the worker — the adapter, the
// coding agent, the ACP terminal, the local MCP server and every subprocess
// they spawn — runs inside. The worker sees only the mounts the policy names,
// a private HOME and temp directory, and a private PID/IPC/UTS namespace.
//
// The network is deliberately shared: a coding task clones repositories and
// calls its model provider, so a network namespace would make every run fail.
// The boundary this package provides is the filesystem and the process tree,
// not the network.
package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Paths inside the sandbox. They are fixed so an argument a task passes to a
// tool means the same thing on every host.
const (
	sandboxRepo        = "/workspace/repo"
	sandboxHome        = "/home/agent"
	sandboxTemp        = "/tmp"
	sandboxAgentSocket = "/run/multica/ssh-agent.sock"
)

// WorkerArg selects the hidden worker entrypoint when the sandboxed process
// starts.
const WorkerArg = "__multica_internal_task_worker"

// Mount is one extra bind mount.
type Mount struct {
	Source   string
	Target   string
	ReadOnly bool
}

// Policy describes the boundary for one attempt.
type Policy struct {
	// TaskRoot is the attempt's own environment root. Every writable mount
	// must live under it (except an explicitly granted extra mount such as
	// the agent's own per-task config directory).
	TaskRoot string
	// HomeDir is the attempt's private HOME.
	HomeDir string
	// TempDir is the attempt's private temp directory.
	TempDir string
	// CheckoutDir is the task's working tree.
	CheckoutDir string
	// RuntimeRoots are the read-only roots the agent CLI needs to execute
	// (its own installation and the system libraries).
	RuntimeRoots []string
	// ExtraMounts are additional binds the daemon built for this attempt —
	// a per-task CODEX_HOME, a Claude settings file, and so on. They are
	// deliberately explicit: nothing is inherited from the host implicitly.
	ExtraMounts []Mount
	// AgentSocket, when set, is the attempt's signing socket. It is mounted
	// at sandboxAgentSocket and SSH_AUTH_SOCK points at it.
	AgentSocket string
	// ForbiddenRoots are roots no mount source may resolve under, with the
	// task root as the only exception: the shared workspaces root, the host
	// home, the repo cache. They are the paths that hold another task's or
	// another user's data.
	ForbiddenRoots []string
	// Env is the non-secret environment the worker itself needs. It is not
	// the agent environment: that travels in the manifest, because bwrap
	// arguments are visible in the process table.
	Env map[string]string
	// AllowedExactPaths are single files that may be mounted even though they
	// live under a forbidden root.
	//
	// This exists for exactly one thing: the per-attempt signing socket lives
	// in the daemon's profile directory, which holds credentials and must not
	// be mountable as a tree. Naming the socket path itself grants the socket
	// and nothing around it.
	AllowedExactPaths []string
}

// BuildArgs renders the bwrap argv for a policy.
//
// The order is fixed: environment and namespace flags, /proc and /dev, the
// mounts, the working directory, then the worker command. bwrap applies
// namespace flags before mounts, so a flag placed after a bind would be
// silently ineffective.
func BuildArgs(policy Policy, self string) ([]string, error) {
	if strings.TrimSpace(self) == "" {
		return nil, fmt.Errorf("sandbox: the worker executable is required")
	}
	for name, value := range map[string]string{
		"task root": policy.TaskRoot,
		"home":      policy.HomeDir,
		"temp":      policy.TempDir,
		"checkout":  policy.CheckoutDir,
	} {
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("sandbox: %s is required", name)
		}
		if !filepath.IsAbs(value) {
			return nil, fmt.Errorf("sandbox: %s must be absolute", name)
		}
	}

	args := []string{
		"--clearenv",
		"--unshare-user",
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
		"--unshare-cgroup-try",
		"--new-session",
		"--die-with-parent",
		"--cap-drop", "ALL",
		"--no-new-privileges",
		"--proc", "/proc",
		"--dev", "/dev",
	}

	for _, runtimeRoot := range policy.RuntimeRoots {
		if err := checkMountSource(runtimeRoot, policy); err != nil {
			return nil, err
		}
		args = append(args, "--ro-bind", runtimeRoot, runtimeRoot)
	}

	writable := []Mount{
		{Source: policy.CheckoutDir, Target: sandboxRepo},
		{Source: policy.HomeDir, Target: sandboxHome},
		{Source: policy.TempDir, Target: sandboxTemp},
	}
	writable = append(writable, policy.ExtraMounts...)
	for _, mount := range writable {
		if err := checkMountSource(mount.Source, policy); err != nil {
			return nil, err
		}
		if strings.TrimSpace(mount.Target) == "" {
			return nil, fmt.Errorf("sandbox: mount %s has no target", mount.Source)
		}
		flag := "--bind"
		if mount.ReadOnly {
			flag = "--ro-bind"
		}
		args = append(args, flag, mount.Source, mount.Target)
	}

	// The agent socket is a capability, not a secret: mounting it is what
	// lets Git sign without a private key in the sandbox.
	if policy.AgentSocket != "" {
		if err := checkMountSource(policy.AgentSocket, policy); err != nil {
			return nil, err
		}
		args = append(args, "--bind", policy.AgentSocket, sandboxAgentSocket)
	}

	env := map[string]string{
		"HOME":   sandboxHome,
		"TMPDIR": sandboxTemp,
	}
	if policy.AgentSocket != "" {
		env["SSH_AUTH_SOCK"] = sandboxAgentSocket
	}
	for key, value := range policy.Env {
		env[key] = value
	}
	// Sorted so the argv is stable for tests and for log comparison.
	for _, key := range sortedKeys(env) {
		args = append(args, "--setenv", key+"="+env[key])
	}

	args = append(args, "--chdir", sandboxRepo, "--", self, WorkerArg)
	return args, nil
}

// checkMountSource rejects a mount that would expose another task's or another
// user's data, and one that does not exist.
//
// A missing source is an error rather than a skipped mount: silently dropping
// a bind would start the agent with a path it expects to be there.
func checkMountSource(source string, policy Policy) error {
	if strings.TrimSpace(source) == "" {
		return fmt.Errorf("sandbox: empty mount source")
	}
	if !filepath.IsAbs(source) {
		return fmt.Errorf("sandbox: mount source %q must be absolute", source)
	}
	cleaned := filepath.Clean(source)
	if _, err := os.Stat(cleaned); err != nil {
		return fmt.Errorf("sandbox: mount source %q is not accessible: %w", cleaned, err)
	}

	allowedExact := make(map[string]struct{}, len(policy.AllowedExactPaths))
	for _, allowed := range policy.AllowedExactPaths {
		if strings.TrimSpace(allowed) != "" {
			allowedExact[filepath.Clean(allowed)] = struct{}{}
		}
	}
	if _, ok := allowedExact[cleaned]; ok {
		return nil
	}

	taskRoot := filepath.Clean(policy.TaskRoot)
	for _, forbidden := range policy.ForbiddenRoots {
		forbidden = filepath.Clean(forbidden)
		if forbidden == "/" || forbidden == "." {
			continue
		}
		if !isUnder(cleaned, forbidden) {
			continue
		}
		// The attempt's own root is the one allowed exception: its checkout,
		// home, temp and per-task config all live there.
		if isUnder(cleaned, taskRoot) {
			continue
		}
		return fmt.Errorf("sandbox: mount source %q is under the forbidden root %q", cleaned, forbidden)
	}
	return nil
}

// isUnder reports whether path is root itself or below it.
func isUnder(path, root string) bool {
	if path == root {
		return true
	}
	return strings.HasPrefix(path, root+string(filepath.Separator))
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
