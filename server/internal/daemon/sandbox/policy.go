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
	// sandboxWorker is where the worker executable is mounted. The host path
	// is deliberately not reused: the daemon binary may live under the
	// user's home, which the boundary does not mount.
	sandboxWorker = "/run/multica/worker"
)

// CheckoutPath and HomePath are the in-sandbox paths the daemon must use when
// it rewrites a host path for the worker.
const (
	CheckoutPath = sandboxRepo
	HomePath     = sandboxHome
	TempPath     = sandboxTemp
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
	// HomeDir is the attempt's private HOME. It is used when ReadOnlyHome is
	// empty.
	HomeDir string
	// ReadOnlyHome is the host home, mounted read-only at its own path.
	//
	// The boundary is about the code and the credentials, not about the whole
	// home: a provider CLI has to find its own configuration, and hiding
	// every dotfile breaks it for no security gain. What must not be readable
	// is named in HiddenHomePaths.
	ReadOnlyHome string
	// HiddenHomePaths are paths inside ReadOnlyHome that are replaced by an
	// empty directory (for a directory) or by /dev/null (for a file), so the
	// agent sees nothing there. They are the credential stores: the Git keys,
	// the Git credential files, and this application's own token.
	HiddenHomePaths []string
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
	// AllowedRoots are directories that may be mounted even though they live
	// under a forbidden root.
	//
	// This exists for the agent CLI's own installation: an npm- or nvm-managed
	// CLI lives under the user's home, and the sandbox cannot execute it
	// unless that install directory is readable. It is code, not task data.
	AllowedRoots []string
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
		"--proc", "/proc",
		"--dev", "/dev",
	}

	allowedExact := make(map[string]struct{}, len(policy.AllowedExactPaths)+1)
	for _, allowed := range policy.AllowedExactPaths {
		if strings.TrimSpace(allowed) != "" {
			allowedExact[filepath.Clean(allowed)] = struct{}{}
		}
	}
	// The worker binary is named by the caller, not reached through a broader
	// rule, so it is allowed even when it lives under a forbidden root.
	allowedExact[filepath.Clean(self)] = struct{}{}

	if policy.ReadOnlyHome != "" {
		if !filepath.IsAbs(policy.ReadOnlyHome) {
			return nil, fmt.Errorf("sandbox: the read-only home must be absolute")
		}
		if info, err := os.Stat(policy.ReadOnlyHome); err != nil || !info.IsDir() {
			return nil, fmt.Errorf("sandbox: the read-only home %q is not a directory", policy.ReadOnlyHome)
		}
	}

	for _, runtimeRoot := range policy.RuntimeRoots {
		if err := checkMountSource(runtimeRoot, policy, allowedExact); err != nil {
			return nil, err
		}
		args = append(args, "--ro-bind", runtimeRoot, runtimeRoot)
	}

	// The worker itself runs from inside the boundary, so its executable has
	// to be there.
	if err := checkMountSource(self, policy, allowedExact); err != nil {
		return nil, err
	}
	args = append(args, "--ro-bind", self, sandboxWorker)

	writable := []Mount{
		{Source: policy.TempDir, Target: sandboxTemp},
		{Source: policy.CheckoutDir, Target: sandboxRepo},
		{Source: policy.HomeDir, Target: sandboxHome},
	}
	for _, mount := range writable {
		if err := checkMountSource(mount.Source, policy, allowedExact); err != nil {
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

	// The home is mounted read-only so a provider CLI finds its own config,
	// and then the credential paths inside it are covered by empty mounts.
	// bwrap applies mounts in order, so a later mount at a nested path wins.
	if policy.ReadOnlyHome != "" {
		args = append(args, "--ro-bind", policy.ReadOnlyHome, policy.ReadOnlyHome)
		emptyDir := filepath.Join(policy.TaskRoot, "empty-mount")
		createdEmpty := false
		for _, hidden := range policy.HiddenHomePaths {
			if strings.TrimSpace(hidden) == "" || !filepath.IsAbs(hidden) {
				return nil, fmt.Errorf("sandbox: the hidden path %q must be absolute", hidden)
			}
			if !isUnder(filepath.Clean(hidden), filepath.Clean(policy.ReadOnlyHome)) {
				return nil, fmt.Errorf("sandbox: the hidden path %q is outside the read-only home", hidden)
			}
			info, err := os.Stat(hidden)
			if err != nil {
				// Nothing to hide: the path does not exist on this host.
				continue
			}
			if info.IsDir() {
				if !createdEmpty {
					if err := os.MkdirAll(emptyDir, 0o700); err != nil {
						return nil, fmt.Errorf("sandbox: create the shadow directory: %w", err)
					}
					createdEmpty = true
				}
				args = append(args, "--ro-bind", emptyDir, hidden)
				continue
			}
			args = append(args, "--ro-bind", "/dev/null", hidden)
		}
	}

	// The private temp is mounted first. Any later mount whose source or
	// destination lives under /tmp then lands on top of it instead of being
	// hidden by it: bwrap applies mounts in order, so a bind of /tmp placed
	// after another mount removes that mount's path from the tree.
	// Extra mounts come after the home shadows. A per-task config the daemon
	// built may live inside the profile directory, which is hidden as a tree;
	// naming the exact per-task path re-exposes that path and nothing else.
	for _, mount := range policy.ExtraMounts {
		if err := checkMountSource(mount.Source, policy, allowedExact); err != nil {
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
		if err := checkMountSource(policy.AgentSocket, policy, allowedExact); err != nil {
			return nil, err
		}
		args = append(args, "--bind", policy.AgentSocket, sandboxAgentSocket)
	}

	home := sandboxHome
	if policy.ReadOnlyHome != "" {
		// The provider CLI reads its configuration from the real home path,
		// which is mounted read-only; HOME must name that path for it to
		// resolve.
		home = policy.ReadOnlyHome
	}
	// The caller's environment is applied first and the paths the boundary
	// owns are set last: a caller must not be able to point HOME at a
	// directory the boundary did not mount, or redirect the signing socket.
	env := make(map[string]string, len(policy.Env)+3)
	for key, value := range policy.Env {
		env[key] = value
	}
	env["HOME"] = home
	env["TMPDIR"] = sandboxTemp
	// Never inherit an agent socket. When the attempt has no credential the
	// run must have no SSH_AUTH_SOCK at all, rather than one that points
	// somewhere the boundary did not grant.
	delete(env, "SSH_AUTH_SOCK")
	if policy.AgentSocket != "" {
		env["SSH_AUTH_SOCK"] = sandboxAgentSocket
	}
	// Sorted so the argv is stable for tests and for log comparison.
	// bwrap takes one variable per flag: --setenv KEY VALUE.
	for _, key := range sortedKeys(env) {
		args = append(args, "--setenv", key, env[key])
	}

	args = append(args, "--chdir", sandboxRepo, "--", sandboxWorker, WorkerArg)
	return args, nil
}

// checkMountSource rejects a mount that would expose another task's or another
// user's data, and one that does not exist.
//
// A missing source is an error rather than a skipped mount: silently dropping
// a bind would start the agent with a path it expects to be there.
func checkMountSource(source string, policy Policy, allowedExact map[string]struct{}) error {
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

	if _, ok := allowedExact[cleaned]; ok {
		return nil
	}
	// The read-only home is mounted by name, not as a tree that includes its
	// credential paths, so only the exact home path is allowed here.
	if policy.ReadOnlyHome != "" && cleaned == filepath.Clean(policy.ReadOnlyHome) {
		return nil
	}

	taskRoot := filepath.Clean(policy.TaskRoot)
	for _, allowed := range policy.AllowedRoots {
		if strings.TrimSpace(allowed) == "" {
			continue
		}
		if isUnder(cleaned, filepath.Clean(allowed)) {
			return nil
		}
	}
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
