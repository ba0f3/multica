// Package sandbox runs a task's worker, adapter and descendants inside an
// explicit filesystem and process boundary. Network policy is unchanged.
package sandbox

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const (
	sandboxRepo        = "/workspace/repo"
	sandboxHome        = "/home/agent"
	sandboxTemp        = "/tmp"
	sandboxAgentSocket = "/run/multica/ssh-agent.sock"
	sandboxWorker      = "/run/multica/worker"
	CheckoutPath       = sandboxRepo
	HomePath           = sandboxHome
	TempPath           = sandboxTemp
	WorkerArg          = "__multica_internal_task_worker"
)

type Mount struct {
	Source   string
	Target   string
	ReadOnly bool
}

type Policy struct {
	TaskRoot string
	// HomeDir is private task storage. HostHome is only the original pathname
	// at which that empty directory is mounted, never a home mount source.
	HomeDir           string
	HostHome          string
	TempDir           string
	OutputDir         string
	CheckoutDir       string
	CheckoutTarget    string
	Command           []string
	RuntimeRoots      []string
	ExtraMounts       []Mount
	Links             []NativeLink
	AgentSocket       string
	ForbiddenRoots    []string
	AllowedRoots      []string
	AllowedExactPaths []string
	Env               map[string]string
}

func BuildArgs(policy Policy, self string) ([]string, error) {
	if strings.TrimSpace(self) == "" {
		return nil, fmt.Errorf("sandbox: the worker executable is required")
	}
	for name, path := range map[string]string{"task root": policy.TaskRoot, "home": policy.HomeDir, "temp": policy.TempDir, "checkout": policy.CheckoutDir} {
		if err := nativeAbsolutePath(path); err != nil {
			return nil, fmt.Errorf("sandbox %s: %w", name, err)
		}
	}
	homeTarget := sandboxHome
	links := append([]NativeLink(nil), policy.Links...)
	if policy.HostHome != "" {
		if err := nativeAbsolutePath(policy.HostHome); err != nil {
			return nil, fmt.Errorf("sandbox home pathname: %w", err)
		}
		resolved, homeLinks, err := nativeResolveLinks(policy.HostHome)
		if err != nil {
			return nil, fmt.Errorf("sandbox home pathname: %w", err)
		}
		homeTarget = resolved
		links = appendNativeLinks(links, homeLinks...)
	}
	allowedExact := make(map[string]struct{})
	for _, path := range append(append([]string{}, policy.AllowedExactPaths...), self) {
		if path != "" {
			allowedExact[filepath.Clean(path)] = struct{}{}
		}
	}
	args := []string{"--clearenv", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try", "--new-session", "--die-with-parent", "--cap-drop", "ALL", "--proc", "/proc", "--dev", "/dev"}
	for _, path := range policy.RuntimeRoots {
		if err := checkMountSource(path, policy, allowedExact); err != nil {
			return nil, err
		}
		args = append(args, "--ro-bind", path, path)
	}
	checkoutTarget := policy.CheckoutTarget
	if checkoutTarget == "" {
		checkoutTarget = sandboxRepo
	}
	if err := nativeAbsolutePath(checkoutTarget); err != nil {
		return nil, err
	}
	for _, mount := range []Mount{{Source: policy.TempDir, Target: sandboxTemp}, {Source: policy.HomeDir, Target: homeTarget}, {Source: policy.CheckoutDir, Target: checkoutTarget}} {
		if err := checkMountSource(mount.Source, policy, allowedExact); err != nil {
			return nil, err
		}
		args = append(args, "--bind", mount.Source, mount.Target)
	}
	if policy.OutputDir != "" {
		if err := checkMountSource(policy.OutputDir, policy, allowedExact); err != nil {
			return nil, err
		}
		args = append(args, "--bind", policy.OutputDir, "/workspace/output")
	}

	// Links are created while HOME is still private. Creating them after a
	// shared profile bind could write into the host's installation or profile.
	for _, link := range links {
		inherited := false
		for _, root := range policy.RuntimeRoots {
			if isUnder(link.Path, root) {
				inherited = true
				break
			}
		}
		if inherited {
			continue
		}
		if err := nativeAbsolutePath(link.Path); err != nil || link.Target == "" {
			return nil, fmt.Errorf("sandbox: invalid native installation link %q", link.Path)
		}
		args = append(args, "--symlink", link.Target, link.Path)
	}
	mounts := append([]Mount(nil), policy.ExtraMounts...)
	sort.SliceStable(mounts, func(i, j int) bool {
		return strings.Count(mounts[i].Target, string(filepath.Separator)) < strings.Count(mounts[j].Target, string(filepath.Separator))
	})
	for _, mount := range mounts {
		if err := checkMountSource(mount.Source, policy, allowedExact); err != nil {
			return nil, err
		}
		if err := nativeAbsolutePath(mount.Target); err != nil {
			return nil, fmt.Errorf("sandbox mount target: %w", err)
		}
		resolvedTarget, err := nativeResolveExistingParent(mount.Target)
		if err != nil || resolvedTarget != mount.Target {
			return nil, fmt.Errorf("sandbox: mount target %q traverses a host symlink", mount.Target)
		}
		flag := "--bind"
		if mount.ReadOnly {
			flag = "--ro-bind"
		}
		args = append(args, flag, mount.Source, mount.Target)
	}
	if policy.AgentSocket != "" {
		if err := checkMountSource(policy.AgentSocket, policy, allowedExact); err != nil {
			return nil, err
		}
		args = append(args, "--bind", policy.AgentSocket, sandboxAgentSocket)
	}
	if err := checkMountSource(self, policy, allowedExact); err != nil {
		return nil, err
	}
	args = append(args, "--ro-bind", self, sandboxWorker)
	// Seal the empty root and home after mountpoints/links have been created.
	// Explicit child mounts keep their own writable flags.
	args = append(args, "--remount-ro", homeTarget, "--remount-ro", "/")
	env := make(map[string]string, len(policy.Env)+3)
	for key, value := range policy.Env {
		env[key] = value
	}
	env["HOME"] = sandboxHome
	if policy.HostHome != "" {
		env["HOME"] = policy.HostHome
	}
	env["TMPDIR"] = sandboxTemp
	delete(env, "SSH_AUTH_SOCK")
	if policy.AgentSocket != "" {
		env["SSH_AUTH_SOCK"] = sandboxAgentSocket
	}
	for _, key := range sortedKeys(env) {
		args = append(args, "--setenv", key, env[key])
	}
	command := policy.Command
	if len(command) == 0 {
		command = []string{sandboxWorker, WorkerArg}
	}
	return append(append(args, "--chdir", checkoutTarget, "--"), command...), nil
}

func checkMountSource(source string, policy Policy, allowedExact map[string]struct{}) error {
	if err := nativeAbsolutePath(source); err != nil {
		return fmt.Errorf("sandbox mount source: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(source)
	if err != nil {
		return fmt.Errorf("sandbox: mount source %q is not accessible: %w", source, err)
	}
	taskRoot, err := filepath.EvalSymlinks(policy.TaskRoot)
	if err != nil {
		return err
	}
	if isUnder(source, policy.TaskRoot) && !isUnder(resolved, taskRoot) {
		return fmt.Errorf("sandbox: mount source %q escapes the task root", source)
	}
	for _, broad := range []string{"/proc", "/sys", "/run", "/var/run"} {
		if resolved == broad {
			return fmt.Errorf("sandbox: broad host management root %q cannot be mounted", source)
		}
	}
	for _, forbidden := range policy.ForbiddenRoots {
		if forbidden == "" || forbidden == "/" || forbidden == "." {
			continue
		}
		root, err := nativeResolveExistingParent(forbidden)
		if err != nil {
			return err
		}
		if isUnder(root, resolved) {
			return fmt.Errorf("sandbox: mount source %q exposes forbidden root %q", source, forbidden)
		}
		if !isUnder(resolved, root) || isUnder(resolved, taskRoot) {
			continue
		}
		if _, exact := allowedExact[source]; exact {
			continue
		}
		granted := false
		for _, allowed := range policy.AllowedRoots {
			canonical, err := filepath.EvalSymlinks(allowed)
			if err == nil && isUnder(source, allowed) && isUnder(resolved, canonical) && isUnder(allowed, forbidden) {
				granted = true
				break
			}
		}
		if !granted {
			return fmt.Errorf("sandbox: mount source %q is under forbidden root %q", source, forbidden)
		}
	}
	return nil
}

func isUnder(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
