package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// dockerAgentBinaryContainerDir is where host-isolated agent CLIs are mounted
// read-only inside the task worker. Paths stay stable so the manifest can
// reference them without leaking host layout into the container.
const dockerAgentBinaryContainerDir = "/usr/local/bin"

// DockerAgentBinaryBind maps a host agent executable into the worker container.
//
// Isolated-tool providers (codex, cursor, opencode) register a host path at
// runtime discovery time. The Docker worker image does not bundle those CLIs;
// instead the supervisor bind-mounts the resolved binary read-only at a fixed
// in-container path and rewrites ExecutablePath before the manifest crosses
// the boundary.
func DockerAgentBinaryBind(hostExecutable string) (containerExec string, bind string, err error) {
	hostExecutable = strings.TrimSpace(hostExecutable)
	if hostExecutable == "" {
		return "", "", fmt.Errorf("sandbox: agent executable path is required")
	}

	resolved := hostExecutable
	if link, linkErr := filepath.EvalSymlinks(hostExecutable); linkErr == nil && link != "" {
		resolved = link
	}
	resolved = filepath.Clean(resolved)

	info, err := os.Stat(resolved)
	if err != nil {
		return "", "", fmt.Errorf("sandbox: agent executable %q: %w", hostExecutable, err)
	}
	if info.IsDir() {
		return "", "", fmt.Errorf("sandbox: agent executable %q is a directory", hostExecutable)
	}

	base := filepath.Base(resolved)
	if base == "" || base == "." {
		return "", "", fmt.Errorf("sandbox: agent executable %q has no basename", hostExecutable)
	}

	containerExec = filepath.Join(dockerAgentBinaryContainerDir, base)
	// Docker volume syntax always uses forward slashes on the container side.
	containerExec = strings.ReplaceAll(containerExec, "\\", "/")
	bind = DockerBind(resolved, containerExec, "ro")
	return containerExec, bind, nil
}

// ProviderUsesDockerAgentBinary reports whether the provider's CLI should be
// bind-mounted for Docker-backed attempts.
func ProviderUsesDockerAgentBinary(provider string) bool {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "codex", "cursor", "opencode":
		return true
	default:
		return false
	}
}
