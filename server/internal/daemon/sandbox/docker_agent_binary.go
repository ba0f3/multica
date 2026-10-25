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
// Isolated-tool providers register a host path at runtime discovery time. The
// Docker worker image does not bundle those CLIs; instead the supervisor
// bind-mounts the resolved binary read-only at a fixed in-container path and
// rewrites ExecutablePath before the manifest crosses the boundary.
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

// DockerMcodeRuntimeBinds mounts the versioned runtime files used by the
// MiniMax Code install launcher. The launcher derives its install root from
// /usr/local/bin/mcode, so its current pointer and releases directory must be
// available under /usr/local in the worker as well.
func DockerMcodeRuntimeBinds(hostExecutable string) ([]string, error) {
	hostExecutable = strings.TrimSpace(hostExecutable)
	if hostExecutable == "" {
		return nil, fmt.Errorf("sandbox: MCode executable path is required")
	}
	resolved := hostExecutable
	if link, err := filepath.EvalSymlinks(hostExecutable); err == nil && link != "" {
		resolved = link
	}
	script, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("sandbox: read MCode launcher %q: %w", hostExecutable, err)
	}
	contents := string(script)
	if !strings.Contains(contents, `"$root/current"`) || !strings.Contains(contents, `"$root/releases/$release/.mcode-launcher"`) {
		return nil, nil
	}
	installRoot := filepath.Dir(filepath.Dir(filepath.Clean(resolved)))
	var binds []string
	for _, name := range []string{"current", "releases"} {
		source := filepath.Join(installRoot, name)
		if _, err := os.Stat(source); err != nil {
			return nil, fmt.Errorf("sandbox: MCode launcher dependency %q: %w", source, err)
		}
		target := filepath.Join(filepath.Dir(dockerAgentBinaryContainerDir), name)
		binds = append(binds, DockerBind(source, target, "ro"))
	}
	return binds, nil
}

// ProviderUsesDockerAgentBinary reports whether the provider's CLI should be
// bind-mounted for Docker-backed attempts. Every supported provider — a
// Multica-supported backend or a built-in runtime — bind-mounts its resolved
// host binary read-only into the worker image, which does not bundle agent
// CLIs. Empty and unknown names return false.
func ProviderUsesDockerAgentBinary(provider string) bool {
	return ProviderSupportsIsolatedTools(provider)
}
