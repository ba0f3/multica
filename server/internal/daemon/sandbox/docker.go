package sandbox

import (
	"fmt"
	"sort"
	"strings"
)

// AgentSocketPath is the SSH agent socket path inside the task container.
const AgentSocketPath = sandboxAgentSocket

// DefaultDockerTaskImage is the worker image reference when the operator does
// not set MULTICA_DOCKER_TASK_IMAGE.
const DefaultDockerTaskImage = "ghcr.io/r2d-ai/multica-task-worker:latest"

// DockerRunSpec describes one trusted docker run invocation for a task attempt.
type DockerRunSpec struct {
	DockerPath string
	Image      string
	// ContainerName is optional; when set the supervisor can stop the attempt
	// with docker kill even if the client disconnects.
	ContainerName string
	NetworkMode   string
	MemoryBytes   int64
	PIDsLimit     int64
	NanoCPUs      int64
	Env           map[string]string
	Binds         []string
	User          string
	Workdir       string
	Labels        map[string]string
}

// BuildDockerRunArgs renders argv for `docker run` without executing it.
func BuildDockerRunArgs(spec DockerRunSpec, entrypoint ...string) ([]string, error) {
	if strings.TrimSpace(spec.DockerPath) == "" {
		return nil, fmt.Errorf("sandbox: docker binary is required")
	}
	if strings.TrimSpace(spec.Image) == "" {
		return nil, fmt.Errorf("sandbox: task image is required")
	}
	if len(entrypoint) == 0 {
		return nil, fmt.Errorf("sandbox: worker entrypoint is required")
	}

	args := []string{"run", "--rm", "-i", "--init",
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
	}
	if name := strings.TrimSpace(spec.ContainerName); name != "" {
		args = append(args, "--name", name)
	}
	if spec.NetworkMode != "" {
		args = append(args, "--network", spec.NetworkMode)
	}
	if spec.MemoryBytes > 0 {
		args = append(args, "--memory", fmt.Sprintf("%d", spec.MemoryBytes))
	}
	if spec.PIDsLimit > 0 {
		args = append(args, "--pids-limit", fmt.Sprintf("%d", spec.PIDsLimit))
	}
	if spec.NanoCPUs > 0 {
		args = append(args, "--cpus", fmt.Sprintf("%.3f", float64(spec.NanoCPUs)/1e9))
	}
	if spec.User != "" {
		args = append(args, "--user", spec.User)
	}
	if spec.Workdir != "" {
		args = append(args, "--workdir", spec.Workdir)
	}
	for _, bind := range spec.Binds {
		if strings.TrimSpace(bind) == "" {
			continue
		}
		args = append(args, "-v", bind)
	}
	keys := sortedStringMapKeys(spec.Env)
	for _, key := range keys {
		args = append(args, "-e", key+"="+spec.Env[key])
	}
	labelKeys := sortedStringMapKeys(spec.Labels)
	for _, key := range labelKeys {
		args = append(args, "--label", key+"="+spec.Labels[key])
	}
	args = append(args, spec.Image)
	args = append(args, entrypoint...)
	return args, nil
}

func sortedStringMapKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// SanitizeContainerName returns a docker-safe container name fragment.
func SanitizeContainerName(attemptID string) string {
	var b strings.Builder
	b.WriteString("multica-attempt-")
	for _, r := range attemptID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	name := b.String()
	if len(name) > 128 {
		return name[:128]
	}
	return name
}
