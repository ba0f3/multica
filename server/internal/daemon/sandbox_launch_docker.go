package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/multica-ai/multica/server/internal/daemon/execenv"
	"github.com/multica-ai/multica/server/internal/daemon/sandbox"
	"github.com/multica-ai/multica/server/pkg/agent"
)

func (d *Daemon) dockerBackend(
	provider string,
	config agent.Config,
	env *execenv.Environment,
	agentSocket string,
	attemptID string,
) (agent.Backend, error) {
	if env == nil {
		return nil, fmt.Errorf("%w: no execution environment", errSandboxUnavailable)
	}
	dockerPath := d.cfg.DockerCLIPath
	if dockerPath == "" {
		dockerPath = "docker"
	}
	if _, err := exec.LookPath(dockerPath); err != nil {
		return nil, fmt.Errorf("%w: docker is not installed (%s)", errSandboxUnavailable, dockerPath)
	}
	image := strings.TrimSpace(d.cfg.DockerTaskImage)
	if image == "" {
		image = sandbox.DefaultDockerTaskImage
	}

	homeDir := filepath.Join(env.RootDir, "home")
	tempDir := filepath.Join(env.RootDir, "tmp")
	for _, dir := range []string{homeDir, tempDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("%w: create %s: %w", errSandboxUnavailable, dir, err)
		}
	}

	binds := []string{
		sandbox.DockerBind(env.WorkDir, sandbox.CheckoutPath, "rw"),
		sandbox.DockerBind(homeDir, sandbox.HomePath, "rw"),
		sandbox.DockerBind(tempDir, sandbox.TempPath, "rw"),
	}
	binds = append(binds, sandbox.DockerConfigBinds(
		homeDir,
		env.MulticaConfigRoot,
		env.CodexHome,
		env.CursorDataDir,
		env.HermesHome,
		filepath.Dir(env.OpenclawConfigPath),
	)...)

	if agentSocket != "" {
		socketDir := filepath.Dir(agentSocket)
		if err := os.MkdirAll(socketDir, 0o700); err != nil {
			return nil, fmt.Errorf("%w: create signing socket dir: %w", errSandboxUnavailable, err)
		}
		binds = append(binds, sandbox.DockerBind(socketDir, filepath.Dir(sandbox.AgentSocketPath), "rw"))
	}

	agentConfig := config
	if sandbox.ProviderUsesDockerAgentBinary(provider) {
		containerExec, agentBind, err := sandbox.DockerAgentBinaryBind(config.ExecutablePath)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errSandboxUnavailable, err)
		}
		binds = append(binds, agentBind)
		agentConfig.ExecutablePath = containerExec
	}

	containerEnv := sandbox.ContainerEnv(agentConfig.Env)
	if agentSocket != "" {
		containerEnv["SSH_AUTH_SOCK"] = sandbox.AgentSocketPath
	}

	dockerUser := strings.TrimSpace(d.cfg.DockerTaskUser)
	if dockerUser == "" {
		// Match the daemon uid so bind-mounted task homes (owned by the daemon)
		// remain writable inside the worker. Override with MULTICA_DOCKER_TASK_USER
		// when the image runs as a fixed non-root user.
		dockerUser = fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	}

	spec := sandbox.DockerRunSpec{
		DockerPath:    dockerPath,
		Image:         image,
		ContainerName: sandbox.SanitizeContainerName(attemptID),
		NetworkMode:   d.cfg.DockerNetworkMode,
		MemoryBytes:   d.cfg.DockerMemoryBytes,
		PIDsLimit:     d.cfg.DockerPIDsLimit,
		NanoCPUs:      d.cfg.DockerNanoCPUs,
		User:          dockerUser,
		Workdir:       sandbox.CheckoutPath,
		Env:           containerEnv,
		Binds:         binds,
		Labels: map[string]string{
			"multica.task_id":    config.TaskID,
			"multica.attempt_id": attemptID,
		},
	}
	runArgs, err := sandbox.BuildDockerRunArgs(spec, "multica", sandbox.WorkerArg)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errSandboxUnavailable, err)
	}

	sandboxConfig := sandbox.ConfigFromAgent(agentConfig)
	sandboxConfig.AttemptID = attemptID
	sandboxConfig.Env = containerEnv

	containerName := spec.ContainerName
	stopContainer := func() {
		stop := exec.Command(dockerPath, "kill", containerName)
		_ = stop.Run()
	}

	return &sandbox.IPCBackend{
		Provider:      provider,
		Config:        sandboxConfig,
		KeepStdinOpen: true,
		StopAttempt:   stopContainer,
		Launch: func() (*exec.Cmd, error) {
			return exec.Command(dockerPath, runArgs...), nil
		},
	}, nil
}

func parseDockerMemoryBytes(raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	if strings.HasSuffix(raw, "g") || strings.HasSuffix(raw, "G") {
		value, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimSuffix(raw, "g"), "G"), 64)
		if err != nil {
			return 0, err
		}
		return int64(value * (1 << 30)), nil
	}
	return strconv.ParseInt(raw, 10, 64)
}
