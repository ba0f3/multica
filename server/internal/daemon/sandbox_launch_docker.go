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
	"github.com/multica-ai/multica/server/internal/daemon/workercheckout"
	"github.com/multica-ai/multica/server/pkg/agent"
)

func (d *Daemon) dockerBackend(
	provider string,
	config agent.Config,
	env *execenv.Environment,
	agentSocket string,
	attemptID string,
	repos []workercheckout.Entry,
	extraCachePaths []string,
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
	)...)

	repoBinds, err := sandbox.DockerRepoCacheBinds(repos, extraCachePaths)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errSandboxUnavailable, err)
	}
	if err := repoCacheOverlapError(repos, extraCachePaths, env, homeDir, tempDir); err != nil {
		return nil, err
	}
	binds = append(binds, repoBinds...)
	if len(repos) > 0 {
		if env.MulticaConfigRoot == "" {
			return nil, fmt.Errorf("%w: repo cache requires a task config root", errSandboxUnavailable)
		}
		// Bind the manifest only after DockerConfigBinds so the .multica parent
		// directory exists when docker creates the file mount.
		binds = append(binds, sandbox.DockerBind(
			filepath.Join(env.RootDir, workercheckout.ManifestFileName),
			sandbox.RepoManifestPath,
			"ro",
		))
	}

	if agentSocket != "" {
		socketDir := filepath.Dir(agentSocket)
		if err := os.MkdirAll(socketDir, 0o700); err != nil {
			return nil, fmt.Errorf("%w: create signing socket dir: %w", errSandboxUnavailable, err)
		}
		binds = append(binds, sandbox.DockerBind(agentSocket, sandbox.AgentSocketPath, "rw"))
	}

	agentConfig := config
	if sandbox.ProviderUsesDockerAgentBinary(provider) {
		switch strings.ToLower(strings.TrimSpace(provider)) {
		case "codex":
			containerExec, codexBinds, err := sandbox.DockerCodexAgentBinds(config.ExecutablePath)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", errSandboxUnavailable, err)
			}
			binds = append(binds, codexBinds...)
			agentConfig.ExecutablePath = containerExec
		case "cursor":
			containerExec, cursorBinds, err := sandbox.DockerCursorAgentBinds(config.ExecutablePath)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", errSandboxUnavailable, err)
			}
			binds = append(binds, cursorBinds)
			agentConfig.ExecutablePath = containerExec
		case "mcode":
			containerExec, mcodeBinds, handled, err := sandbox.DockerMcodeContainerAgentBind(
				config.ExecutablePath,
				filepath.Join(env.RootDir, "mcode-container-launcher"),
			)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", errSandboxUnavailable, err)
			}
			if handled {
				binds = append(binds, mcodeBinds...)
				agentConfig.ExecutablePath = containerExec
			}
			if !handled {
				containerExec, agentBind, err := sandbox.DockerAgentBinaryBind(config.ExecutablePath)
				if err != nil {
					return nil, fmt.Errorf("%w: %w", errSandboxUnavailable, err)
				}
				binds = append(binds, agentBind)
				agentConfig.ExecutablePath = containerExec
			}
		default:
			containerExec, agentBind, err := sandbox.DockerAgentBinaryBind(config.ExecutablePath)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", errSandboxUnavailable, err)
			}
			binds = append(binds, agentBind)
			agentConfig.ExecutablePath = containerExec
		}
	}

	// Per-task QwenPaw workspace: bind it read-write at its own absolute path
	// so ExecSpec.QwenpawWorkspace (which the worker passes to `qwenpaw acp
	// --workspace`) stays valid. The path is a directory the daemon created for
	// this task, not an inherited host-home tree.
	if env.QwenpawWorkspace != "" {
		binds = append(binds, sandbox.DockerBind(env.QwenpawWorkspace, env.QwenpawWorkspace, "rw"))
	}

	// OpenClaw reads its per-task config through an absolute $include. Bind the
	// config file and its include root at their own absolute paths so the
	// wrapper's include resolution stays valid inside the container. Both are
	// per-task paths the daemon synthesized/validated for this attempt.
	if env.OpenclawConfigPath != "" {
		binds = append(binds, sandbox.DockerBind(env.OpenclawConfigPath, env.OpenclawConfigPath, "ro"))
	}
	if env.OpenclawIncludeRoot != "" {
		binds = append(binds, sandbox.DockerBind(env.OpenclawIncludeRoot, env.OpenclawIncludeRoot, "ro"))
	}

	// Bind the task-local Claude --settings file after the config binds so the
	// .multica parent directory exists when docker creates the file mount. The
	// host path is rewritten to the container path in the manifest below, so
	// the worker never sees the host layout.
	claudeSettingsContainerPath := ""
	if env.ClaudeSettingsPath != "" {
		binds = append(binds, sandbox.DockerBind(env.ClaudeSettingsPath, sandbox.ClaudeSettingsPath, "ro"))
		claudeSettingsContainerPath = sandbox.ClaudeSettingsPath
	}

	containerEnv := sandbox.ContainerEnv(agentConfig.Env)
	if provider == "mcode" {
		mcodeBinds, mcodeEnv, err := sandbox.DockerMcodeAuthBinds(homeDir, env.McodeDataDir)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errSandboxUnavailable, err)
		}
		binds = append(binds, mcodeBinds...)
		for key, value := range mcodeEnv {
			containerEnv[key] = value
		}
	}
	if provider == "opencode" && env.OpenCodeCredentialsPath != "" {
		binds = append(binds, sandbox.DockerBind(env.OpenCodeCredentialsPath, sandbox.OpenCodeCredentialsPath, "ro"))
		containerEnv[sandbox.OpenCodeCredentialsEnv] = sandbox.OpenCodeCredentialsPath
	}
	if agentSocket != "" {
		containerEnv["SSH_AUTH_SOCK"] = sandbox.AgentSocketPath
	}
	if env.WorkerCABundlePath != "" {
		// Mount the bundle read-only after the config binds so the .multica
		// parent exists, and point every TLS tool at it before the environment
		// is written to the manifest and argv.
		binds = append(binds, sandbox.DockerBind(env.WorkerCABundlePath, sandbox.RepoCABundlePath, "ro"))
		for key, value := range sandbox.CAEnv(sandbox.RepoCABundlePath) {
			containerEnv[key] = value
		}
	}
	if env.GitKnownHostsPath != "" {
		binds = append(binds, sandbox.DockerBind(env.GitKnownHostsPath, sandbox.GitKnownHostsPath, "ro"))
		containerEnv["GIT_SSH_COMMAND"] = sandbox.GitSSHCommand(sandbox.GitKnownHostsPath)
	}

	dockerUser := strings.TrimSpace(d.cfg.DockerTaskUser)
	if dockerUser == "" {
		// Match the daemon uid so bind-mounted task homes (owned by the daemon)
		// remain writable inside the worker. Override with MULTICA_DOCKER_TASK_USER
		// when the image runs as a fixed non-root user.
		dockerUser = fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	}
	identityBinds, err := sandbox.DockerUserIdentityBinds(env.RootDir, dockerUser)
	if err != nil {
		return nil, fmt.Errorf("%w: prepare Docker user: %w", errSandboxUnavailable, err)
	}
	binds = append(binds, identityBinds...)

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
	stopContainer := func() error {
		stop := exec.Command(dockerPath, "kill", containerName)
		_ = stop.Run()
		return nil
	}

	return &sandbox.IPCBackend{
		Provider:      provider,
		Config:        sandboxConfig,
		KeepStdinOpen: true,
		StopAttempt:   stopContainer,
		Launch: func() (*exec.Cmd, error) {
			return exec.Command(dockerPath, runArgs...), nil
		},
		ClaudeSettingsPath: claudeSettingsContainerPath,
	}, nil
}

// repoCacheOverlapError rejects any cache path that equals or contains one of
// the sandbox's own roots — the checkout, home, temp, or task config root —
// and vice versa. Mounting a cache over one of those would hand the worker a
// directory the boundary owns, or replace one outright.
func repoCacheOverlapError(repos []workercheckout.Entry, extraCachePaths []string, env *execenv.Environment, homeDir, tempDir string) error {
	roots := []string{env.WorkDir, homeDir, tempDir, env.MulticaConfigRoot}
	check := func(path string) error {
		path = filepath.Clean(path)
		for _, root := range roots {
			if root == "" {
				continue
			}
			if isUnderPath(path, root) || isUnderPath(root, path) {
				return fmt.Errorf("%w: repo cache path %q overlaps the sandbox root %q", errSandboxUnavailable, path, root)
			}
		}
		return nil
	}
	for _, entry := range repos {
		if err := check(entry.CachePath); err != nil {
			return err
		}
	}
	for _, path := range extraCachePaths {
		if err := check(path); err != nil {
			return err
		}
	}
	return nil
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
