package daemon

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/multica-ai/multica/server/internal/daemon/execenv"
	"github.com/multica-ai/multica/server/internal/daemon/sandbox"
	"github.com/multica-ai/multica/server/pkg/agent"
)

// errSandboxUnavailable reports that the task required the sandbox and the
// host could not provide it.
//
// It is a sentinel so the failure classification can say "sandbox_unavailable"
// instead of falling through to an agent-error reason: the run never reached
// an agent, and no agent-error label fits.
var errSandboxUnavailable = errors.New("sandbox unavailable")

// sandboxedBackend returns a bwrap-backed backend for one attempt.
//
// A nil backend with a nil error means the deployment did not enable the
// sandbox and the task should run on the host. Once the sandbox is enabled,
// every failure is an error: a run that was configured to be isolated never
// silently executes outside the boundary.
func (d *Daemon) sandboxedBackend(
	provider string,
	config agent.Config,
	env *execenv.Environment,
	profileDir string,
	agentSocket string,
) (agent.Backend, error) {
	if !d.cfg.SandboxEnabled {
		return nil, nil
	}
	if env == nil {
		return nil, fmt.Errorf("%w: no execution environment", errSandboxUnavailable)
	}

	bwrapPath := d.cfg.BwrapPath
	if bwrapPath == "" {
		bwrapPath = "bwrap"
	}
	resolvedBwrap, err := exec.LookPath(bwrapPath)
	if err != nil {
		return nil, fmt.Errorf("%w: bwrap is not installed (%s)", errSandboxUnavailable, bwrapPath)
	}

	self := d.cfg.SandboxSelfPath
	if self == "" {
		self, err = os.Executable()
		if err != nil {
			return nil, fmt.Errorf("%w: resolve the worker executable: %w", errSandboxUnavailable, err)
		}
	}

	homeDir := filepath.Join(env.RootDir, "home")
	tempDir := filepath.Join(env.RootDir, "tmp")
	for _, dir := range []string{homeDir, tempDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("%w: create %s: %w", errSandboxUnavailable, dir, err)
		}
	}

	binaryRoots := sandboxBinaryRoots(config.ExecutablePath)
	policy := sandbox.Policy{
		TaskRoot:     env.RootDir,
		HomeDir:      homeDir,
		TempDir:      tempDir,
		CheckoutDir:  env.WorkDir,
		RuntimeRoots: append(sandboxRuntimeRoots(), binaryRoots...),
		ExtraMounts:  sandboxExtraMounts(env),
		AgentSocket:  agentSocket,
		// The CLI's install directory is code the sandbox must execute. It
		// may live under the user's home, so it is named explicitly rather
		// than reached through a broader rule.
		AllowedRoots:   append([]string{env.RootDir}, binaryRoots...),
		ForbiddenRoots: sandboxForbiddenRoots(d.cfg.WorkspacesRoot, profileDir),
		// The signing socket lives in the profile directory, which is
		// forbidden as a tree. Naming the socket file grants exactly it.
		AllowedExactPaths: []string{agentSocket},
		Env: map[string]string{
			"PATH": sandboxPath(),
		},
	}
	args, err := sandbox.BuildArgs(policy, self)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errSandboxUnavailable, err)
	}

	sandboxConfig := sandbox.ConfigFromAgent(config)
	sandboxConfig.Env = sandboxAgentEnv(config.Env)
	backend := &sandbox.IPCBackend{
		Provider: provider,
		Config:   sandboxConfig,
		Launch: func() (*exec.Cmd, error) {
			return exec.Command(resolvedBwrap, args...), nil
		},
	}
	return backend, nil
}

// sandboxRuntimeRoots lists the read-only system roots the agent CLI needs to
// execute. Only roots that exist are included: a missing one is a host
// difference, not a reason to refuse the run.
func sandboxRuntimeRoots() []string {
	candidates := []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"}
	roots := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			roots = append(roots, candidate)
		}
	}
	return roots
}

// sandboxExtraMounts lists the per-task paths the daemon built for this
// attempt.
//
// Each of these is a path the daemon created or validated for THIS task: a
// private config root, a per-task CODEX_HOME, a settings file. None of them is
// an inherited home directory, which is what keeps one task's credentials out
// of another's sandbox.
func sandboxExtraMounts(env *execenv.Environment) []sandbox.Mount {
	var mounts []sandbox.Mount
	appendMount := func(source string, readOnly bool) {
		if source == "" {
			return
		}
		mounts = append(mounts, sandbox.Mount{Source: source, Target: source, ReadOnly: readOnly})
	}
	appendMount(env.MulticaConfigRoot, false)
	appendMount(env.CodexHome, false)
	appendMount(env.CursorDataDir, false)
	appendMount(env.HermesHome, false)
	appendMount(env.QwenpawWorkspace, false)
	appendMount(env.OpenclawConfigPath, true)
	appendMount(env.ClaudeSettingsPath, true)
	return mounts
}

// sandboxForbiddenRoots names the trees no mount may reach into.
//
// The shared workspaces root holds every task's checkout; the host home holds
// the user's SSH keys, shell history and the CLI's own credential store. The
// task's own root is the one exception BuildArgs makes.
//
// A per-task mount the daemon built elsewhere — a provider config under the
// daemon's own profile — is allowed, because the daemon named it for this
// task and it is not inherited from the host home.
func sandboxForbiddenRoots(workspacesRoot, profileDir string) []string {
	roots := make([]string, 0, 3)
	if workspacesRoot != "" {
		roots = append(roots, workspacesRoot)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		roots = append(roots, home)
	}
	// The daemon's profile holds its own credentials, the CLI's config and
	// the signing sockets of every attempt. A task must not be able to mount
	// it as a tree.
	if profileDir != "" {
		roots = append(roots, profileDir)
	}
	return roots
}

// sandboxAgentEnv rewrites the agent environment for the boundary.
//
// The daemon builds the environment around host paths under the task root. The
// private temp and HOME are mounted at fixed in-sandbox paths, so the variables
// that name them would point at directories that do not exist in there. The
// keys that point at per-task config the sandbox mounts unchanged are left
// alone.
func sandboxAgentEnv(env map[string]string) map[string]string {
	rewritten := make(map[string]string, len(env))
	for key, value := range env {
		rewritten[key] = value
	}
	rewritten["HOME"] = sandbox.HomePath
	rewritten["TMPDIR"] = sandbox.TempPath
	rewritten["TMP"] = sandbox.TempPath
	rewritten["TEMP"] = sandbox.TempPath
	// The sandbox does not mount the user's home, so a PATH that points into
	// it would resolve to nothing.
	rewritten["PATH"] = sandboxPath()
	if _, ok := rewritten["CLAUDE_CODE_TMPDIR"]; ok {
		rewritten["CLAUDE_CODE_TMPDIR"] = sandbox.TempPath
	}
	return rewritten
}

// sandboxBinaryRoots lists the directories that hold the agent CLI.
//
// A symlinked launcher is common (an npm shim in ~/.local/bin pointing at a
// package directory), so both the link's directory and the resolved target's
// directory are mounted. Mounting one directory too many is still code, not
// user data; failing to mount the real one would make the run unable to start.
func sandboxBinaryRoots(executablePath string) []string {
	if executablePath == "" {
		return nil
	}
	roots := make([]string, 0, 2)
	seen := map[string]struct{}{}
	add := func(dir string) {
		if dir == "" || dir == "." || dir == "/" {
			return
		}
		if _, ok := seen[dir]; ok {
			return
		}
		seen[dir] = struct{}{}
		roots = append(roots, dir)
	}
	add(filepath.Dir(executablePath))
	if resolved, err := filepath.EvalSymlinks(executablePath); err == nil {
		add(filepath.Dir(resolved))
	}
	return roots
}

// sandboxPath is the PATH the sandboxed worker passes to the agent.
//
// It is the standard system path rather than the daemon's own PATH: the
// daemon's PATH points into the user's home (nvm, asdf, local bins), which the
// sandbox deliberately does not mount.
func sandboxPath() string {
	return "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"
}
