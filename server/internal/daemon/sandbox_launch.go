package daemon

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/multica-ai/multica/server/internal/daemon/execenv"
	"github.com/multica-ai/multica/server/internal/daemon/sandbox"
	"github.com/multica-ai/multica/server/internal/daemon/workercheckout"
	"github.com/multica-ai/multica/server/pkg/agent"
)

// errSandboxUnavailable reports that the task required the sandbox and the
// host could not provide it.
//
// It is a sentinel so the failure classification can say "sandbox_unavailable"
// instead of falling through to an agent-error reason: the run never reached
// an agent, and no agent-error label fits.
var errSandboxUnavailable = errors.New("sandbox unavailable")

func parseTaskSandboxEnv(raw string) (enabled bool, backend string) {
	value := strings.TrimSpace(strings.ToLower(raw))
	switch value {
	case "0", "false", "off", "disabled", "no":
		return false, ""
	case "bwrap":
		return true, "bwrap"
	case "docker":
		return true, "docker"
	case "1", "true", "on", "yes":
		return true, "docker"
	case "":
		// Git security MVP: every task attempt is isolated unless the operator
		// opts out with MULTICA_TASK_SANDBOX=false.
		return true, "docker"
	default:
		return true, value
	}
}

// sandboxedBackend returns an isolated backend for one attempt.
//
// A nil backend with a nil error means the deployment did not enable the
// sandbox and the task should run on the host. Protected mode refuses host
// execution even when the sandbox flag is unset.
func (d *Daemon) sandboxedBackend(
	provider string,
	config agent.Config,
	env *execenv.Environment,
	profileDir string,
	agentSocket string,
	attemptID string,
	repos []workercheckout.Entry,
	extraCachePaths []string,
) (agent.Backend, error) {
	if !d.cfg.SandboxEnabled {
		if d.cfg.TaskProtectedMode {
			return nil, fmt.Errorf("%w: protected mode requires an execution boundary", errSandboxUnavailable)
		}
		return nil, nil
	}
	if !sandbox.ProviderSupportsIsolatedTools(provider) {
		return nil, fmt.Errorf("%w: provider %q is not supported in the isolated tool boundary (codex, cursor, opencode, claude, antigravity only)", errSandboxUnavailable, provider)
	}
	if d.cfg.TaskProtectedMode && d.cfg.TaskSandboxBackend == "" {
		return nil, fmt.Errorf("%w: protected mode requires a sandbox backend", errSandboxUnavailable)
	}
	backend := strings.TrimSpace(d.cfg.TaskSandboxBackend)
	if backend == "" {
		backend = "bwrap"
	}
	switch backend {
	case "docker":
		return d.dockerBackend(provider, config, env, agentSocket, attemptID, repos, extraCachePaths)
	case "bwrap":
		return d.bwrapBackend(provider, config, env, profileDir, agentSocket, attemptID)
	default:
		return nil, fmt.Errorf("%w: unknown sandbox backend %q", errSandboxUnavailable, backend)
	}
}

func (d *Daemon) bwrapBackend(
	provider string,
	config agent.Config,
	env *execenv.Environment,
	profileDir string,
	agentSocket string,
	attemptID string,
) (agent.Backend, error) {
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
	hostHome, _ := os.UserHomeDir()
	extras := sandboxExtraMounts(env)
	policy := sandbox.Policy{
		TaskRoot:        env.RootDir,
		HomeDir:         homeDir,
		ReadOnlyHome:    hostHome,
		HiddenHomePaths: sandboxHiddenHomePaths(hostHome, profileDir),
		TempDir:         tempDir,
		CheckoutDir:     env.WorkDir,
		RuntimeRoots:    append(sandboxRuntimeRoots(), binaryRoots...),
		ExtraMounts:     sandboxExtraMounts(env),
		AgentSocket:     agentSocket,
		// The CLI's install directory is code the sandbox must execute. It
		// may live under the user's home, so it is named explicitly rather
		// than reached through a broader rule. The home itself is mounted by
		// ReadOnlyHome, not through this list: allowing the home here would
		// also allow every path under it.
		AllowedRoots:   append([]string{env.RootDir}, binaryRoots...),
		ForbiddenRoots: sandboxForbiddenRoots(d.cfg.WorkspacesRoot, profileDir),
		// Per-task config paths and the signing socket live under roots the
		// boundary forbids as trees. Naming each exact path grants that path
		// and nothing around it.
		AllowedExactPaths: append([]string{agentSocket}, extraMountSources(extras)...),
		Env: map[string]string{
			"PATH": sandboxPath(),
		},
	}
	args, err := sandbox.BuildArgs(policy, self)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errSandboxUnavailable, err)
	}

	sandboxConfig := sandbox.ConfigFromAgent(config)
	sandboxConfig.AttemptID = attemptID
	sandboxConfig.Env = sandboxAgentEnv(config.Env, hostHome)
	backend := &sandbox.IPCBackend{
		Provider:      provider,
		Config:        sandboxConfig,
		KeepStdinOpen: true,
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

// extraMountSources lists the sources of the per-task extra mounts.
func extraMountSources(mounts []sandbox.Mount) []string {
	sources := make([]string, 0, len(mounts))
	for _, mount := range mounts {
		if mount.Source != "" {
			sources = append(sources, mount.Source)
		}
	}
	return sources
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
func sandboxAgentEnv(env map[string]string, home string) map[string]string {
	rewritten := make(map[string]string, len(env))
	for key, value := range env {
		rewritten[key] = value
	}
	if home == "" {
		home = sandbox.HomePath
	}
	rewritten["HOME"] = home
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

// sandboxHiddenHomePaths names the credential stores inside the host home that
// the sandbox must not be able to read.
//
// The boundary protects the code and the credentials, not the whole home: a
// provider CLI still reads its own configuration from there. These are the
// paths that would otherwise hand the agent a credential directly — the Git
// keys, the Git credential files, and this application's own session token,
// which would be a full account takeover.
//
// MULTICA_SANDBOX_HIDE adds more, one absolute path per comma, for an operator
// who keeps other tokens in the home.
func sandboxHiddenHomePaths(home, profileDir string) []string {
	if home == "" {
		return nil
	}
	paths := []string{
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".git-credentials"),
		filepath.Join(home, ".netrc"),
		filepath.Join(home, ".config", "git", "credentials"),
		// A gh token is a Git credential with the same reach as a key.
		filepath.Join(home, ".config", "gh"),
		// The CLI config holds the user's session token.
		filepath.Join(home, ".multica"),
	}
	if profileDir != "" && isUnderPath(profileDir, home) {
		paths = append(paths, profileDir)
	}
	for _, extra := range strings.Split(os.Getenv("MULTICA_SANDBOX_HIDE"), ",") {
		if extra = strings.TrimSpace(extra); extra != "" {
			paths = append(paths, extra)
		}
	}
	return paths
}

// isUnderPath reports whether path is root or below it.
func isUnderPath(path, root string) bool {
	if path == root {
		return true
	}
	return strings.HasPrefix(path, root+string(filepath.Separator))
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
