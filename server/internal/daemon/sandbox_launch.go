package daemon

import (
	"errors"
	"fmt"
	"os"
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
		return nil, fmt.Errorf("%w: provider %q is not a supported agent backend", errSandboxUnavailable, provider)
	}
	if d.cfg.TaskProtectedMode && d.cfg.TaskSandboxBackend == "" {
		return nil, fmt.Errorf("%w: protected mode requires a sandbox backend", errSandboxUnavailable)
	}
	backend := strings.TrimSpace(d.cfg.TaskSandboxBackend)
	if backend == "" {
		backend = "docker"
	}

	switch backend {
	case "docker":
		return d.dockerBackend(provider, config, env, agentSocket, attemptID, repos, extraCachePaths)
	case "bwrap":
		return d.bwrapBackend(provider, config, env, profileDir, agentSocket, attemptID, repos, extraCachePaths)
	default:
		return nil, fmt.Errorf("%w: unknown sandbox backend %q", errSandboxUnavailable, backend)
	}
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

// sandboxCredentialRoots rejects explicit native grants that would expose
// Git or daemon credentials. The rest of HOME is absent by construction.
func sandboxCredentialRoots(home, profileDir string) []string {
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

// sandboxPath is the PATH the sandboxed worker passes to the agent.
//
// It is the standard system path rather than the daemon's own PATH: the
// daemon's PATH points into the user's home (nvm, asdf, local bins), which the
// sandbox deliberately does not mount.
func sandboxPath() string {
	return "/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"
}
