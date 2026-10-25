package sandbox

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/multica-ai/multica/server/internal/daemon/workercheckout"
)

// RepoManifestPath is the in-container path of the task repo cache manifest,
// which the daemon writes and the worker CLI reads.
const RepoManifestPath = HomePath + "/.multica/" + workercheckout.ManifestFileName

// RepoCABundlePath is the in-container path of the CA bundle the worker's
// git/curl/node/python must trust for private Git hosts.
const RepoCABundlePath = HomePath + "/.multica/ca-bundle.pem"

// ClaudeSettingsPath is the in-container path of the task-local Claude Code
// --settings file. dockerBackend binds the host file here; bwrap already mounts
// it at its own host path, so only Docker needs this fixed container path.
const ClaudeSettingsPath = HomePath + "/.multica/claude-settings.json"

// CAEnv returns the environment variables that point a worker's TLS tooling at
// the mounted CA bundle, all set to bundlePath.
func CAEnv(bundlePath string) map[string]string {
	return map[string]string{
		"GIT_SSL_CAINFO":      bundlePath,
		"SSL_CERT_FILE":       bundlePath,
		"CURL_CA_BUNDLE":      bundlePath,
		"NODE_EXTRA_CA_CERTS": bundlePath,
		"REQUESTS_CA_BUNDLE":  bundlePath,
	}
}

// ContainerEnv rewrites agent environment variables to the fixed in-container
// paths used by the Docker worker. Keys managed by the launcher are replaced
// even when the task supplied a host path.
func ContainerEnv(env map[string]string) map[string]string {
	rewritten := make(map[string]string, len(env)+8)
	for key, value := range env {
		rewritten[key] = value
	}
	rewritten["HOME"] = HomePath
	rewritten["TMPDIR"] = TempPath
	rewritten["TMP"] = TempPath
	rewritten["TEMP"] = TempPath
	rewritten["PATH"] = containerPath()
	// The Docker worker is always isolated, so the markers are fixed here and
	// never depend on the daemon's later runTask assignment order.
	rewritten["MULTICA_ISOLATED_TOOL_BOUNDARY"] = "1"
	rewritten["MULTICA_HOST_REPO_CHECKOUT"] = "disabled"
	if _, ok := rewritten["SSH_AUTH_SOCK"]; ok {
		rewritten["SSH_AUTH_SOCK"] = AgentSocketPath
	}
	if _, ok := rewritten["CLAUDE_CODE_TMPDIR"]; ok {
		rewritten["CLAUDE_CODE_TMPDIR"] = TempPath
	}
	// Claude Code reads ~/.claude, which the task-home copy seeds at
	// /home/agent/.claude; an explicit CLAUDE_CONFIG_DIR host path must not
	// survive into the container. Antigravity has no such variable (it uses
	// HOME), so nothing is added for it.
	rewriteIfSet(rewritten, "CLAUDE_CONFIG_DIR", filepath.Join(HomePath, ".claude"))
	rewriteIfSet(rewritten, "MULTICA_CONFIG_ROOT", filepath.Join(HomePath, ".multica"))
	rewriteIfSet(rewritten, "MULTICA_TASK_CONFIG_ROOT", filepath.Join(HomePath, ".multica"))
	rewriteIfSet(rewritten, "CODEX_HOME", filepath.Join(HomePath, ".codex"))
	rewriteIfSet(rewritten, "CURSOR_DATA_DIR", filepath.Join(HomePath, ".cursor"))
	rewriteIfSet(rewritten, "HERMES_HOME", filepath.Join(HomePath, ".hermes"))
	rewriteIfSet(rewritten, "XDG_CONFIG_HOME", filepath.Join(HomePath, ".config"))
	rewriteIfSet(rewritten, "XDG_DATA_HOME", filepath.Join(HomePath, ".local", "share"))
	rewriteIfSet(rewritten, "XDG_CACHE_HOME", filepath.Join(HomePath, ".cache"))
	return rewritten
}

func rewriteIfSet(env map[string]string, key, target string) {
	if _, ok := env[key]; ok {
		env[key] = target
	}
}

func containerPath() string {
	return "/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin:/home/agent/go/bin:/home/agent/.local/bin"
}

// DockerBind returns a docker volume bind hostPath:containerPath:mode.
func DockerBind(hostPath, containerPath, mode string) string {
	if mode == "" {
		mode = "rw"
	}
	return hostPath + ":" + containerPath + ":" + mode
}

// DockerConfigBinds maps per-task host directories into the container home
// layout. Only non-empty host paths are bound.
//
// OpenClaw and QwenPaw are deliberately absent here: their per-task paths are
// bound at their own absolute paths in dockerBackend (not remapped into the
// container home), because their CLIs reference those paths by absolute value
// (OpenClaw's `$include`, QwenPaw's `--workspace`). Passing filepath.Dir of an
// empty path here used to bind "." — the daemon's working directory, which is
// the user's home on a systemd user unit.
func DockerConfigBinds(hostHome, hostMultica, hostCodex, hostCursor, hostHermes string) []string {
	type pair struct {
		host   string
		target string
	}
	pairs := []pair{
		{hostHome, HomePath},
		{hostMultica, filepath.Join(HomePath, ".multica")},
		{hostCodex, filepath.Join(HomePath, ".codex")},
		{hostCursor, filepath.Join(HomePath, ".cursor")},
		{hostHermes, filepath.Join(HomePath, ".hermes")},
	}
	var binds []string
	seen := map[string]struct{}{}
	for _, item := range pairs {
		host := strings.TrimSpace(item.host)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		binds = append(binds, DockerBind(host, item.target, "rw"))
	}
	return binds
}

// DockerRepoCacheBinds returns one read-only bind per unique absolute cache
// path across the prepared entries and the extra cache paths. The worker sees
// each cache at the same host path, so Git alternates the host writes stay
// valid inside the container. Relative or `..`-containing paths are refused:
// a cache path the daemon hands over must already be a clean, absolute host
// path.
func DockerRepoCacheBinds(repos []workercheckout.Entry, extraCachePaths []string) ([]string, error) {
	var binds []string
	seen := make(map[string]struct{})
	add := func(raw string) error {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return nil
		}
		if !filepath.IsAbs(raw) {
			return fmt.Errorf("sandbox: repo cache path %q is not absolute", raw)
		}
		if containsDotDot(raw) {
			return fmt.Errorf("sandbox: repo cache path %q contains ..", raw)
		}
		clean := filepath.Clean(raw)
		if _, ok := seen[clean]; ok {
			return nil
		}
		seen[clean] = struct{}{}
		binds = append(binds, DockerBind(clean, clean, "ro"))
		return nil
	}
	for _, entry := range repos {
		if err := add(entry.CachePath); err != nil {
			return nil, err
		}
	}
	for _, path := range extraCachePaths {
		if err := add(path); err != nil {
			return nil, err
		}
	}
	return binds, nil
}

// containsDotDot reports whether any path component is the parent marker.
func containsDotDot(path string) bool {
	for _, component := range strings.Split(path, string(filepath.Separator)) {
		if component == ".." {
			return true
		}
	}
	return false
}
