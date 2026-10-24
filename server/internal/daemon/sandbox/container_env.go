package sandbox

import (
	"path/filepath"
	"strings"
)

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
	if _, ok := rewritten["SSH_AUTH_SOCK"]; ok {
		rewritten["SSH_AUTH_SOCK"] = AgentSocketPath
	}
	if _, ok := rewritten["CLAUDE_CODE_TMPDIR"]; ok {
		rewritten["CLAUDE_CODE_TMPDIR"] = TempPath
	}
	rewriteIfSet(rewritten, "MULTICA_CONFIG_ROOT", filepath.Join(HomePath, ".multica"))
	rewriteIfSet(rewritten, "CODEX_HOME", filepath.Join(HomePath, ".codex"))
	rewriteIfSet(rewritten, "CURSOR_DATA_DIR", filepath.Join(HomePath, ".cursor"))
	rewriteIfSet(rewritten, "HERMES_HOME", filepath.Join(HomePath, ".hermes"))
	rewriteIfSet(rewritten, "OPENCLAW_CONFIG_PATH", filepath.Join(HomePath, ".openclaw", "config.json"))
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
	return "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"
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
// OpenClaw is deliberately absent: the isolated tool boundary only admits
// codex, cursor, and opencode, so there is never a per-task OpenClaw config to
// mount. Passing filepath.Dir of an empty path here used to bind "." — the
// daemon's working directory, which is the user's home on a systemd user unit.
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
