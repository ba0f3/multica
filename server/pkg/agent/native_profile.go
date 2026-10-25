package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/pelletier/go-toml/v2"
)

// Native task settings travel in the thread RPC, never in argv or the shared
// config.toml. The worker's environment has already crossed the task boundary.
func applyNativeCodexThreadConfig(params map[string]any, opts ExecOptions, env map[string]string) error {
	if !opts.NativeProfile {
		return nil
	}
	config, _ := params["config"].(map[string]any)
	if config == nil {
		config = map[string]any{}
	}
	keys := []string{"HOME", "TMPDIR", "PATH"}
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	config["shell_environment_policy"] = map[string]any{"inherit": "all", "ignore_default_excludes": true, "include_only": keys}
	if len(opts.CodexDisabledSkillPaths) > 0 {
		var profile struct {
			Skills struct {
				Config []map[string]any `toml:"config"`
			} `toml:"skills"`
		}
		path := filepath.Join(env["CODEX_HOME"], "config.toml")
		data, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("read native Codex skill configuration: %w", err)
		}
		if err == nil && toml.Unmarshal(data, &profile) != nil {
			return fmt.Errorf("native Codex skill policy: invalid shared config.toml")
		}
		for _, path := range opts.CodexDisabledSkillPaths {
			paths := []string{path}
			if canonical, err := filepath.EvalSymlinks(path); err == nil && canonical != path {
				paths = append(paths, canonical)
			}
			for _, disabled := range paths {
				found := false
				for _, entry := range profile.Skills.Config {
					if entry["path"] == filepath.ToSlash(disabled) {
						entry["enabled"] = false
						found = true
					}
				}
				if !found {
					profile.Skills.Config = append(profile.Skills.Config, map[string]any{"path": filepath.ToSlash(disabled), "enabled": false})
				}
			}
		}
		config["skills"] = map[string]any{"config": profile.Skills.Config}
	}
	if hasManagedCodexMcpConfig(opts.McpConfig) {
		if _, _, err := renderCodexMcpServersBlock(opts.McpConfig); err != nil {
			return err
		}
		var parsed struct {
			Servers map[string]map[string]any `json:"mcpServers"`
		}
		if err := json.Unmarshal(opts.McpConfig, &parsed); err != nil {
			return err
		}
		servers := map[string]any{}
		for name, value := range parsed.Servers {
			servers[name] = normalizeCodexMcpServerConfig(value)
		}
		config["mcp_servers"] = servers
	}
	params["config"] = config
	return nil
}
