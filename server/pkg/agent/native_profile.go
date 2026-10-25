package agent

import (
	"encoding/json"
	"sort"
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
