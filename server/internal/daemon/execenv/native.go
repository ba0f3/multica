package execenv

import (
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
)

// NativeProfile is selected by the daemon from the runtime owner's environment.
// It names shared state; it never seeds a task-local credential or session copy.
type NativeProfile struct {
	Home string
	Env  map[string]string
}

func prepareNativeTask(env *Environment, selected *NativeProfile, provider string, task TaskContextForEnv, mcp json.RawMessage, manifest *sidecarManifest) error {
	if !filepath.IsAbs(selected.Home) || filepath.Clean(selected.Home) != selected.Home || selected.Home == string(filepath.Separator) {
		return fmt.Errorf("execenv: native profile requires an absolute home narrower than root")
	}
	switch provider {
	case "codex", "cursor", "opencode", "mcode":
	default:
		return fmt.Errorf("execenv: native profile is unsupported for provider %q", provider)
	}
	profile := &NativeProfile{Home: selected.Home, Env: maps.Clone(selected.Env)}
	if profile.Env == nil {
		profile.Env = map[string]string{}
	}
	profile.Env["HOME"] = profile.Home
	env.NativeProfile = profile
	env.CodexDisabledSkillPaths = nil
	switch provider {
	case "codex":
		env.CodexHome = profile.Env["CODEX_HOME"]
		if env.CodexHome == "" {
			env.CodexHome = filepath.Join(profile.Home, ".codex")
		}
		profile.Env["CODEX_HOME"] = env.CodexHome
		for _, skill := range task.DisabledRuntimeSkills {
			key, valid := cleanRuntimeSkillKey(skill.Key)
			if !valid {
				continue
			}
			var path string
			switch skill.Root {
			case "provider":
				path = filepath.Join(env.CodexHome, "skills", filepath.FromSlash(key), "SKILL.md")
			case "universal":
				path = filepath.Join(profile.Home, ".agents", "skills", filepath.FromSlash(key), "SKILL.md")
			default:
				continue
			}
			env.CodexDisabledSkillPaths = append(env.CodexDisabledSkillPaths, path)
		}
		if len(task.AgentSkills) > 0 {
			dir := filepath.Join(env.WorkDir, ".agents", "skills")
			if err := recordMkdirAll(dir, 0755, manifest); err != nil {
				return err
			}
			if err := writeSkillFiles(dir, task.AgentSkills, manifest); err != nil {
				return err
			}
		}
	case "cursor":
		env.CursorDataDir = profile.Env["CURSOR_DATA_DIR"]
		if env.CursorDataDir == "" {
			env.CursorDataDir = filepath.Join(profile.Home, ".cursor")
		}
		if hasManagedCursorMcpConfig(mcp) {
			servers, err := parseCursorManagedMcpServers(mcp)
			if err != nil {
				return err
			}
			data, err := marshalCursorMcpConfig(servers)
			if err != nil {
				return err
			}
			dir := filepath.Join(cursorProjectRoot(env.WorkDir), ".cursor")
			if err := recordMkdirAll(dir, 0755, manifest); err != nil {
				return err
			}
			if err := recordWriteFile(filepath.Join(dir, "mcp.json"), data, 0600, manifest); err != nil {
				return fmt.Errorf("execenv: native managed Cursor MCP: %w", err)
			}
		}
	case "mcode":
		env.McodeDataDir = profile.Env["MINIMAX_DATA_DIR"]
		if env.McodeDataDir == "" {
			env.McodeDataDir = profile.Env["MAVIS_DATA_DIR"]
		}
		if env.McodeDataDir == "" {
			env.McodeDataDir = filepath.Join(profile.Home, ".minimax")
		}
	}
	return nil
}
