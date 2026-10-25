package execenv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativePrepareAndReusePreserveOriginalProfile(t *testing.T) {
	for _, provider := range []string{"codex", "cursor", "opencode", "mcode"} {
		t.Run(provider, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			profiles := []string{".codex/auth.json", ".codex/config.toml", ".codex/sessions/session", ".cursor/credentials.json", ".config/cursor/auth.json", ".local/share/opencode/auth.json", ".local/share/opencode/opencode.db", ".minimax/state/credentials.json", ".minimax/state/auth.lock", ".minimax/run/host.lock"}
			before := map[string]os.FileInfo{}
			for _, rel := range profiles {
				p := filepath.Join(home, rel)
				if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte("sentinel "+rel), 0600); err != nil {
					t.Fatal(err)
				}
				before[rel], _ = os.Stat(p)
			}
			exporter := filepath.Join(t.TempDir(), "fake-opencode")
			record := filepath.Join(t.TempDir(), "export-called")
			t.Setenv("NATIVE_EXPORT_RECORD", record)
			if err := os.WriteFile(exporter, []byte("#!/bin/sh\nprintf called > \"$NATIVE_EXPORT_RECORD\"\nexit 9\n"), 0700); err != nil {
				t.Fatal(err)
			}
			selected := &NativeProfile{Home: home, Env: map[string]string{"CODEX_HOME": filepath.Join(home, ".codex"), "MINIMAX_DATA_DIR": filepath.Join(home, ".minimax")}}
			params := PrepareParams{WorkspacesRoot: t.TempDir(), WorkspaceID: "ws", TaskID: "native-task", Provider: provider, IsolatedToolBoundary: true, OpenCodeBin: exporter, NativeProfile: selected, McpConfig: json.RawMessage(`{"mcpServers":{"fixture":{"command":"fixture-mcp"}}}`), Task: TaskContextForEnv{IssueID: "issue", AgentID: "agent", AgentSkills: []SkillContextForEnv{{Name: "Fixture", Content: "native skill sentinel"}}}}
			env, err := Prepare(params, discardLogger())
			if err != nil {
				t.Fatal(err)
			}
			defer env.ReleaseLock()
			check := func(env *Environment) {
				t.Helper()
				if env == nil {
					t.Fatal("native reuse declined")
				}
				if env.NativeProfile == nil || env.NativeProfile.Home != home {
					t.Fatalf("selected profile lost: %+v", env.NativeProfile)
				}
				if env.MulticaConfigRoot == "" {
					t.Fatal("task API config missing")
				}
				for _, rel := range []string{"home", "codex-home", "cursor-data", "opencode-credentials.json"} {
					if _, err := os.Stat(filepath.Join(env.RootDir, rel)); !os.IsNotExist(err) {
						t.Errorf("private provider copy unexpectedly exists: %s, %v", rel, err)
					}
				}
				if _, err := os.Stat(record); !os.IsNotExist(err) {
					t.Fatal("native preparation exported credentials")
				}
				for _, rel := range profiles {
					p := filepath.Join(home, rel)
					data, err := os.ReadFile(p)
					info, statErr := os.Stat(p)
					if err != nil || statErr != nil || string(data) != "sentinel "+rel || !os.SameFile(before[rel], info) || !before[rel].ModTime().Equal(info.ModTime()) {
						t.Errorf("shared profile changed: %s", rel)
					}
				}
				skillDir := skillsDirPath(env.WorkDir, provider)
				if provider == "codex" {
					skillDir = filepath.Join(env.WorkDir, ".agents", "skills")
				}
				found := false
				_ = filepath.WalkDir(skillDir, func(path string, d os.DirEntry, err error) error {
					if err == nil && !d.IsDir() {
						data, _ := os.ReadFile(path)
						found = found || strings.Contains(string(data), "native skill sentinel")
					}
					return nil
				})
				if !found {
					t.Fatalf("native task skill missing in %s", skillDir)
				}
				if provider == "cursor" {
					data, err := os.ReadFile(filepath.Join(env.WorkDir, ".cursor", "mcp.json"))
					if err != nil || !strings.Contains(string(data), "fixture-mcp") {
						t.Fatalf("managed MCP missing: %s, %v", data, err)
					}
				}
			}
			check(env)
			env.ReleaseLock()
			reused := Reuse(ReuseParams{WorkDir: env.WorkDir, Provider: provider, IsolatedToolBoundary: true, OpenCodeBin: exporter, NativeProfile: selected, McpConfig: params.McpConfig, Task: params.Task}, discardLogger())
			check(reused)
		})
	}
}

func TestNativeReuseProviderChangeDoesNotCarryPreviousSelection(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	profile := &NativeProfile{Home: home, Env: map[string]string{"CODEX_HOME": filepath.Join(home, ".codex")}}
	env, err := Prepare(PrepareParams{WorkspacesRoot: t.TempDir(), WorkspaceID: "ws", TaskID: "task", Provider: "codex", NativeProfile: profile}, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	env.ReleaseLock()
	selected := &NativeProfile{Home: home, Env: map[string]string{"MINIMAX_DATA_DIR": filepath.Join(home, "selected-minimax")}}
	reused := Reuse(ReuseParams{WorkDir: env.WorkDir, Provider: "mcode", NativeProfile: selected}, discardLogger())
	if reused == nil || reused.CodexHome != "" || reused.McodeDataDir != selected.Env["MINIMAX_DATA_DIR"] || reused.NativeProfile.Env["CODEX_HOME"] != "" {
		t.Fatalf("provider selection leaked: %+v", reused)
	}
}
