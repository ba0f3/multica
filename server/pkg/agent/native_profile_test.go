package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeCodexDoesNotWriteSharedConfig(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config.toml")
	original := []byte("# native profile sentinel\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	exe := filepath.Join(t.TempDir(), "codex")
	_ = os.WriteFile(exe, []byte("#!/bin/sh\nexit 1\n"), 0700)
	backend, _ := New("codex", Config{ExecutablePath: exe, Env: map[string]string{"CODEX_HOME": home}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	session, _ := backend.Execute(ctx, "hello", ExecOptions{NativeProfile: true, McpConfig: json.RawMessage(`{"mcpServers":{"fixture":{"command":"fixture-mcp","env":{"TOKEN":"task-secret"}}}}`)})
	if session != nil {
		for range session.Messages {
		}
		<-session.Result
	}
	data, _ := os.ReadFile(path)
	after, _ := os.Stat(path)
	if string(data) != string(original) || !os.SameFile(info, after) || !info.ModTime().Equal(after.ModTime()) {
		t.Fatal("native adapter changed the shared configuration")
	}
}

func TestNativeCodexSettingsUsePrivateRPCForFreshAndResume(t *testing.T) {
	for _, method := range []string{"thread/start", "thread/resume"} {
		t.Run(method, func(t *testing.T) {
			params := map[string]any{"config": map[string]any{"model_reasoning_effort": "high"}}
			opts := ExecOptions{NativeProfile: true, McpConfig: json.RawMessage(`{"mcpServers":{"fixture":{"command":"fixture-mcp","env":{"TOKEN":"task-secret"}}}}`)}
			if err := applyNativeCodexThreadConfig(params, opts, map[string]string{"MULTICA_TOKEN": "scoped", "PATH": "/bin"}); err != nil {
				t.Fatal(err)
			}
			config := params["config"].(map[string]any)
			if config["model_reasoning_effort"] != "high" {
				t.Fatal("existing thread setting overwritten")
			}
			encoded, _ := json.Marshal(config)
			if !strings.Contains(string(encoded), "task-secret") || !strings.Contains(string(encoded), "MULTICA_TOKEN") || !strings.Contains(string(encoded), "include_only") {
				t.Fatalf("task RPC settings lost: %s", encoded)
			}
		})
	}
}

func TestNativeCodexSkillPolicyIsPrivatePerTurn(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config.toml")
	original := []byte("[[skills.config]]\npath = '/native/global/SKILL.md'\nenabled = false\n[[skills.config]]\npath = '/native/task-a/SKILL.md'\nenabled = true\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	for _, method := range []string{"thread/start", "thread/resume"} {
		for _, name := range []string{"task-a", "task-b"} {
			t.Run(method+"/"+name, func(t *testing.T) {
				params := map[string]any{}
				disabled := "/native/" + name + "/SKILL.md"
				opts := ExecOptions{NativeProfile: true, CodexDisabledSkillPaths: []string{disabled}}
				if err := applyNativeCodexThreadConfig(params, opts, map[string]string{"CODEX_HOME": home}); err != nil {
					t.Fatal(err)
				}
				data, _ := json.Marshal(params)
				if !strings.Contains(string(data), disabled) || !strings.Contains(string(data), "/native/global/SKILL.md") || !strings.Contains(string(data), `"enabled":false`) {
					t.Fatalf("native skill exclusions missing from private RPC: %s", data)
				}
				var decoded struct {
					Config struct {
						Skills struct {
							Config []struct {
								Path    string `json:"path"`
								Enabled bool   `json:"enabled"`
							} `json:"config"`
						} `json:"skills"`
					} `json:"config"`
				}
				_ = json.Unmarshal(data, &decoded)
				for _, entry := range decoded.Config.Skills.Config {
					if entry.Path == disabled && entry.Enabled {
						t.Fatal("native enabled entry overrides the task exclusion")
					}
				}
				other := "/native/task-a/SKILL.md"
				if name == "task-a" {
					other = "/native/task-b/SKILL.md"
				}
				if name == "task-a" && strings.Contains(string(data), other) {
					t.Fatal("task inherited another task's skill policy")
				}
			})
		}
	}
	data, _ := os.ReadFile(path)
	after, _ := os.Stat(path)
	if string(data) != string(original) || !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("private task skill policy changed the shared profile")
	}
}
