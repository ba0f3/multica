package sandbox

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/pkg/agent"
)

func testManifest() Manifest {
	return Manifest{
		TaskID:    "task-1",
		AttemptID: "attempt-1",
		Provider:  "claude",
		Prompt:    "fix the failing test",
		Config: Config{
			ExecutablePath: "/usr/local/bin/claude",
			LaunchPrefix:   []string{"ccms", "start"},
			CLIVersion:     "1.2.3",
			Env:            map[string]string{"PATH": "/usr/local/bin:/usr/bin"},
			TaskID:         "task-1",
			RuntimeID:      "runtime-1",
			BuiltinRuntime: true,
		},
		Exec: ExecSpec{
			Cwd:            "/workspace/repo",
			Model:          "sonnet",
			TimeoutSeconds: 600,
			ExtraArgs:      []string{"--flag"},
			ResumeExpected: true,
		},
	}
}

func TestManifestRoundTrips(t *testing.T) {
	original := testManifest()
	var buffer bytes.Buffer
	if err := WriteManifest(&buffer, original); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	decoded, err := ReadManifest(&buffer)
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if decoded.Provider != original.Provider || decoded.Prompt != original.Prompt {
		t.Fatalf("manifest did not round-trip: %+v", decoded)
	}
	if decoded.Config.ExecutablePath != original.Config.ExecutablePath {
		t.Fatalf("config did not round-trip: %+v", decoded.Config)
	}
	if decoded.Exec.TimeoutSeconds != 600 {
		t.Fatalf("exec did not round-trip: %+v", decoded.Exec)
	}
	if got := decoded.Exec.ExecOptions().Timeout; got != 10*time.Minute {
		t.Fatalf("timeout = %s, want %s", got, 10*time.Minute)
	}
}

func TestManifestCarriesTheAgentEnvironmentOnlyOverStdin(t *testing.T) {
	// The manifest is the transport for the agent environment because argv
	// and env are readable by every process of the same user. This test pins
	// that the environment is IN the manifest, not that it is absent from it.
	manifest := testManifest()
	manifest.Config.Env = map[string]string{"MULTICA_TOKEN": "task-token"}
	var buffer bytes.Buffer
	if err := WriteManifest(&buffer, manifest); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	decoded, err := ReadManifest(&buffer)
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if decoded.Config.Env["MULTICA_TOKEN"] != "task-token" {
		t.Fatal("the agent environment did not survive the manifest")
	}
}

func TestReadManifestRejectsAnIncompleteManifest(t *testing.T) {
	cases := map[string]string{
		"no provider": `{"prompt":"hi"}`,
		"no prompt":   `{"provider":"claude"}`,
		"unknown key": `{"provider":"claude","prompt":"hi","extra":true}`,
		"not json":    `not json`,
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadManifest(strings.NewReader(line + "\n")); err == nil {
				t.Fatal("an invalid manifest was accepted")
			}
		})
	}
}

func TestFrameRoundTripsAnAgentMessage(t *testing.T) {
	message := agent.Message{
		Type:      agent.MessageToolUse,
		Tool:      "Bash",
		CallID:    "call-1",
		Input:     map[string]any{"command": "ls"},
		SessionID: "session-1",
	}
	var buffer bytes.Buffer
	if err := WriteFrame(&buffer, Frame{Type: FrameMessage, Message: &message}); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	frame, err := ReadFrame(bufio.NewReader(&buffer))
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if frame.Message == nil || frame.Message.Tool != "Bash" || frame.Message.CallID != "call-1" {
		t.Fatalf("message did not round-trip: %+v", frame.Message)
	}
	if frame.Message.Input["command"] != "ls" {
		t.Fatalf("tool input did not round-trip: %+v", frame.Message.Input)
	}
}

func TestReadFrameRejectsMalformedFrames(t *testing.T) {
	cases := map[string]string{
		"truncated json":  `{"type":"message"`,
		"unknown type":    `{"type":"progress"}`,
		"message no data": `{"type":"message"}`,
		"result no data":  `{"type":"result"}`,
		"error no text":   `{"type":"error"}`,
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadFrame(bufio.NewReader(strings.NewReader(line + "\n"))); err == nil {
				t.Fatal("a malformed frame was accepted")
			}
		})
	}
}

func TestReadFrameBoundsOneFrame(t *testing.T) {
	huge := strings.Repeat("x", maxFrameBytes+1)
	if _, err := ReadFrame(bufio.NewReader(strings.NewReader(huge + "\n"))); err == nil {
		t.Fatal("an oversized frame was accepted")
	}
}

func TestExecSpecKeepsEveryOptionTheBackendsRead(t *testing.T) {
	options := agent.ExecOptions{
		EnableTaskSupplement: true,
		Cwd:                  "/workspace/repo",
		Model:                "sonnet",
		SystemPrompt:         "brief",
		ThreadName:           "thread",
		MaxTurns:             7,
		Timeout:              2 * time.Minute,
		ResumeSessionID:      "session-1",
		ResumeExpected:       true,
		ExtraArgs:            []string{"--a"},
		CustomArgs:           []string{"--b"},
		ThinkingLevel:        "high",
		ServiceTier:          "priority",
		OpenclawMode:         "gateway",
		ClaudeSettingsPath:   "/tmp/settings.json",
		CursorHookCommand:    []string{"multica", "__cursor_hook"},
		McpConfig:            json.RawMessage(`{"mcpServers":{}}`),
		IsolatedToolBoundary: true,
	}
	roundTripped := ConvertExecOptions(options).ExecOptions()
	if roundTripped.EnableTaskSupplement != options.EnableTaskSupplement ||
		roundTripped.Cwd != options.Cwd ||
		roundTripped.Model != options.Model ||
		roundTripped.SystemPrompt != options.SystemPrompt ||
		roundTripped.MaxTurns != options.MaxTurns ||
		roundTripped.Timeout != options.Timeout ||
		roundTripped.ResumeSessionID != options.ResumeSessionID ||
		roundTripped.ThinkingLevel != options.ThinkingLevel ||
		roundTripped.ServiceTier != options.ServiceTier ||
		roundTripped.OpenclawMode != options.OpenclawMode ||
		roundTripped.ClaudeSettingsPath != options.ClaudeSettingsPath ||
		len(roundTripped.ExtraArgs) != 1 ||
		len(roundTripped.CustomArgs) != 1 ||
		len(roundTripped.CursorHookCommand) != 2 ||
		string(roundTripped.McpConfig) != string(options.McpConfig) ||
		roundTripped.IsolatedToolBoundary != options.IsolatedToolBoundary {
		t.Fatalf("an execution option was lost:\n got %+v\nwant %+v", roundTripped, options)
	}
}
