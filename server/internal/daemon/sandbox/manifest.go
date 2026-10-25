package sandbox

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/multica-ai/multica/server/pkg/agent"
)

// maxFrameBytes bounds one IPC frame. A transcript message carries tool input
// and output, so the ceiling is generous but finite: a worker that emits a
// runaway line must fail the run instead of exhausting the supervisor.
const maxFrameBytes = 8 << 20

// Manifest is everything the worker needs to run one attempt.
//
// It travels over stdin, not over argv and not over the environment: process
// arguments and environments are readable by every process of the same user,
// and the manifest carries the agent's environment — which includes the
// task-scoped API token.
type Manifest struct {
	TaskID    string   `json:"task_id"`
	AttemptID string   `json:"attempt_id"`
	Provider  string   `json:"provider"`
	Prompt    string   `json:"prompt"`
	Config    Config   `json:"config"`
	Exec      ExecSpec `json:"exec"`
}

// Config is the serializable part of agent.Config.
//
// agent.Config carries a *slog.Logger, which is a live object, so the worker
// rebuilds its own logger instead of receiving one.
type Config struct {
	ExecutablePath string            `json:"executable_path"`
	LaunchPrefix   []string          `json:"launch_prefix,omitempty"`
	CLIVersion     string            `json:"cli_version,omitempty"`
	Env            map[string]string `json:"env,omitempty"`
	TaskID         string            `json:"task_id"`
	AttemptID      string            `json:"attempt_id,omitempty"`
	RuntimeID      string            `json:"runtime_id"`
	DaemonVersion  string            `json:"daemon_version,omitempty"`
	CodexVersion   string            `json:"codex_version,omitempty"`
	BuiltinRuntime bool              `json:"builtin_runtime"`
}

// ExecSpec is the serializable part of agent.ExecOptions.
type ExecSpec struct {
	CodexDisabledSkillPaths    []string        `json:"codex_disabled_skill_paths,omitempty"`
	NativeProfile              bool            `json:"native_profile,omitempty"`
	EnableTaskSupplement       bool            `json:"enable_task_supplement,omitempty"`
	Cwd                        string          `json:"cwd"`
	Model                      string          `json:"model,omitempty"`
	SystemPrompt               string          `json:"system_prompt,omitempty"`
	ThreadName                 string          `json:"thread_name,omitempty"`
	MaxTurns                   int             `json:"max_turns,omitempty"`
	TimeoutSeconds             int64           `json:"timeout_seconds,omitempty"`
	SemanticInactivitySeconds  int64           `json:"semantic_inactivity_seconds,omitempty"`
	FirstTurnNoProgressSeconds int64           `json:"first_turn_no_progress_seconds,omitempty"`
	IdleWatchdogSeconds        int64           `json:"idle_watchdog_seconds,omitempty"`
	HandshakeSeconds           int64           `json:"handshake_seconds,omitempty"`
	TurnInterruptSeconds       int64           `json:"turn_interrupt_seconds,omitempty"`
	ThreadHandshakeSeconds     int64           `json:"thread_handshake_seconds,omitempty"`
	ResumeSessionID            string          `json:"resume_session_id,omitempty"`
	ResumeExpected             bool            `json:"resume_expected,omitempty"`
	ResumeContinuityNotice     string          `json:"resume_continuity_notice,omitempty"`
	ExtraArgs                  []string        `json:"extra_args,omitempty"`
	CustomArgs                 []string        `json:"custom_args,omitempty"`
	QwenpawWorkspace           string          `json:"qwenpaw_workspace,omitempty"`
	McpConfig                  json.RawMessage `json:"mcp_config,omitempty"`
	ThinkingLevel              string          `json:"thinking_level,omitempty"`
	ServiceTier                string          `json:"service_tier,omitempty"`
	OpenclawMode               string          `json:"openclaw_mode,omitempty"`
	ClaudeSettingsPath         string          `json:"claude_settings_path,omitempty"`
	CursorHookCommand          []string        `json:"cursor_hook_command,omitempty"`
	IsolatedToolBoundary       bool            `json:"isolated_tool_boundary,omitempty"`
}

// WriteManifest writes the manifest as one JSON line.
func WriteManifest(w io.Writer, manifest Manifest) error {
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("sandbox: encode the manifest: %w", err)
	}
	if len(encoded) > maxFrameBytes {
		return errors.New("sandbox: the manifest is too large")
	}
	if _, err := w.Write(append(encoded, '\n')); err != nil {
		return fmt.Errorf("sandbox: write the manifest: %w", err)
	}
	return nil
}

// ReadManifest reads one JSON line.
func ReadManifest(r io.Reader) (Manifest, error) {
	reader := bufio.NewReaderSize(r, 64<<10)
	line, err := readLimitedLine(reader)
	if err != nil {
		return Manifest{}, fmt.Errorf("sandbox: read the manifest: %w", err)
	}
	var manifest Manifest
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("sandbox: decode the manifest: %w", err)
	}
	if strings.TrimSpace(manifest.Provider) == "" || strings.TrimSpace(manifest.Prompt) == "" {
		return Manifest{}, errors.New("sandbox: the manifest is incomplete")
	}
	return manifest, nil
}

// ConvertExecOptions maps the daemon's execution options into the serializable
// spec. Durations become seconds because JSON has no duration type.
func ConvertExecOptions(opts agent.ExecOptions) ExecSpec {
	return ExecSpec{
		CodexDisabledSkillPaths:    opts.CodexDisabledSkillPaths,
		NativeProfile:              opts.NativeProfile,
		EnableTaskSupplement:       opts.EnableTaskSupplement,
		Cwd:                        opts.Cwd,
		Model:                      opts.Model,
		SystemPrompt:               opts.SystemPrompt,
		ThreadName:                 opts.ThreadName,
		MaxTurns:                   opts.MaxTurns,
		TimeoutSeconds:             int64(opts.Timeout.Seconds()),
		SemanticInactivitySeconds:  int64(opts.SemanticInactivityTimeout.Seconds()),
		FirstTurnNoProgressSeconds: int64(opts.FirstTurnNoProgressTimeout.Seconds()),
		IdleWatchdogSeconds:        int64(opts.IdleWatchdogTimeout.Seconds()),
		HandshakeSeconds:           int64(opts.HandshakeTimeout.Seconds()),
		TurnInterruptSeconds:       int64(opts.TurnInterruptTimeout.Seconds()),
		ThreadHandshakeSeconds:     int64(opts.ThreadHandshakeTimeout.Seconds()),
		ResumeSessionID:            opts.ResumeSessionID,
		ResumeExpected:             opts.ResumeExpected,
		ResumeContinuityNotice:     opts.ResumeContinuityNotice,
		ExtraArgs:                  append([]string(nil), opts.ExtraArgs...),
		CustomArgs:                 append([]string(nil), opts.CustomArgs...),
		QwenpawWorkspace:           opts.QwenpawWorkspace,
		McpConfig:                  append(json.RawMessage(nil), opts.McpConfig...),
		ThinkingLevel:              opts.ThinkingLevel,
		ServiceTier:                opts.ServiceTier,
		OpenclawMode:               opts.OpenclawMode,
		ClaudeSettingsPath:         opts.ClaudeSettingsPath,
		CursorHookCommand:          append([]string(nil), opts.CursorHookCommand...),
		IsolatedToolBoundary:       opts.IsolatedToolBoundary,
	}
}

// ExecOptions reverses ConvertExecOptions.
func (s ExecSpec) ExecOptions() agent.ExecOptions {
	return agent.ExecOptions{
		CodexDisabledSkillPaths:    s.CodexDisabledSkillPaths,
		NativeProfile:              s.NativeProfile,
		EnableTaskSupplement:       s.EnableTaskSupplement,
		Cwd:                        s.Cwd,
		Model:                      s.Model,
		SystemPrompt:               s.SystemPrompt,
		ThreadName:                 s.ThreadName,
		MaxTurns:                   s.MaxTurns,
		Timeout:                    seconds(s.TimeoutSeconds),
		SemanticInactivityTimeout:  seconds(s.SemanticInactivitySeconds),
		FirstTurnNoProgressTimeout: seconds(s.FirstTurnNoProgressSeconds),
		IdleWatchdogTimeout:        seconds(s.IdleWatchdogSeconds),
		HandshakeTimeout:           seconds(s.HandshakeSeconds),
		TurnInterruptTimeout:       seconds(s.TurnInterruptSeconds),
		ThreadHandshakeTimeout:     seconds(s.ThreadHandshakeSeconds),
		ResumeSessionID:            s.ResumeSessionID,
		ResumeExpected:             s.ResumeExpected,
		ResumeContinuityNotice:     s.ResumeContinuityNotice,
		ExtraArgs:                  append([]string(nil), s.ExtraArgs...),
		CustomArgs:                 append([]string(nil), s.CustomArgs...),
		QwenpawWorkspace:           s.QwenpawWorkspace,
		McpConfig:                  append(json.RawMessage(nil), s.McpConfig...),
		ThinkingLevel:              s.ThinkingLevel,
		ServiceTier:                s.ServiceTier,
		OpenclawMode:               s.OpenclawMode,
		ClaudeSettingsPath:         s.ClaudeSettingsPath,
		CursorHookCommand:          append([]string(nil), s.CursorHookCommand...),
		IsolatedToolBoundary:       s.IsolatedToolBoundary,
	}
}

// readLimitedLine reads one newline-terminated line without buffering more
// than the frame ceiling.
func readLimitedLine(r *bufio.Reader) (string, error) {
	var builder strings.Builder
	for {
		chunk, err := r.ReadSlice('\n')
		builder.Write(chunk)
		if builder.Len() > maxFrameBytes {
			return "", errors.New("frame too large")
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return "", err
		}
		return builder.String(), nil
	}
}
