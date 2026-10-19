//go:build linux

package r2dgit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// ProtectedEntrypointConfig belongs to the immutable, operator-approved image.
// It is not a task/API payload. A different config cannot grant broker rights.
type ProtectedEntrypointConfig struct {
	SocketPath         string `json:"socket_path"`
	GitExecutable      string `json:"git_executable"`
	ProviderExecutable string `json:"provider_executable"`
	WorkspaceRoot      string `json:"workspace_root"`
	HomeRoot           string `json:"home_root"`
	TmpRoot            string `json:"tmp_root"`
	TimeoutSeconds     int    `json:"timeout_seconds"`
}

// ProtectedProviderInput/Result are the sole image-provider v1 contract. There
// is no native CLI, model credential, provider selection or egress fallback.
type ProtectedProviderInput struct {
	Version    int                `json:"version"`
	Assignment WorkloadAssignment `json:"assignment"`
	Directory  string             `json:"directory"`
	Head       string             `json:"head"`
}
type ProtectedProviderResult struct {
	Version int                   `json:"version"`
	Kind    string                `json:"kind"`
	Content string                `json:"content"`
	Changes []ProtectedFileChange `json:"changes,omitempty"`
}

func ReadProtectedEntrypointConfig(path string) (ProtectedEntrypointConfig, error) {
	var config ProtectedEntrypointConfig
	info, err := os.Lstat(path)
	if err != nil || !filepath.IsAbs(path) || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 16384 {
		return config, ErrRuntime
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 16384 {
		return config, ErrRuntime
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&config) != nil {
		return config, ErrRuntime
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return config, ErrRuntime
	}
	return config, nil
}

func privateEmptyDirectory(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return false
	}
	files, err := os.ReadDir(path)
	return err == nil && len(files) == 0
}
func separateDirectories(paths ...string) bool {
	for i, a := range paths {
		for j, b := range paths {
			if i == j {
				continue
			}
			relative, err := filepath.Rel(a, b)
			if err != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				return false
			}
		}
	}
	return true
}

// RunProtectedEntrypoint completes the locally supported read-only workflow.
// It must run INSIDE accepted containment. Process groups are cleanup hygiene,
// not proof against escaped descendants; the supervisor removes the whole run.
func RunProtectedEntrypoint(ctx context.Context, c ProtectedEntrypointConfig) error {
	if c.TimeoutSeconds < 1 || c.TimeoutSeconds > 45 || !separateDirectories(c.WorkspaceRoot, c.HomeRoot, c.TmpRoot) {
		return ErrRuntime
	}
	for _, root := range []string{c.WorkspaceRoot, c.HomeRoot, c.TmpRoot} {
		if !privateEmptyDirectory(root) {
			return ErrRuntime
		}
	}
	for _, executable := range []string{c.GitExecutable, c.ProviderExecutable} {
		info, err := os.Lstat(executable)
		if err != nil || !filepath.IsAbs(executable) || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return ErrRuntime
		}
	}
	ctx, stop := context.WithTimeout(ctx, time.Duration(c.TimeoutSeconds)*time.Second)
	defer stop()
	client, err := NewWorkloadClient(c.SocketPath)
	if err != nil {
		return err
	}
	defer client.Close()
	assignment, err := client.Assignment(ctx)
	if err != nil {
		return err
	}
	directory, head, err := client.Prepare(ctx, c.GitExecutable, c.WorkspaceRoot)
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	input, err := json.Marshal(ProtectedProviderInput{Version: 1, Assignment: assignment, Directory: directory, Head: head})
	if err != nil {
		return ErrScope
	}
	defer clear(input)
	providerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(providerCtx, c.ProviderExecutable, "--multica-protected-v1")
	cmd.Dir = directory
	cmd.Env = []string{"HOME=" + c.HomeRoot, "XDG_CONFIG_HOME=" + c.HomeRoot, "TMPDIR=" + c.TmpRoot, "PATH=/usr/bin:/bin", "LC_ALL=C", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_COUNT=0", "GIT_TERMINAL_PROMPT=0", "GIT_NO_REPLACE_OBJECTS=1"}
	cmd.Stdin = bytes.NewReader(input)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	kill := func() error {
		if cmd.Process == nil {
			return nil
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.Cancel = kill
	cmd.WaitDelay = 500 * time.Millisecond
	out := &entrypointOutput{limit: (1 << 20) + 1024, cancel: cancel}
	diagnostic := &entrypointOutput{limit: 64 << 10, cancel: cancel, discard: true}
	cmd.Stdout = out
	cmd.Stderr = diagnostic
	err = cmd.Run()
	// Also reap same-group descendants after a leader that exited on its own.
	_ = kill()
	defer clear(out.buffer.Bytes())
	if err != nil || ctx.Err() != nil || out.overflow || diagnostic.overflow || !utf8.Valid(out.buffer.Bytes()) {
		return ErrRuntime
	}
	var result ProtectedProviderResult
	d := json.NewDecoder(&out.buffer)
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil {
		return ErrScope
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return ErrScope
	}
	if result.Version != 1 || len(result.Content) == 0 || len(result.Content) > 1<<20 || (result.Kind != "artifact" && result.Kind != "diff" && result.Kind != "transcript" && result.Kind != "tool") {
		return ErrScope
	}
	if len(result.Changes) > 0 {
		old, writeErr := client.WriteReference(ctx)
		if writeErr != nil {
			return writeErr
		}
		newHead, pack, writeErr := applyProtectedChanges(ctx, c.GitExecutable, directory, head, result.Changes)
		defer clear(pack)
		if writeErr != nil {
			return writeErr
		}
		if writeErr = client.Finalize(ctx, FinalizeRequest{Old: old, New: newHead, Pack: pack}); writeErr != nil {
			return writeErr
		}
	}
	_, err = client.Submit(ctx, result.Kind, result.Content)
	return err
}

type entrypointOutput struct {
	buffer            bytes.Buffer
	limit, count      int
	cancel            context.CancelFunc
	discard, overflow bool
}

func (w *entrypointOutput) Write(p []byte) (int, error) {
	if len(p) > w.limit-w.count {
		w.overflow = true
		w.cancel()
		return 0, ErrScope
	}
	w.count += len(p)
	if w.discard {
		return len(p), nil
	}
	return w.buffer.Write(p)
}
