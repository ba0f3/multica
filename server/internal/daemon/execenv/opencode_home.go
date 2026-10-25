package execenv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// prepareOpenCodeIsolatedHome seeds the per-task HOME with OpenCode config and
// credentials for isolated workers. Docker imports an auth-only export inside
// the container so existing session databases remain private and intact.
func prepareOpenCodeIsolatedHome(taskHome, executable string, logger *slog.Logger) error {
	if strings.TrimSpace(taskHome) == "" {
		return fmt.Errorf("task home is required")
	}
	configSrc, err := resolveOpenCodeConfigDir()
	if err != nil {
		return err
	}
	dataSrc, err := resolveOpenCodeDataDir()
	if err != nil {
		return err
	}

	if err := mirrorProviderTree(configSrc, filepath.Join(taskHome, ".config", "opencode"), openCodeHomeSkipDirs, logger); err != nil {
		return fmt.Errorf("copy opencode config: %w", err)
	}
	if executable != "" {
		return exportOpenCodeCredentials(executable, filepath.Join(filepath.Dir(taskHome), "opencode-credentials.json"))
	}
	dataDst := filepath.Join(taskHome, ".local", "share", "opencode")
	// Sessions and credentials share this database. Keep an existing task DB
	// together with its own WAL rather than mixing in host database files.
	if _, err := os.Lstat(filepath.Join(dataDst, "opencode.db")); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect task opencode database: %w", err)
	}
	if err := mirrorProviderTree(dataSrc, dataDst, openCodeHomeSkipDirs, logger); err != nil {
		return fmt.Errorf("copy opencode data: %w", err)
	}
	return nil
}

func resolveOpenCodeConfigDir() (string, error) {
	configHome, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(configHome, "opencode"), nil
}

func resolveOpenCodeDataDir() (string, error) {
	if dataHome := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); dataHome != "" {
		return filepath.Join(dataHome, "opencode"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	return filepath.Join(home, ".local", "share", "opencode"), nil
}

var openCodeHomeSkipDirs = dirSet("log", "shell", "snapshot", "worktree", "tool-output", "repos")

func copyRegularFile(src, dst string, entry fs.DirEntry) error {
	if entry != nil && !entry.Type().IsRegular() {
		// Sockets/FIFOs/devices cannot be copied and are runtime state, not
		// provider config. Callers walk provider homes, which may contain them.
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	mode := fs.FileMode(0o600)
	if info, err := entry.Info(); err == nil {
		mode = info.Mode() & 0o777
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

// Export only trusted host credentials. Import runs inside the worker because
// task-owned configuration and plugins must never execute on the host.
func exportOpenCodeCredentials(executable, destination string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "auth", "export", "--standalone")
	cmd.WaitDelay = 2 * time.Second
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	cmd.Dir = home
	data, err := cmd.Output()
	if err != nil {
		// CLI stderr and exported data can contain credentials.
		return fmt.Errorf("export OpenCode credentials failed; check OpenCode login on the daemon host (timeout=%t)", ctx.Err() != nil)
	}
	if !json.Valid(data) {
		return fmt.Errorf("OpenCode credential export returned invalid JSON")
	}
	return writeFileAtomic(destination, data, 0600)
}
