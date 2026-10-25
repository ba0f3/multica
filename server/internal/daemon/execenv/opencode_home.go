package execenv

import (
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// prepareOpenCodeIsolatedHome seeds the per-task HOME with OpenCode config and
// credentials for Docker/bwrap workers. Host runs can keep using the daemon
// user's XDG dirs via inherited environment; isolated workers only see what is
// copied into the task home that is bind-mounted at /home/agent.
func prepareOpenCodeIsolatedHome(taskHome string, logger *slog.Logger) error {
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

	if err := mirrorOpenCodeTree(configSrc, filepath.Join(taskHome, ".config", "opencode"), logger); err != nil {
		return fmt.Errorf("copy opencode config: %w", err)
	}
	if err := mirrorOpenCodeTree(dataSrc, filepath.Join(taskHome, ".local", "share", "opencode"), logger); err != nil {
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

func mirrorOpenCodeTree(src, dst string, logger *slog.Logger) error {
	src = filepath.Clean(src)
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			if logger != nil {
				logger.Warn("execenv: opencode source missing (isolated run may fail auth)", "path", src)
			}
			return nil
		}
		return err
	}
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if entry.IsDir() && shouldSkipOpenCodeDir(rel) {
			return fs.SkipDir
		}
		target := filepath.Join(dst, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			// Never follow host symlinks into the worker; credentials must be copies.
			if logger != nil {
				logger.Warn("execenv: skip opencode symlink in isolated copy", "path", path)
			}
			return nil
		}
		if err := copyRegularFile(path, target, entry); err != nil {
			return err
		}
		return nil
	})
}

func shouldSkipOpenCodeDir(rel string) bool {
	base := filepath.Base(rel)
	switch base {
	case "log", "shell", "snapshot", "worktree", "tool-output", "repos":
		return true
	default:
		return false
	}
}

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
