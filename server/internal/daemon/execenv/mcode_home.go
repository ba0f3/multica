package execenv

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

func resolveMcodeDataDir() (string, error) {
	for _, key := range []string{"MINIMAX_DATA_DIR", "MAVIS_DATA_DIR"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			if !filepath.IsAbs(value) || filepath.Clean(value) == string(filepath.Separator) {
				return "", fmt.Errorf("%s must name an absolute MCode data directory", key)
			}
			return filepath.Clean(value), nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".minimax"), nil
}

// OAuth refresh tokens rotate, so task-local copies cannot remain independent.
// Docker mounts the original auth namespace and lock at their original paths;
// everything else is copied into this private task data directory.
func prepareMcodeHome(taskHome string, logger *slog.Logger) error {
	source, err := resolveMcodeDataDir()
	if err != nil {
		return err
	}
	target := filepath.Join(taskHome, ".minimax")
	taskRoot, err := os.OpenRoot(taskHome)
	if err != nil {
		return err
	}
	// Remove obsolete task auth and process locks before applying profile mounts.
	// Root prevents task-created symlinks from redirecting this cleanup outside HOME.
	err = taskRoot.RemoveAll(filepath.Join(".minimax", "auth"))
	if err == nil {
		// The daemon holds the task-home claim; a prior container cannot still
		// own this process lock, even if it exited before releasing it.
		err = taskRoot.RemoveAll(filepath.Base(source) + ".lock")
	}
	taskRoot.Close()
	if err != nil {
		return fmt.Errorf("clean stale MCode task state: %w", err)
	}
	if err := mirrorProviderTree(source, target, dirSet("auth", "run", "v2", "cache", "background-tasks", "sessions", "snapshots", "logs"), logger); err != nil {
		return err
	}
	preference := filepath.Join(source, "preferences", "mcode-region.json")
	info, err := os.Lstat(preference)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("MCode region preference must be a regular file")
	}
	data, err := os.ReadFile(preference)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(target, "preferences", "mcode-region.json"), data, 0600)
}
