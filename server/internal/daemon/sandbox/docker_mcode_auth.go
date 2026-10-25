package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
)

// DockerMcodeAuthBinds preserves the profile's lexical auth path: MCode hashes
// that path into its credential key. Its native cross-process lock coordinates
// refreshes across workers and host CLI processes. Only OAuth state is shared;
// sessions, config, logs and tools resolve into the task's private data tree.
func DockerMcodeAuthBinds(taskHome, sourceDataDir string) ([]string, map[string]string, error) {
	if !filepath.IsAbs(sourceDataDir) || filepath.Clean(sourceDataDir) != sourceDataDir || filepath.Dir(sourceDataDir) == string(filepath.Separator) {
		return nil, nil, fmt.Errorf("MCode profile data directory must be absolute, clean and below a private parent")
	}
	authDir := filepath.Join(sourceDataDir, "auth")
	if err := os.MkdirAll(authDir, 0700); err != nil {
		return nil, nil, fmt.Errorf("create MCode auth directory: %w", err)
	}
	info, err := os.Lstat(authDir)
	if err != nil {
		return nil, nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("MCode auth directory must be a real directory")
	}
	privateData := filepath.Join(taskHome, ".minimax")
	if err := os.MkdirAll(privateData, 0700); err != nil {
		return nil, nil, err
	}
	// MCode locks the data directory using a sibling <dataDir>.lock. Its
	// parent must therefore be writable too, without exposing the host parent.
	return []string{DockerBind(taskHome, filepath.Dir(sourceDataDir), "rw"), DockerBind(privateData, sourceDataDir, "rw"), DockerBind(authDir, authDir, "rw")}, map[string]string{"MINIMAX_DATA_DIR": sourceDataDir, "MAVIS_DATA_DIR": sourceDataDir}, nil
}
