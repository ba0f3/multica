package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
)

// RuntimeNetworkMounts preserves the host's resolver when /etc names a file
// below a runtime directory that is otherwise absent from the sandbox.
func RuntimeNetworkMounts() ([]Mount, error) {
	return runtimeNetworkMounts([]string{"/etc/resolv.conf", "/etc/hosts"})
}

func runtimeNetworkMounts(paths []string) ([]Mount, error) {
	var mounts []Mount
	seen := map[string]bool{}
	for _, path := range paths {
		canonical, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, fmt.Errorf("native sandbox: network configuration %q is unavailable: %w", path, err)
		}
		info, err := os.Stat(canonical)
		if err != nil || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("native sandbox: network configuration %q must name a regular file", path)
		}
		if seen[canonical] {
			continue
		}
		mounts = append(mounts, Mount{Source: canonical, Target: canonical, ReadOnly: true})
		seen[canonical] = true
	}
	return mounts, nil
}
