package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Keep the root mount private so bwrap can create task IPC/output mountpoints.
// Each inherited top-level entry remains read-only at its original path.
func hostViewArgs(policy Policy) ([]string, []string, error) {
	entries, err := os.ReadDir("/")
	if err != nil {
		return nil, nil, fmt.Errorf("sandbox: read host root: %w", err)
	}
	var args []string
	for _, entry := range entries {
		switch entry.Name() {
		case "proc", "dev", "run", "sys", "tmp", "workspace":
			continue
		}
		path := filepath.Join("/", entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return nil, nil, err
			}
			args = append(args, "--symlink", target, path)
		} else {
			args = append(args, "--ro-bind", path, path)
		}
	}
	args = append(args, "--dir", "/workspace")
	masks := map[string]struct{}{}
	paths, err := hostMountAliases(policy.ForbiddenRoots)
	if err != nil {
		return nil, nil, err
	}
	// A read-only bind of a Unix socket still permits control RPCs.
	data, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		return nil, nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		path := strings.Join(fields[7:], " ")
		if !filepath.IsAbs(path) {
			continue
		}
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			paths = append(paths, path)
		}
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		if err := nativeAbsolutePath(path); err != nil {
			return nil, nil, err
		}
		if path == "/" {
			return nil, nil, fmt.Errorf("sandbox: cannot mask the host root")
		}
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, nil, err
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, nil, err
		}
		// The original alias resolves through the canonical mask too.
		masks[resolved] = struct{}{}
	}
	ordered := make([]string, 0, len(masks))
	for path := range masks {
		ordered = append(ordered, path)
	}
	sort.Slice(ordered, func(i, j int) bool { return len(ordered[i]) < len(ordered[j]) })
	var roots []string
	for _, path := range ordered {
		nested := false
		for _, parent := range roots {
			if isUnder(path, parent) {
				nested = true
				break
			}
		}
		if nested {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, nil, err
		}
		if info.IsDir() {
			args = append(args, "--tmpfs", path)
			roots = append(roots, path)
		} else {
			if isUnder(path, "/run") || isUnder(path, "/tmp") {
				continue
			}
			args = append(args, "--ro-bind", "/dev/null", path)
		}
	}
	return args, roots, nil
}
