package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var privateHostViews = []string{"/proc", "/dev", "/run", "/sys", "/tmp"}

type hostMask struct {
	path      string
	directory bool
}
type hostView struct {
	home       string
	args       []string
	seals      []string
	early      []hostMask
	management []hostMask
	sockets    []string
}

// The root itself stays private so bwrap can create task IPC/output paths.
// Inherited top-level entries are read-only at their original locations.
func hostViewArgs(policy Policy) (hostView, error) {
	var view hostView
	entries, err := os.ReadDir("/")
	if err != nil {
		return view, err
	}
	for _, entry := range entries {
		switch entry.Name() {
		case "proc", "dev", "run", "sys", "tmp", "workspace":
			continue
		}
		path := filepath.Join("/", entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return view, err
			}
			view.args = append(view.args, "--symlink", target, path)
		} else {
			view.args = append(view.args, "--ro-bind", path, path)
		}
	}
	view.args = append(view.args, "--dir", "/workspace")
	if policy.HostHome != "" {
		view.home, err = filepath.EvalSymlinks(policy.HostHome)
		if err != nil {
			return view, err
		}
	}
	managed, err := hostMountAliases(policy.ForbiddenRoots)
	if err != nil {
		return view, err
	}
	view.early, err = existingHostMasks(managed, false, "")
	if err != nil {
		return view, err
	}
	for _, mask := range view.early {
		if mask.directory {
			view.seals = append(view.seals, mask.path)
		}
	}
	management, err := hostMountAliases(privateHostViews)
	if err != nil {
		return view, err
	}
	view.management, err = existingHostMasks(management, true, view.home)
	if err != nil {
		return view, err
	}
	// A read-only socket still accepts control RPCs. Expand its aliases too.
	data, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		return view, err
	}
	var sockets []string
	for _, line := range strings.Split(string(data), "\n") {
		rest := line
		for i := 0; i < 7; i++ {
			rest = strings.TrimLeft(rest, " \t")
			end := strings.IndexAny(rest, " \t")
			if end < 0 {
				rest = ""
				break
			}
			rest = rest[end:]
		}
		path := strings.TrimLeft(rest, " \t")
		if !filepath.IsAbs(path) {
			continue
		}
		if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeSocket != 0 {
			sockets = append(sockets, path)
		}
	}
	view.sockets, err = hostMountAliases(sockets)
	return view, err
}

func existingHostMasks(paths []string, skipPrivate bool, hostHome string) ([]hostMask, error) {
	var masks []hostMask
	for _, path := range paths {
		if path == "" {
			continue
		}
		if err := nativeAbsolutePath(path); err != nil {
			return nil, err
		}
		if path == "/" {
			return nil, fmt.Errorf("sandbox: cannot mask the host root")
		}
		if skipPrivate && underPrivateView(path) && (hostHome == "" || !isUnder(path, hostHome)) {
			primary := false
			for _, root := range privateHostViews {
				if path == root {
					primary = true
					break
				}
			}
			if !primary {
				continue
			}
		}
		resolved, err := filepath.EvalSymlinks(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}

		info, err := os.Stat(resolved)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		masks = append(masks, hostMask{path: resolved, directory: info.IsDir()})
	}
	// Primary private views are replaced before HOME/profile grants. Keep their
	// aliases separate until final rendering so a /tmp parent cannot absorb a
	// management alias inside an explicitly restored HOME.
	if skipPrivate {
		return masks, nil
	}
	return collapseHostMasks(masks), nil
}

func underPrivateView(path string) bool {
	for _, root := range privateHostViews {
		if isUnder(path, root) {
			return true
		}
	}
	return false
}

func collapseHostMasks(masks []hostMask) []hostMask {
	sort.Slice(masks, func(i, j int) bool {
		if len(masks[i].path) == len(masks[j].path) {
			return masks[i].path < masks[j].path
		}
		return len(masks[i].path) < len(masks[j].path)
	})
	var result []hostMask
	for _, mask := range masks {
		covered := false
		for _, parent := range result {
			if mask.path == parent.path || parent.directory && isUnder(mask.path, parent.path) {
				covered = true
				break
			}
		}
		if !covered {
			result = append(result, mask)
		}
	}
	return result
}

func appendHostMask(args []string, mask hostMask) []string {
	if mask.directory {
		return append(args, "--tmpfs", mask.path)
	}
	return append(args, "--ro-bind", "/dev/null", mask.path)
}

// Enforce exclusions after every host grant, including remapped profile trees.
// Only the explicitly bound task signer is added after these exclusions.
func (view hostView) finalMasks(grants []Mount) []hostMask {
	var masks []hostMask
	for _, mask := range view.management {
		if !underPrivateView(mask.path) || view.home != "" && isUnder(mask.path, view.home) {
			masks = append(masks, mask)
		}
		// /tmp is intentionally repopulated with scoped task data. Other process
		// and management trees must not be restored through a declared grant.
		if isUnder(mask.path, "/tmp") {
			continue
		}
		for _, grant := range grants {
			if isUnder(mask.path, grant.Source) {
				rel, _ := filepath.Rel(grant.Source, mask.path)
				masks = append(masks, hostMask{path: filepath.Join(grant.Target, rel), directory: mask.directory})
			} else if mask.directory && isUnder(grant.Source, mask.path) {
				info, err := os.Stat(grant.Source)
				if err == nil {
					masks = append(masks, hostMask{path: grant.Target, directory: info.IsDir()})
				}
			}
		}
	}
	candidates := append([]string(nil), view.sockets...)
	for _, source := range view.sockets {
		for _, grant := range grants {
			if isUnder(source, grant.Source) {
				rel, _ := filepath.Rel(grant.Source, source)
				candidates = append(candidates, filepath.Join(grant.Target, rel))
			}
		}
	}
	for _, target := range candidates {
		source := target
		if underPrivateView(target) && (view.home == "" || !isUnder(target, view.home)) {
			source = ""
		}
		for _, mask := range view.early {
			if target == mask.path || mask.directory && isUnder(target, mask.path) {
				source = ""
				break
			}
		}
		for _, grant := range grants {
			if isUnder(target, grant.Target) {
				rel, _ := filepath.Rel(grant.Target, target)
				source = filepath.Join(grant.Source, rel)
			}
		}
		if source == "" {
			continue
		}
		if info, err := os.Stat(source); err == nil && info.Mode()&os.ModeSocket != 0 {
			masks = append(masks, hostMask{path: target})
		}
	}
	return collapseHostMasks(masks)
}
