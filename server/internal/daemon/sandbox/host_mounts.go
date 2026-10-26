package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type hostMount struct{ device, root, target string }

func hostMountAliases(paths []string) ([]string, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("sandbox: read host mounts: %w", err)
	}
	decode := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	var mounts []hostMount
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		mounts = append(mounts, hostMount{device: fields[2], root: decode.Replace(fields[3]), target: decode.Replace(fields[4])})
	}
	result := append([]string(nil), paths...)
	seeds := make(map[string]bool)
	for _, path := range paths {
		if path == "" {
			continue
		}
		canonical, err := filepath.EvalSymlinks(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		seeds[canonical] = true
		// Mountinfo already names canonical mountpoints. Do not resolve a child
		// through its host permissions: another readable alias may exist elsewhere.
		for _, mount := range mounts {
			if isUnder(mount.target, canonical) {
				seeds[mount.target] = true
			}
		}
	}
	for canonical := range seeds {
		var source *hostMount
		for i := range mounts {
			m := &mounts[i]
			if isUnder(canonical, m.target) && (source == nil || len(m.target) >= len(source.target)) {
				source = m
			}
		}
		if source == nil {
			continue
		}
		rel, err := filepath.Rel(source.target, canonical)
		if err != nil {
			return nil, err
		}
		backing := filepath.Join(source.root, rel)
		for _, mount := range mounts {
			if mount.device != source.device {
				continue
			}
			if isUnder(backing, mount.root) {
				rel, err := filepath.Rel(mount.root, backing)
				if err != nil {
					return nil, err
				}
				result = append(result, filepath.Join(mount.target, rel))
			} else if isUnder(mount.root, backing) {
				result = append(result, mount.target)
			}
		}
	}
	return result, nil
}
