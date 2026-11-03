package sandbox

import (
	"fmt"
	"os"
)

// BuildRestrictedArgs is the native worker/probe entry point. Unlike the
// compatibility BuildArgs view, it never inherits arbitrary host directories
// or the operator's HOME, even read-only. All application data must enter
// through a validated, explicit Policy grant.
func BuildRestrictedArgs(policy Policy, self string) ([]string, error) {
	return buildArgs(policy, self, true)
}

// These are trusted system program/library trees, not application data roots.
// In particular /home, /root, /opt, /srv, /var and the whole /etc are absent.
// Custom provider installations are already granted by the native resolver.
var restrictedSystemDirectories = []string{
	"/usr", "/bin", "/sbin", "/lib", "/lib64",
	"/etc/ssl/certs", "/etc/pki/tls/certs", "/etc/pki/ca-trust/extracted",
	"/etc/terminfo",
}

// Only public runtime configuration is inherited. Never grant /etc/ssl/private,
// SSH keys, credentials, environment files or an entire configuration tree.
var restrictedSystemFiles = []string{
	"/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf",
	"/etc/passwd", "/etc/group", "/etc/localtime", "/etc/ld.so.cache",
	"/etc/gai.conf", "/etc/services", "/etc/protocols",
}

func restrictedHostViewArgs() ([]string, error) {
	args := []string{"--dir", "/workspace"}
	appendPath := func(path string, directory bool) error {
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("sandbox: inspect system path %q: %w", path, err)
		}
		if directory != info.IsDir() || (!directory && !info.Mode().IsRegular()) {
			return fmt.Errorf("sandbox: unexpected system path type for %q", path)
		}
		// Bind the resolved contents, not a host symlink into an otherwise
		// private tree (resolv.conf commonly points into /run).
		args = append(args, "--ro-bind", path, path)
		return nil
	}
	for _, path := range restrictedSystemDirectories {
		if err := appendPath(path, true); err != nil {
			return nil, err
		}
	}
	for _, path := range restrictedSystemFiles {
		if err := appendPath(path, false); err != nil {
			return nil, err
		}
	}
	return args, nil
}

// A host symlink is inherited only if its containing system tree was actually
// mounted. A link under an unmounted HOME must be recreated explicitly, even
// though it exists on the host; otherwise custom CLI installations break.
func restrictedHostPathInherited(path string) bool {
	for _, root := range restrictedSystemDirectories {
		if isUnder(path, root) {
			return true
		}
	}
	for _, file := range restrictedSystemFiles {
		if path == file {
			return true
		}
	}
	return false
}
