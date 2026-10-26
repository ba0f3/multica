package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func newNativePolicy(t *testing.T) Policy {
	t.Helper()
	policy := newTestPolicy(t)
	policy.HostHome = filepath.Join(t.TempDir(), "host-home")
	policy.OutputDir = filepath.Join(policy.TaskRoot, "output")
	for _, path := range []string{policy.HostHome, policy.OutputDir} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	policy.ForbiddenRoots = append(policy.ForbiddenRoots, policy.HostHome)
	return policy
}

func TestNativePolicyPreservesOriginalHomeAndExplicitWritableGrants(t *testing.T) {
	policy := newNativePolicy(t)
	args, err := BuildArgs(policy, testSelf(t))
	if err != nil {
		t.Fatal(err)
	}
	if argsContain(args, "--ro-bind", policy.HostHome, policy.HostHome) || argsContain(args, "--bind", policy.HostHome, policy.HostHome) {
		t.Fatal("the native boundary mounted the host home")
	}
	if argsContain(args, "--bind", policy.HomeDir, policy.HostHome) || !argsContain(args, "--setenv", "HOME", policy.HostHome) {
		t.Fatal("the original read-only HOME was replaced or lost")
	}
}

func TestNativePolicyRejectsSourceSymlinkEscape(t *testing.T) {
	policy := newNativePolicy(t)
	otherTask := filepath.Join(policy.ForbiddenRoots[0], "someone-else", "task-2")
	if err := os.MkdirAll(otherTask, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(policy.TaskRoot, "borrowed")
	if err := os.Symlink(otherTask, alias); err != nil {
		t.Fatal(err)
	}
	policy.AllowedRoots = []string{policy.TaskRoot}
	policy.ExtraMounts = []Mount{{Source: alias, Target: "/opt/borrowed"}}
	if _, err := BuildArgs(policy, testSelf(t)); err == nil {
		t.Fatal("a task-local symlink exposed another task")
	}
}

func TestNativePolicyRejectsTargetSymlinkEscape(t *testing.T) {
	policy := newNativePolicy(t)
	profile := filepath.Join(policy.HostHome, ".codex")
	if err := os.MkdirAll(profile, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(profile, "escape")
	if err := os.Symlink("/usr/bin", alias); err != nil {
		t.Fatal(err)
	}
	policy.AllowedRoots = []string{profile}
	policy.ExtraMounts = []Mount{{Source: profile, Target: alias}}
	if _, err := BuildArgs(policy, testSelf(t)); err == nil {
		t.Fatal("a nested target symlink redirected the profile grant")
	}
}

func TestNativePolicyRejectsAnAncestorOfTheHostHome(t *testing.T) {
	policy := newNativePolicy(t)
	policy.RuntimeRoots = append(policy.RuntimeRoots, filepath.Dir(policy.HostHome))
	if _, err := BuildArgs(policy, testSelf(t)); err == nil {
		t.Fatal("a broad runtime mount exposed the host home through its parent")
	}
}

func TestNativePolicyRealFilesystemBoundary(t *testing.T) {
	if os.Getenv("MULTICA_BWRAP_SMOKE") != "1" {
		t.Skip("set MULTICA_BWRAP_SMOKE=1 for the real boundary with synthetic data")
	}
	policy := newNativePolicy(t)
	policy.RuntimeRoots = nil
	for _, path := range []string{"/usr", "/bin", "/lib", "/lib64", "/etc"} {
		if _, err := os.Stat(path); err == nil {
			policy.RuntimeRoots = append(policy.RuntimeRoots, path)
		}
	}
	profile := filepath.Join(policy.HostHome, ".codex")
	code := filepath.Join(profile, "packages")
	cache := filepath.Join(filepath.Dir(policy.TaskRoot), "repo-cache")
	secrets := []string{filepath.Join(policy.HostHome, ".ssh", "key"), filepath.Join(policy.HostHome, ".multica", "config.json"), filepath.Join(policy.HostHome, ".git-credentials"), filepath.Join(filepath.Dir(policy.TaskRoot), "other-task", "secret")}
	for _, path := range append(append([]string{}, secrets...), filepath.Join(profile, "config.json"), filepath.Join(code, "binary"), filepath.Join(cache, "object")) {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("synthetic sentinel"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(secrets[0], filepath.Join(profile, "secret-link")); err != nil {
		t.Fatal(err)
	}
	policy.AllowedRoots = append(policy.AllowedRoots, profile, cache)
	// The renderer must order the parent grant before its read-only child.
	policy.ExtraMounts = []Mount{{Source: code, Target: code, ReadOnly: true}, {Source: cache, Target: "/run/multica/cache", ReadOnly: true}, {Source: profile, Target: profile}}
	script := "#!/bin/sh\nset -eu\n"
	for _, path := range append(secrets, filepath.Join(profile, "secret-link"), "/run/docker.sock", "/var/run/docker.sock") {
		script += fmt.Sprintf("test ! -r '%s'\n", path)
	}
	script += fmt.Sprintf("test \"$HOME\" = '%s'\ncat '%s/config.json' > report.txt\nprintf 'changed profile' > '%s/state'\n", policy.HostHome, profile, profile)
	script += fmt.Sprintf("if (printf bad > '%s/binary') 2>/dev/null; then exit 41; fi\n", code)
	script += "if (printf bad > /run/multica/cache/object) 2>/dev/null; then exit 42; fi\n"
	script += "if (printf bad > \"$HOME/outside-profile\") 2>/dev/null; then exit 43; fi\n"
	script += "if (printf bad > /outside-task) 2>/dev/null; then exit 44; fi\n"
	script += "grep -q '^NoNewPrivs:[[:space:]]*1$' /proc/self/status\ngrep -q '^CapEff:[[:space:]]*0000000000000000$' /proc/self/status\n"
	script += fmt.Sprintf("test ! -e /proc/%d\nprintf artifact > '/workspace/output/result'\n", os.Getpid())
	worker := filepath.Join(t.TempDir(), "probe-worker")
	if err := os.WriteFile(worker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	args, err := BuildArgs(policy, worker)
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("bwrap", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("native boundary: %v: %s", err, output)
	}
	for path, want := range map[string]string{filepath.Join(policy.CheckoutDir, "report.txt"): "synthetic sentinel", filepath.Join(policy.OutputDir, "result"): "artifact", filepath.Join(profile, "state"): "changed profile"} {
		got, err := os.ReadFile(path)
		if err != nil || strings.TrimSpace(string(got)) != want {
			t.Fatalf("artifact %s: %q, %v", path, got, err)
		}
	}
}
