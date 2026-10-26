package sandbox

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestNativeHostViewRealReadOnlyAndUserMasks(t *testing.T) {
	if os.Getenv("MULTICA_BWRAP_SMOKE") != "1" {
		t.Skip("set MULTICA_BWRAP_SMOKE=1 for synthetic kernel probe")
	}
	policy := newNativePolicy(t)
	policy.ForbiddenRoots = policy.ForbiddenRoots[:1]
	policy.CheckoutTarget = policy.CheckoutDir
	unmanaged, err := os.MkdirTemp(".", ".host-view-")
	if err != nil {
		t.Fatal(err)
	}
	unmanaged, err = filepath.Abs(unmanaged)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(unmanaged) })
	hostFile := filepath.Join(unmanaged, "original-install-file")
	if err := os.WriteFile(hostFile, []byte("host-runtime"), 0600); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(policy.HostHome, ".provider")
	if err := os.MkdirAll(profile, 0700); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(policy.ForbiddenRoots[0], "bob", "private.git")
	if err := os.MkdirAll(sibling, 0700); err != nil {
		t.Fatal(err)
	}
	siblingFile := filepath.Join(sibling, "secret")
	if err := os.WriteFile(siblingFile, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(unmanaged, "code-alias")
	if err := os.Symlink(policy.ForbiddenRoots[0], alias); err != nil {
		t.Fatal(err)
	}
	admin := filepath.Join(policy.HostHome, ".multica")
	if err := os.MkdirAll(admin, 0700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(admin, "control.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	policy.ForbiddenRoots = append(policy.ForbiddenRoots, admin)
	policy.ExtraMounts = []Mount{{Source: profile, Target: profile}}
	worker := filepath.Join(unmanaged, "worker")
	script := fmt.Sprintf("#!/bin/sh\nset -eu\ntest \"$(cat '%s')\" = host-runtime\nif (echo bad > '%s') 2>/dev/null; then exit 41; fi\ntest ! -r '%s'\ntest ! -r '%s/bob/private.git/secret'\ntest ! -S '%s/control.sock'\necho state > '%s/session'\necho checkout > result\ntest ! -e /run/docker.sock\ntest ! -e /var/run/docker.sock\ntest ! -e /proc/%d\n", hostFile, hostFile, siblingFile, alias, admin, profile, os.Getpid())
	if err := os.WriteFile(worker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	args, err := BuildArgs(policy, worker)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("bwrap", args...).CombinedOutput(); err != nil {
		t.Fatalf("host view: %v: %s", err, output)
	}
	for _, path := range []string{filepath.Join(profile, "session"), filepath.Join(policy.CheckoutDir, "result")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNativeHostViewMasksBindAliases(t *testing.T) {
	if os.Getenv("MULTICA_BWRAP_SMOKE") != "1" {
		t.Skip("synthetic mount namespace probe")
	}
	policy := newNativePolicy(t)
	policy.ForbiddenRoots = policy.ForbiddenRoots[:1]
	policy.CheckoutTarget = policy.CheckoutDir
	sibling := filepath.Join(policy.ForbiddenRoots[0], "bob", "secret")
	if err := os.MkdirAll(filepath.Dir(sibling), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sibling, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Mkdir(alias, 0700); err != nil {
		t.Fatal(err)
	}
	worker := testSelf(t)
	policy.Command = []string{"/bin/sh", "-c", `test ! -r "$1/bob/secret"`, "probe", alias}
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("unshare", "--user", "--map-root-user", "--mount", "--fork", "/bin/sh", "-c", `mount --bind "$1" "$2" && exec "$3" -test.run '^TestNativeHostViewBindAliasHelper$'`, "probe", policy.ForbiddenRoots[0], alias, binary)
	cmd.Env = append(os.Environ(), "MULTICA_HOST_ALIAS_POLICY="+string(data), "MULTICA_HOST_ALIAS_WORKER="+worker)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bind alias boundary: %v: %s", err, out)
	}
}

func TestNativeHostViewBindAliasHelper(t *testing.T) {
	data := os.Getenv("MULTICA_HOST_ALIAS_POLICY")
	if data == "" {
		t.Skip("mount namespace helper")
	}
	var policy Policy
	if err := json.Unmarshal([]byte(data), &policy); err != nil {
		t.Fatal(err)
	}
	args, err := BuildArgs(policy, os.Getenv("MULTICA_HOST_ALIAS_WORKER"))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("bwrap", args...).CombinedOutput(); err != nil {
		t.Fatalf("other user's bind alias remained visible: %v: %s", err, out)
	}
}

func TestNativeHostViewHidesNestedFilesystemAliases(t *testing.T) {
	t.Setenv("TMPDIR", "/var/tmp")
	if os.Getenv("MULTICA_BWRAP_SMOKE") != "1" {
		t.Skip("synthetic mount namespace probe")
	}
	policy := newHostViewKernelFixture(t)
	policy.CheckoutTarget = policy.CheckoutDir
	bob := filepath.Join(policy.ForbiddenRoots[0], "bob")
	if err := os.MkdirAll(bob, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("/var/tmp", "mc-nested-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	alias := filepath.Join(root, "alias")
	if err := os.Mkdir(alias, 0700); err != nil {
		t.Fatal(err)
	}
	policy.Command = []string{"/bin/sh", "-c", `test ! -r "$1/secret"`, "probe", alias}
	runHostViewNamespaceHelper(t, policy, `mount -t tmpfs tmpfs "$1" && printf synthetic > "$1/secret" && mount --bind "$1" "$2" && exec "$3" -test.run '^TestNativeHostViewBindAliasHelper$'`, bob, alias)
}

func TestNativeHostViewHidesManagementRootAliases(t *testing.T) {
	t.Setenv("TMPDIR", "/var/tmp")
	if os.Getenv("MULTICA_BWRAP_SMOKE") != "1" {
		t.Skip("synthetic mount namespace probe")
	}
	for _, kind := range []string{"run", "proc", "run-restored-home"} {
		t.Run(kind, func(t *testing.T) {
			policy := newHostViewKernelFixture(t)
			policy.CheckoutTarget = policy.CheckoutDir
			root, err := os.MkdirTemp("/var/tmp", "mc-management-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			alias := filepath.Join(root, "alias")
			if kind == "run-restored-home" {
				home, err := os.MkdirTemp("/tmp", "mc-restored-home-")
				if err != nil {
					t.Fatal(err)
				}
				defer os.RemoveAll(home)
				policy.HostHome = home
				alias = filepath.Join(home, "alias")
			}
			if err := os.Mkdir(alias, 0700); err != nil {
				t.Fatal(err)
			}
			script := `mount --rbind /proc "$2" && exec "$3" -test.run '^TestNativeHostViewBindAliasHelper$'`
			source := root
			policy.Command = []string{"/bin/sh", "-c", `test ! -r "$1/self/status"`, "probe", alias}
			if kind != "proc" {
				source = filepath.Join(root, "management")
				if err := os.Mkdir(source, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(source, "sentinel"), []byte("synthetic"), 0600); err != nil {
					t.Fatal(err)
				}
				script = `mount --bind "$1" /run && mount --bind /run "$2" && exec "$3" -test.run '^TestNativeHostViewBindAliasHelper$'`
				policy.Command = []string{"/bin/sh", "-c", `test ! -r "$1/sentinel"`, "probe", alias}
			}
			runHostViewNamespaceHelper(t, policy, script, source, alias)
		})
	}
}

func TestNativeHostViewHidesSocketAliasesAfterProfileMount(t *testing.T) {
	t.Setenv("TMPDIR", "/var/tmp")
	if os.Getenv("MULTICA_BWRAP_SMOKE") != "1" {
		t.Skip("synthetic mount namespace probe")
	}
	policy := newHostViewKernelFixture(t)
	policy.CheckoutTarget = policy.CheckoutDir
	root, err := os.MkdirTemp("/var/tmp", "mc-socket-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	policy.HostHome = filepath.Join(root, "home")
	profile := filepath.Join(policy.HostHome, "provider  state")
	if err := os.MkdirAll(profile, 0700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(profile, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	alias := filepath.Join(root, "alias.sock")
	if err := os.WriteFile(alias, nil, 0600); err != nil {
		t.Fatal(err)
	}
	mapped := filepath.Join(root, "mapped")
	if err := os.Mkdir(mapped, 0700); err != nil {
		t.Fatal(err)
	}
	policy.ExtraMounts = []Mount{{Source: profile, Target: profile}, {Source: profile, Target: mapped}}
	policy.Command = []string{"/bin/sh", "-c", `test ! -S "$1" && test ! -S "$2" && test ! -S "$3/control.sock" && printf state > "$4/auth-state"`, "probe", socket, alias, mapped, profile}
	runHostViewNamespaceHelper(t, policy, `mount --bind "$1" "$2" && exec "$3" -test.run '^TestNativeHostViewBindAliasHelper$'`, socket, alias)
	info, err := os.Lstat(socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("host socket was changed: %v", err)
	}
}

func runHostViewNamespaceHelper(t *testing.T, policy Policy, script, source, alias string) {
	t.Helper()
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("unshare", "--user", "--map-root-user", "--mount", "--fork", "/bin/sh", "-c", script, "probe", source, alias, binary)
	cmd.Env = append(os.Environ(), "MULTICA_HOST_ALIAS_POLICY="+string(data), "MULTICA_HOST_ALIAS_WORKER="+testSelf(t))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("host-view exclusion: %v: %s", err, out)
	}
}

func newHostViewKernelFixture(t *testing.T) Policy {
	t.Helper()
	root, err := os.MkdirTemp("/var/tmp", "mc-view-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	managed := filepath.Join(root, "managed")
	task := filepath.Join(managed, "alice", "task")
	policy := Policy{TaskRoot: task, HomeDir: filepath.Join(task, "home"), HostHome: filepath.Join(root, "host-home"), TempDir: filepath.Join(task, "tmp"), CheckoutDir: filepath.Join(task, "workdir"), ForbiddenRoots: []string{managed}, Env: map[string]string{"PATH": "/usr/bin:/bin"}}
	for _, path := range []string{policy.HomeDir, policy.HostHome, policy.TempDir, policy.CheckoutDir} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	return policy
}
