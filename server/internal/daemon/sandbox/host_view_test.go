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
	policy.RuntimeRoots = []string{"/usr", "/bin", "/lib", "/lib64", "/etc"}
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
