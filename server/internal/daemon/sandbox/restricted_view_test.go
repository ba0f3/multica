package sandbox

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func restrictedViewFixture(t *testing.T) (Policy, string, string, string) {
	t.Helper()
	// Keep Unix socket paths short, independently of the test's full name.
	root, err := os.MkdirTemp("", "mc-r2-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	home := filepath.Join(root, "host")
	own := filepath.Join(home, "profiles", "a")
	peer := filepath.Join(home, "profiles", "b")
	task := filepath.Join(root, "task")
	for _, path := range []string{home, own, peer, filepath.Join(task, "home"), filepath.Join(task, "tmp"), filepath.Join(task, "repo")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for path, content := range map[string]string{
		filepath.Join(own, "canary"): "own-data",
		filepath.Join(peer, "canary"): "peer-secret",
		filepath.Join(home, "operator-secret"): "operator-secret",
	} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(peer, "canary"), filepath.Join(own, "peer-link")); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	policy := Policy{
		TaskRoot: task, HomeDir: filepath.Join(task, "home"), HostHome: home,
		TempDir: filepath.Join(task, "tmp"), CheckoutDir: filepath.Join(task, "repo"),
		ExtraMounts: []Mount{{Source: own, Target: own}},
		AllowedRoots: []string{task}, AllowedExactPaths: []string{own},
		Env: map[string]string{"PATH": "/usr/bin:/bin"},
	}
	return policy, self, own, peer
}

func TestRestrictedViewDoesNotInheritHostDataRoots(t *testing.T) {
	policy, self, own, peer := restrictedViewFixture(t)
	args, err := BuildRestrictedArgs(policy, self)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+2 < len(args); i++ {
		if args[i] != "--bind" && args[i] != "--ro-bind" {
			continue
		}
		source := args[i+1]
		for _, forbidden := range []string{"/", "/home", "/root", "/opt", "/srv", "/var", "/etc", policy.HostHome, filepath.Dir(own), peer} {
			if source == forbidden {
				t.Fatalf("restricted worker inherits broad/private source %q", source)
			}
		}
	}
	if !strings.Contains(strings.Join(args, "\n"), "--bind\n"+own+"\n"+own) {
		t.Fatal("authorized profile grant is missing")
	}
}

func TestRestrictedViewRecreatesCustomInstallationLinks(t *testing.T) {
	policy, self, _, _ := restrictedViewFixture(t)
	link := filepath.Join(policy.HostHome, "agent")
	if err := os.Symlink("/bin/sh", link); err != nil {
		t.Fatal(err)
	}
	policy.Links = []NativeLink{{Path: link, Target: "/bin/sh"}}
	args, err := BuildRestrictedArgs(policy, self)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(args, "\n"), "--symlink\n/bin/sh\n"+link) {
		t.Fatal("custom installation link was incorrectly considered inherited")
	}
}

func TestRestrictedViewBwrapDeniesPeerReadAndLateSocket(t *testing.T) {
	require := os.Getenv("MULTICA_REQUIRE_BWRAP_SECURITY_TESTS") == "1"
	unavailable := func(message string) {
		t.Helper()
		if require {
			t.Fatal(message)
		}
		t.Skip(message)
	}
	if runtime.GOOS != "linux" {
		unavailable("Linux is required for the native boundary test")
	}
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		unavailable("bwrap is required for the native boundary test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, bwrap, "--unshare-user", "--ro-bind", "/", "/", "--", "/bin/true").CombinedOutput(); err != nil {
		unavailable("user namespaces unavailable: " + err.Error() + ": " + string(output))
	}
	policy, self, own, peer := restrictedViewFixture(t)
	ownSocket := filepath.Join(policy.TaskRoot, "signer.sock")
	listener, err := net.Listen("unix", ownSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	policy.AgentSocket = ownSocket
	policy.AllowedExactPaths = append(policy.AllowedExactPaths, ownSocket)
	policy.Env["OWN"] = own
	policy.Env["PEER"] = peer
	policy.Command = []string{"/bin/sh", "-ec", `
		test "$(cat "$OWN/canary")" = own-data
		test ! -e "$PEER/canary"
		test ! -e "$OWN/peer-link"
		test ! -e "$HOME/operator-secret"
		test ! -S "$PEER/late.sock"
		test -S "$SSH_AUTH_SOCK"
		printf writable > "$OWN/write-check"
		printf writable > repo-write-check
		printf 'RESTRICTED_BOUNDARY_OK\n'
	`}
	args, err := BuildRestrictedArgs(policy, self)
	if err != nil {
		t.Fatal(err)
	}
	// The peer socket appears AFTER snapshot-based socket masks were built.
	// Only excluding the peer tree itself reliably closes this race.
	late, err := net.Listen("unix", filepath.Join(peer, "late.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer late.Close()
	output, err := exec.CommandContext(ctx, bwrap, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("restricted worker failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "RESTRICTED_BOUNDARY_OK") {
		t.Fatalf("missing successful boundary probe: %s", output)
	}
	for _, path := range []string{filepath.Join(own, "write-check"), filepath.Join(policy.CheckoutDir, "repo-write-check")} {
		if data, err := os.ReadFile(path); err != nil || string(data) != "writable" {
			t.Fatalf("authorized write did not reach %s: %q, %v", path, data, err)
		}
	}
}
