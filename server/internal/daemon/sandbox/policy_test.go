package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestPolicy(t *testing.T) Policy {
	t.Helper()
	root := t.TempDir()
	workspaces := filepath.Join(root, "workspaces")
	taskRoot := filepath.Join(workspaces, "acme", "task-1")
	checkout := filepath.Join(taskRoot, "workdir")
	home := filepath.Join(taskRoot, "home")
	temp := filepath.Join(taskRoot, "tmp")
	for _, dir := range []string{checkout, home, temp, filepath.Join(root, "usr"), filepath.Join(root, "etc")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
	}
	return Policy{
		TaskRoot:       taskRoot,
		HomeDir:        home,
		TempDir:        temp,
		CheckoutDir:    checkout,
		RuntimeRoots:   []string{filepath.Join(root, "usr"), filepath.Join(root, "etc")},
		ForbiddenRoots: []string{workspaces, filepath.Join(root, "home", "someone")},
		Env:            map[string]string{"PATH": "/usr/bin:/bin", "HOME": "/home/agent"},
	}
}

// testSelf creates the worker executable the policy mounts.
func testSelf(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "multica")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write the worker executable: %v", err)
	}
	return path
}

func argsContain(args []string, want ...string) bool {
	joined := strings.Join(args, "\x00")
	return strings.Contains(joined, strings.Join(want, "\x00"))
}

func TestBuildArgsIsolatesTheTask(t *testing.T) {
	policy := newTestPolicy(t)
	args, err := BuildArgs(policy, testSelf(t))
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}

	for _, flag := range []string{
		"--clearenv",
		"--unshare-user",
		"--unshare-pid",
		"--unshare-ipc",
		"--unshare-uts",
		"--new-session",
		"--die-with-parent",
		"--cap-drop", "ALL",
	} {
		if !argsContain(args, flag) {
			t.Errorf("argv is missing %q", flag)
		}
	}
	// Network stays available: tasks clone repositories and call providers.
	if argsContain(args, "--unshare-net") {
		t.Error("argv unshares the network, which would break Git and model calls")
	}
	// bwrap itself forces no_new_privs during setup; older releases have no
	// flag for it, so asserting one here would pin an option that does not
	// exist.
	if argsContain(args, "--no-new-privileges") {
		t.Error("argv carries a bwrap option that is not supported")
	}
}

func TestBuildArgsMountsOnlyTheTaskAndTheRuntime(t *testing.T) {
	policy := newTestPolicy(t)
	args, err := BuildArgs(policy, testSelf(t))
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}

	if !argsContain(args, "--bind", policy.CheckoutDir, sandboxRepo) {
		t.Errorf("the checkout is not mounted read-write at %s", sandboxRepo)
	}
	if !argsContain(args, "--bind", policy.HomeDir, sandboxHome) {
		t.Errorf("the private home is not mounted at %s", sandboxHome)
	}
	if !argsContain(args, "--bind", policy.TempDir, "/tmp") {
		t.Error("the private temp directory is not mounted at /tmp")
	}
	for _, runtimeRoot := range policy.RuntimeRoots {
		if !argsContain(args, "--ro-bind", runtimeRoot, runtimeRoot) {
			t.Errorf("the runtime root %s is not mounted read-only", runtimeRoot)
		}
	}
	if argsContain(args, "--ro-bind", "/", "/") {
		t.Error("argv exposes the whole filesystem read-only")
	}
}

func TestBuildArgsRefusesToMountTheHostOrAnotherTask(t *testing.T) {
	policy := newTestPolicy(t)
	// A mount that reaches outside the task root, into the shared
	// workspaces root, would expose every other task's checkout.
	policy.ExtraMounts = []Mount{{
		Source: filepath.Join(policy.ForbiddenRoots[0], "other-user", "task-9"),
		Target: "/opt/borrowed",
	}}
	if _, err := BuildArgs(policy, testSelf(t)); err == nil {
		t.Fatal("a mount under the shared workspaces root was accepted")
	}
}

func TestBuildArgsRefusesAMissingSource(t *testing.T) {
	policy := newTestPolicy(t)
	policy.ExtraMounts = []Mount{{Source: filepath.Join(policy.TaskRoot, "missing"), Target: "/opt/missing"}}
	if _, err := BuildArgs(policy, testSelf(t)); err == nil {
		t.Fatal("a mount with a missing source was accepted")
	}
}

func TestBuildArgsRequiresTheEssentialPaths(t *testing.T) {
	cases := map[string]func(*Policy){
		"no task root": func(p *Policy) { p.TaskRoot = "" },
		"no home":      func(p *Policy) { p.HomeDir = "" },
		"no temp":      func(p *Policy) { p.TempDir = "" },
		"no checkout":  func(p *Policy) { p.CheckoutDir = "" },
		"relative task root": func(p *Policy) {
			p.TaskRoot = "relative"
			p.HomeDir = "relative/home"
			p.TempDir = "relative/tmp"
			p.CheckoutDir = "relative/workdir"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			policy := newTestPolicy(t)
			mutate(&policy)
			if _, err := BuildArgs(policy, testSelf(t)); err == nil {
				t.Fatal("BuildArgs accepted an incomplete policy")
			}
		})
	}
	if _, err := BuildArgs(newTestPolicy(t), ""); err == nil {
		t.Fatal("BuildArgs accepted an empty self path")
	}
}

func TestBuildArgsMountsTheAgentSocketWhenOneIsGranted(t *testing.T) {
	policy := newTestPolicy(t)
	socket := filepath.Join(policy.TaskRoot, "git-agent", "ssh-agent.sock")
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		t.Fatalf("create socket dir: %v", err)
	}
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatalf("create socket file: %v", err)
	}
	policy.AgentSocket = socket

	args, err := BuildArgs(policy, testSelf(t))
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	if !argsContain(args, "--bind", socket, sandboxAgentSocket) {
		t.Error("the signing socket is not mounted")
	}
	if !argsContain(args, "--setenv", "SSH_AUTH_SOCK", sandboxAgentSocket) {
		t.Error("SSH_AUTH_SOCK does not point at the mounted socket")
	}
}

func TestBuildArgsEndsWithTheWorkerCommand(t *testing.T) {
	self := testSelf(t)
	args, err := BuildArgs(newTestPolicy(t), self)
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	if len(args) < 4 {
		t.Fatalf("argv is too short: %v", args)
	}
	tail := args[len(args)-3:]
	if tail[0] != "--" || tail[1] != sandboxWorker || tail[2] != WorkerArg {
		t.Fatalf("argv does not end with -- <worker> %s: %v", WorkerArg, tail)
	}
	// The worker runs from inside the boundary, so its executable is mounted
	// there rather than executed from a host path.
	if !argsContain(args, "--ro-bind", self, sandboxWorker) {
		t.Error("the worker executable is not mounted into the sandbox")
	}
}

func TestBuildArgsAllowsANamedPathInsideAForbiddenRoot(t *testing.T) {
	policy := newTestPolicy(t)
	forbidden := policy.ForbiddenRoots[0]
	named := filepath.Join(forbidden, "other-user", "task-9")
	if err := os.MkdirAll(named, 0o755); err != nil {
		t.Fatalf("create the named path: %v", err)
	}
	policy.AllowedExactPaths = []string{named}
	policy.ExtraMounts = []Mount{{Source: named, Target: named}}

	if _, err := BuildArgs(policy, testSelf(t)); err != nil {
		t.Fatalf("a named path inside a forbidden root was refused: %v", err)
	}

	// The parent is still refused: naming one path must not open the tree.
	policy.AllowedExactPaths = nil
	if _, err := BuildArgs(policy, testSelf(t)); err == nil {
		t.Fatal("the forbidden root was opened by a named sibling")
	}
}

func TestBuildArgsRefusesToLetCallerEnvOverrideTheBoundaryPaths(t *testing.T) {
	policy := newTestPolicy(t)
	policy.Env = map[string]string{
		"HOME":          "/home/elsewhere",
		"TMPDIR":        "/tmp/elsewhere",
		"SSH_AUTH_SOCK": "/run/other/agent.sock",
	}
	args, err := BuildArgs(policy, testSelf(t))
	if err != nil {
		t.Fatalf("BuildArgs: %v", err)
	}
	if argsContain(args, "--setenv", "HOME", "/home/elsewhere") {
		t.Error("a caller overrode HOME")
	}
	if argsContain(args, "--setenv", "TMPDIR", "/tmp/elsewhere") {
		t.Error("a caller overrode TMPDIR")
	}
	if argsContain(args, "--setenv", "SSH_AUTH_SOCK", "/run/other/agent.sock") {
		t.Error("a caller redirected the signing socket")
	}
}
