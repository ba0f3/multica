//go:build linux

package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func newFakeNativeScope(t *testing.T) *NativeScope {
	t.Helper()
	root := t.TempDir()
	write := func(name, text string) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	t.Setenv("NATIVE_SCOPE_RECORD", filepath.Join(root, "properties"))
	t.Setenv("NATIVE_SCOPE_PID", filepath.Join(root, "pid"))
	t.Setenv("NATIVE_SCOPE_STARTS", filepath.Join(root, "starts"))
	runner := write("systemd-run", `#!/bin/sh
set -eu
printf x >> "$NATIVE_SCOPE_STARTS"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --property=*) printf '%s\n' "${1#--property=}" >> "$NATIVE_SCOPE_RECORD" ;;
    --) shift; break ;;
  esac
  shift
done
printf '%s' "$$" > "$NATIVE_SCOPE_PID"
exec "$@"
`)
	control := write("systemctl", `#!/bin/sh
set -eu
case "$*" in
  *ControlGroup*) printf '/fixture\n' ;;
  *LoadState*) if [ -f "$NATIVE_SCOPE_PID" ]; then printf 'loaded\n'; else printf 'not-found\n'; fi ;;
  *kill*|*stop*)
    if [ -f "$NATIVE_SCOPE_PID" ]; then kill "$(cat "$NATIVE_SCOPE_PID")" 2>/dev/null || true; rm -f "$NATIVE_SCOPE_PID"; fi ;;
  *) exit 9 ;;
esac
`)
	bwrap := write("bwrap", `#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
  if [ "$1" = -- ]; then shift; exec "$@"; fi
  shift
done
exit 12
`)
	cgroups := filepath.Join(root, "cgroups")
	for name, value := range map[string]string{"memory.max": "33554432", "pids.max": "23", "cpu.max": "50000 100000"} {
		write(filepath.Join("cgroups", "fixture", name), value)
	}
	return &NativeScope{RunPath: runner, ControlPath: control, BwrapPath: bwrap, CgroupRoot: cgroups, Limits: NativeLimits{MemoryBytes: 33554432, PIDsLimit: 23, NanoCPUs: 500000000}}
}

func TestNativeScopePassesConfiguredLimitsToTheWorkerBoundary(t *testing.T) {
	scope := newFakeNativeScope(t)
	cmd, err := scope.Command("multica-attempt-abc.scope", []string{"/bin/sh", "-c", "printf artifact"})
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.Output()
	if err != nil || string(output) != "artifact" {
		t.Fatalf("worker: %q, %v", output, err)
	}
	properties, err := os.ReadFile(os.Getenv("NATIVE_SCOPE_RECORD"))
	if err != nil {
		t.Fatal(err)
	}
	for _, property := range []string{"MemoryMax=33554432", "TasksMax=23", "CPUQuota=50%"} {
		if !strings.Contains(string(properties), property+"\n") {
			t.Fatalf("missing effective resource request %s: %s", property, properties)
		}
	}
}

func TestNativeScopePreflightChecksEffectiveLimitsAndCaches(t *testing.T) {
	scope := newFakeNativeScope(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := scope.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	if err := scope.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	starts, err := os.ReadFile(os.Getenv("NATIVE_SCOPE_STARTS"))
	if err != nil || string(starts) != "x" {
		t.Fatalf("warm launch repeated preflight: %q, %v", starts, err)
	}
}

func TestNativeScopePreflightRejectsMissingOrIgnoredControllers(t *testing.T) {
	for _, controller := range []string{"memory.max", "pids.max", "cpu.max"} {
		t.Run(controller, func(t *testing.T) {
			scope := newFakeNativeScope(t)
			if err := os.Remove(filepath.Join(scope.CgroupRoot, "fixture", controller)); err != nil {
				t.Fatal(err)
			}
			if err := scope.Preflight(t.Context()); err == nil {
				t.Fatalf("unavailable %s did not block execution", controller)
			}
		})
	}
	t.Run("ignored CPU quota", func(t *testing.T) {
		scope := newFakeNativeScope(t)
		if err := os.WriteFile(filepath.Join(scope.CgroupRoot, "fixture", "cpu.max"), []byte("max 100000"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := scope.Preflight(t.Context()); err == nil {
			t.Fatal("requested quota was ignored without blocking execution")
		}
	})
}

func TestNativeScopePreflightRejectsNamespaceFailure(t *testing.T) {
	scope := newFakeNativeScope(t)
	if err := os.WriteFile(scope.BwrapPath, []byte("#!/bin/sh\necho namespace-denied >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := scope.Preflight(t.Context()); err == nil {
		t.Fatal("failed namespace setup was reported as ready")
	}
}

func TestNativeScopeRejectsMalformedAttemptUnits(t *testing.T) {
	scope := newFakeNativeScope(t)
	for _, unit := range []string{"", "other.service", "multica-../other.scope", "multica-task.scope --user"} {
		if _, err := scope.Command(unit, []string{"/bin/true"}); err == nil {
			t.Fatalf("unsafe unit accepted: %q", unit)
		}
	}
}

func TestNativeScopeStopIsIdempotent(t *testing.T) {
	scope := newFakeNativeScope(t)
	for range 2 {
		if err := scope.Stop(t.Context(), "multica-attempt-absent.scope"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNativeScopeStopKillsWholeGroupBeforeCollecting(t *testing.T) {
	scope := newFakeNativeScope(t)
	script := `#!/bin/sh
case "$*" in
 *LoadState*) echo loaded ;;
 *kill*) printf '%s\n' "$*" >> "$NATIVE_SCOPE_RECORD" ;;
 *stop*) printf '%s\n' "$*" >> "$NATIVE_SCOPE_RECORD" ;;
esac
`
	if err := os.WriteFile(scope.ControlPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if err := scope.Stop(t.Context(), "multica-cleanup.scope"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(os.Getenv("NATIVE_SCOPE_RECORD"))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "--signal=KILL") || !strings.Contains(lines[0], "--kill-whom=all") || !strings.Contains(lines[1], "stop") {
		t.Fatalf("cleanup must kill every descendant before collecting: %s", data)
	}
}

func nativeScopeProbeArgs(t *testing.T, directory, action string) []string {
	t.Helper()
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Fatal(err)
	}
	args := []string{bwrap, "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--proc", "/proc", "--dev", "/dev"}
	for _, path := range []string{"/usr", "/bin", "/lib", "/lib64"} {
		if _, err := os.Stat(path); err == nil {
			args = append(args, "--ro-bind", path, path)
		}
	}
	args = append(args, "--bind", directory, "/probe", "--", "/bin/sh", "-c", `setsid /bin/sh -c 'while :; do printf x >> /probe/heartbeat; sleep 0.02; done' &
while [ ! -s /probe/heartbeat ]; do sleep 0.01; done
printf ready > /probe/ready
`+action)
	return args
}

func waitNativeProbeFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("probe did not become ready: %s", path)
}

func assertNativeHeartbeatStopped(t *testing.T, directory string) {
	t.Helper()
	path := filepath.Join(directory, "heartbeat")
	// Allow the kernel and user manager to reap the namespace before observing it.
	time.Sleep(100 * time.Millisecond)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Size() != after.Size() {
		t.Fatal("detached descendant survived the attempt")
	}
}

func TestNativeScopeRealResourcesAndLifecycle(t *testing.T) {
	if os.Getenv("MULTICA_BWRAP_SMOKE") != "1" {
		t.Skip("set MULTICA_BWRAP_SMOKE=1 for real kernel probes")
	}
	scope := &NativeScope{Limits: NativeLimits{MemoryBytes: 256 << 20, PIDsLimit: 32, NanoCPUs: 500000000}}
	if err := scope.Preflight(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"normal", "crash", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			action := "exit 0"
			if scenario == "crash" {
				action = "kill -KILL $$"
			}
			if scenario == "cancel" {
				action = "while :; do sleep 1; done"
			}
			unit := fmt.Sprintf("multica-test-%d-%s.scope", os.Getpid(), scenario)
			cmd, err := scope.Command(unit, nativeScopeProbeArgs(t, dir, action))
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stderr = os.Stderr
			release, err := StartNativeOwnedProcess(cmd)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			defer scope.Stop(context.Background(), unit)
			waitNativeProbeFile(t, filepath.Join(dir, "ready"))
			if scenario == "cancel" {
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()
				if err := scope.Stop(ctx, unit); err != nil {
					t.Fatal(err)
				}
			}
			waitErr := cmd.Wait()
			if scenario == "crash" && (waitErr == nil || cmd.ProcessState.ExitCode() != 137) {
				t.Fatalf("expected SIGKILL exit 137, got %v: %v", cmd.ProcessState, waitErr)
			}
			if err := scope.Stop(t.Context(), unit); err != nil {
				t.Fatal(err)
			}
			assertNativeHeartbeatStopped(t, dir)
		})
	}
}

func TestNativeScopeDaemonDeathHelper(t *testing.T) {
	if os.Getenv("MULTICA_NATIVE_DAEMON_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	scope := &NativeScope{}
	cmd, err := scope.Command(os.Getenv("NATIVE_PROBE_UNIT"), nativeScopeProbeArgs(t, os.Getenv("NATIVE_PROBE_DIR"), "while :; do sleep 1; done"))
	if err != nil {
		t.Fatal(err)
	}
	release, err := StartNativeOwnedProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	_ = cmd.Wait()
}

func TestNativeScopeRealDaemonDeathKillsDetachedDescendants(t *testing.T) {
	if os.Getenv("MULTICA_BWRAP_SMOKE") != "1" {
		t.Skip("set MULTICA_BWRAP_SMOKE=1 for real kernel probes")
	}
	dir := t.TempDir()
	unit := "multica-death-" + strconv.Itoa(os.Getpid()) + ".scope"
	helper := exec.Command(os.Args[0], "-test.run=^TestNativeScopeDaemonDeathHelper$")
	helper.Env = append(os.Environ(), "MULTICA_NATIVE_DAEMON_HELPER=1", "NATIVE_PROBE_UNIT="+unit, "NATIVE_PROBE_DIR="+dir)
	helper.Stderr = os.Stderr
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	defer (&NativeScope{}).Stop(context.Background(), unit)
	defer helper.Process.Kill()
	waitNativeProbeFile(t, filepath.Join(dir, "ready"))
	if err := helper.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = helper.Wait()
	assertNativeHeartbeatStopped(t, dir)
}

func TestNativeScopePreflightInvalidatesChangedToolAndLimits(t *testing.T) {
	scope := newFakeNativeScope(t)
	if err := scope.Preflight(t.Context()); err != nil {
		t.Fatal(err)
	}
	scope.Limits.MemoryBytes++
	if err := scope.Preflight(t.Context()); err == nil {
		t.Fatal("changed limit reused old preflight")
	}
	scope.Limits.MemoryBytes--
	if err := os.WriteFile(scope.BwrapPath, []byte("#!/bin/sh\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := scope.Preflight(t.Context()); err == nil {
		t.Fatal("changed executable reused old preflight")
	}
}
