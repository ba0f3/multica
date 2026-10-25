//go:build linux

package sandbox

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func nativeTool(path, fallback string) (string, error) {
	if path == "" {
		path = fallback
	}
	resolved, err := exec.LookPath(path)
	if err != nil {
		return "", fmt.Errorf("native sandbox requires %s: %w", fallback, err)
	}
	return resolved, nil
}

func nativeScopeCommand(run, unit string, argv []string, limits NativeLimits) (*exec.Cmd, error) {
	if !nativeUnitName.MatchString(unit) || len(argv) == 0 || argv[0] == "" {
		return nil, fmt.Errorf("native sandbox: invalid attempt unit or command")
	}
	if limits.MemoryBytes < 0 || limits.PIDsLimit < 0 || limits.NanoCPUs < 0 {
		return nil, fmt.Errorf("native sandbox: resource limits must not be negative")
	}
	args := []string{"--user", "--scope", "--quiet", "--collect", "--no-ask-password", "--expand-environment=no", "--unit=" + unit}
	if limits.MemoryBytes > 0 {
		args = append(args, "--property=MemoryMax="+strconv.FormatInt(limits.MemoryBytes, 10))
	}
	if limits.PIDsLimit > 0 {
		args = append(args, "--property=TasksMax="+strconv.FormatInt(limits.PIDsLimit, 10))
	}
	if limits.NanoCPUs > 0 {
		quota := strconv.FormatFloat(float64(limits.NanoCPUs)/1e7, 'f', -1, 64)
		args = append(args, "--property=CPUQuota="+quota+"%")
	}
	args = append(args, "--")
	args = append(args, argv...)
	cmd := exec.Command(run, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	return cmd, nil
}

func (s *NativeScope) Command(unit string, argv []string) (*exec.Cmd, error) {
	run, err := nativeTool(s.RunPath, "systemd-run")
	if err != nil {
		return nil, err
	}
	return nativeScopeCommand(run, unit, argv, s.Limits)
}

// StartNativeOwnedProcess pins the creating OS thread until the child has been
// reaped. Linux parent-death signals follow that thread, not a Go goroutine.
// Release must run after whole-attempt cleanup and cmd.Wait.
func StartNativeOwnedProcess(cmd *exec.Cmd) (func(), error) {
	started := make(chan error, 1)
	done := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(done) }) }
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		started <- cmd.Start()
		<-done
	}()
	if err := <-started; err != nil {
		release()
		return nil, err
	}
	return release, nil
}

func (s *NativeScope) Preflight(ctx context.Context) (retErr error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, err := nativeTool(s.RunPath, "systemd-run")
	if err != nil {
		return err
	}
	control, err := nativeTool(s.ControlPath, "systemctl")
	if err != nil {
		return err
	}
	bwrap, err := nativeTool(s.BwrapPath, "bwrap")
	if err != nil {
		return err
	}
	root := s.CgroupRoot
	if root == "" {
		root = "/sys/fs/cgroup"
	}
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%v\x00%s\x00%s", run, control, bwrap, root, s.Limits, os.Getenv("XDG_RUNTIME_DIR"), os.Getenv("DBUS_SESSION_BUS_ADDRESS"))
	if s.cached && s.cacheKey == key && nativeWatchesMatch(s.watch) {
		return nil
	}
	probeLimits := s.Limits
	if probeLimits.MemoryBytes == 0 {
		probeLimits.MemoryBytes = 256 << 20
	}
	if probeLimits.PIDsLimit == 0 {
		probeLimits.PIDsLimit = 32
	}
	if probeLimits.NanoCPUs == 0 {
		probeLimits.NanoCPUs = 1e9
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	unit := "multica-preflight-" + hex.EncodeToString(id) + ".scope"
	args := []string{bwrap, "--clearenv", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--die-with-parent", "--new-session", "--cap-drop", "ALL", "--proc", "/proc", "--dev", "/dev"}
	for _, path := range []string{"/usr", "/bin", "/lib", "/lib64"} {
		if _, err := os.Stat(path); err == nil {
			args = append(args, "--ro-bind", path, path)
		}
	}
	args = append(args, "--remount-ro", "/", "--", "/bin/sh", "-c", "printf 'multica-native-preflight-ready\\n'; exec /bin/sleep 30")
	cmd, err := nativeScopeCommand(run, unit, args, probeLimits)
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr := &boundedBuffer{limit: stderrLimit}
	cmd.Stderr = stderr
	release, err := StartNativeOwnedProcess(cmd)
	if err != nil {
		return fmt.Errorf("native sandbox preflight: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		stopErr := s.Stop(cleanupCtx, unit)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = stdout.Close()
		release()
		if retErr == nil && stopErr != nil {
			retErr = stopErr
			s.cached = false
		}
	}()
	ready := make(chan bool, 1)
	go func() {
		line, err := bufio.NewReader(stdout).ReadString('\n')
		ready <- err == nil && line == "multica-native-preflight-ready\n"
	}()
	select {
	case ok := <-ready:
		if !ok {
			return fmt.Errorf("native sandbox preflight did not become ready: %s", stderr.String())
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		return fmt.Errorf("native sandbox preflight timed out: %s", stderr.String())
	}
	query := exec.CommandContext(ctx, control, "--user", "show", "--property=ControlGroup", "--value", unit)
	data, err := query.Output()
	if err != nil {
		return fmt.Errorf("native sandbox cgroup query: %w", err)
	}
	group := strings.TrimSpace(string(data))
	if !filepath.IsAbs(group) || filepath.Clean(group) != group || group == "/" {
		return fmt.Errorf("native sandbox: invalid attempt cgroup %q", group)
	}
	if err := verifyNativeLimits(filepath.Join(root, strings.TrimPrefix(group, "/")), probeLimits); err != nil {
		return err
	}
	var watch []nativeWatch
	for _, path := range []string{run, control, bwrap, root} {
		if err := watchNativePath(&watch, path); err != nil {
			return err
		}
	}
	s.watch, s.cacheKey, s.cached = watch, key, true
	return nil
}

func verifyNativeLimits(group string, limits NativeLimits) error {
	for file, want := range map[string]int64{"memory.max": limits.MemoryBytes, "pids.max": limits.PIDsLimit} {
		data, err := os.ReadFile(filepath.Join(group, file))
		if err != nil {
			return fmt.Errorf("native sandbox: %s controller is unavailable: %w", file, err)
		}
		got, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		if err != nil || got != want {
			return fmt.Errorf("native sandbox: %s did not enforce requested limit %d", file, want)
		}
	}
	data, err := os.ReadFile(filepath.Join(group, "cpu.max"))
	if err != nil {
		return fmt.Errorf("native sandbox: CPU controller is unavailable: %w", err)
	}
	parts := strings.Fields(string(data))
	if len(parts) != 2 {
		return fmt.Errorf("native sandbox: invalid CPU controller result")
	}
	quota, ok := new(big.Int).SetString(parts[0], 10)
	if !ok {
		return fmt.Errorf("native sandbox: CPU quota was not enforced")
	}
	period, ok := new(big.Int).SetString(parts[1], 10)
	if !ok || period.Sign() <= 0 {
		return fmt.Errorf("native sandbox: invalid CPU quota period")
	}
	want := new(big.Int).Mul(period, big.NewInt(limits.NanoCPUs))
	got := new(big.Int).Mul(quota, big.NewInt(1e9))
	if got.Cmp(want) != 0 {
		return fmt.Errorf("native sandbox: CPU quota did not enforce requested limit")
	}
	return nil
}

func (s *NativeScope) Stop(ctx context.Context, unit string) error {
	if !nativeUnitName.MatchString(unit) {
		return fmt.Errorf("native sandbox: invalid attempt unit")
	}
	control, err := nativeTool(s.ControlPath, "systemctl")
	if err != nil {
		return err
	}
	absent := func() (bool, error) {
		state, err := exec.CommandContext(ctx, control, "--user", "show", "--property=LoadState", "--value", unit).Output()
		if err != nil {
			return false, fmt.Errorf("native sandbox: query attempt before cleanup: %w", err)
		}
		return strings.TrimSpace(string(state)) == "not-found", nil
	}
	if gone, err := absent(); err != nil || gone {
		return err
	}
	// Kill first: a task may ignore TERM, detach, or outlive its namespace leader.
	for _, args := range [][]string{
		{"--user", "kill", "--kill-whom=all", "--signal=KILL", unit},
		{"--user", "stop", unit},
	} {
		if output, err := exec.CommandContext(ctx, control, args...).CombinedOutput(); err != nil {
			if gone, queryErr := absent(); queryErr == nil && gone {
				return nil
			}
			return fmt.Errorf("native sandbox: stop attempt: %w: %.1024s", err, output)
		}
	}
	return nil
}
