//go:build linux

package r2dgit

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func quarantineCommand(ctx context.Context, git string, args ...string) (*exec.Cmd, error) {
	const limiter = "/usr/bin/prlimit"
	if info, err := os.Stat(limiter); err != nil || !info.Mode().IsRegular() {
		return nil, ErrRuntime
	}
	// RLIMIT_NPROC counts every thread for the host UID. Per-run process
	// counts require the S4 cgroup/UID boundary; a host-wide limit is unsafe.
	limits := []string{"--as=536870912", "--cpu=3", "--fsize=33554432", "--nofile=64", "--core=0", "--", git}
	cmd := exec.CommandContext(ctx, limiter, append(limits, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = 500 * time.Millisecond
	return cmd, nil
}
