//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Only this standalone command adopts children. A shared application process
// must not steal wait statuses from other execution paths or exec.Cmd.Wait.
func enableChildReaper() error {
	return unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
}

func readProc(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil || len(raw) > 16384 {
		return nil, fmt.Errorf("child_state_unavailable")
	}
	return raw, nil
}

// drainAdoptedChildren runs after every direct child has completed its own Wait.
// pidfds avoid signaling an unrelated reused PID. Failure is never a successful
// workload exit; accepted whole-container removal remains the final boundary.
func drainAdoptedChildren(budget time.Duration) error {
	deadline := time.Now().Add(budget)
	for {
		empty, err := reapUntilBlocked(deadline, func() (int, error) { var status unix.WaitStatus; return unix.Wait4(-1, &status, unix.WNOHANG, nil) })
		if err != nil {
			return fmt.Errorf("reap: %w", err)
		}
		if empty {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("child_cleanup_unconfirmed")
		}

		if err := signalAdoptedChildren(deadline); err != nil {
			return fmt.Errorf("signal_scan: %w", err)
		}

		time.Sleep(5 * time.Millisecond)
	}
}

func reapUntilBlocked(deadline time.Time, wait func() (int, error)) (bool, error) {
	for {
		// One final nonblocking observation distinguishes an already empty
		// child set from an unconfirmed cleanup after scheduler delay.
		pid, err := wait()
		if errors.Is(err, unix.ECHILD) {
			return true, nil
		}
		if !time.Now().Before(deadline) {
			return false, fmt.Errorf("child_cleanup_unconfirmed")
		}
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return false, err
		}
		if pid == 0 {
			return false, nil
		}
	}
}

func processParent(pid int) (int, error) {
	raw, err := readProc(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return 0, fmt.Errorf("child_state_unavailable")
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 2 {
		return 0, fmt.Errorf("child_state_unavailable")
	}
	return strconv.Atoi(fields[1])
}

func signalAdoptedChildren(deadline time.Time) error {
	directory, err := os.Open("/proc")
	if err != nil {
		return err
	}
	defer directory.Close()
	own, scanned := 0, 0
	for {
		if !time.Now().Before(deadline) {
			return fmt.Errorf("child_cleanup_unconfirmed")
		}
		entries, readErr := directory.ReadDir(128)
		if readErr != nil && readErr != io.EOF {
			return readErr
		}
		for _, entry := range entries {
			if !time.Now().Before(deadline) {
				return fmt.Errorf("child_cleanup_unconfirmed")
			}
			pid, err := strconv.Atoi(entry.Name())
			if err != nil || pid <= 0 {
				continue
			}
			scanned++
			if scanned > 16384 {
				return fmt.Errorf("process_scan_limit_exceeded")
			}
			parent, err := processParent(pid)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return err
			}
			if parent != os.Getpid() {
				continue
			}
			own++
			if own > 1024 {
				return fmt.Errorf("child_limit_exceeded")
			}
			if err := signalOwnedChild(pid, deadline); err != nil {
				return err
			}
		}
		if readErr == io.EOF {
			return nil
		}
	}
}

func signalOwnedChild(pid int, deadline time.Time) (err error) {
	if !time.Now().Before(deadline) {
		return fmt.Errorf("child_cleanup_unconfirmed")
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := unix.Close(fd); closeErr != nil {
			err = closeErr
		}
	}()
	// Recheck after opening the stable handle. A numeric PID replacement cannot
	// turn another process into a signal target.
	if !time.Now().Before(deadline) {
		return fmt.Errorf("child_cleanup_unconfirmed")
	}
	parent, err := processParent(pid)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if parent != os.Getpid() {
		return nil
	}
	if !time.Now().Before(deadline) {
		return fmt.Errorf("child_cleanup_unconfirmed")
	}
	err = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}
