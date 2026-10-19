//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func init() {
	if os.Getenv("MULTICA_TEST_REAPER") != "1" {
		return
	}
	os.Exit(runReaperFixture())
}

type reaperFixtureChild struct {
	PID, Parent int
	State       string
}

func runReaperFixture() int {
	if err := enableChildReaper(); err != nil {
		fmt.Fprintln(os.Stdout, "enable", err)
		return 2
	}
	// Redirect the background child's descriptors so Output waits only for the
	// original parent. The child's PID is observed before cleanup begins.
	cmd := exec.Command("/bin/sh", "-c", "/bin/sleep 30 </dev/null >/dev/null 2>&1 & printf '%s\\n' \"$!\"")
	out, err := cmd.Output()
	if err != nil {
		fmt.Fprintln(os.Stdout, "child", err)
		return 3
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || pid <= 0 {
		fmt.Fprintln(os.Stdout, "invalid child PID", err)
		return 3
	}
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		fmt.Fprintln(os.Stdout, "child handle", err)
		return 3
	}
	defer unix.Close(fd)
	defer func() {
		// Failure cleanup never changes the result of the measured one-second
		// drain. Signal only the already opened stable child handle, then reap.
		_ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
		until := time.Now().Add(time.Second)
		for time.Now().Before(until) {
			var status unix.WaitStatus
			got, e := unix.Wait4(pid, &status, unix.WNOHANG, nil)
			if got == pid || errors.Is(e, unix.ECHILD) {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	parent, state, err := reaperFixtureState(pid)
	if err != nil || parent != os.Getpid() || state == "Z" || state == "X" || unix.PidfdSendSignal(fd, 0, nil, 0) != nil {
		fmt.Fprintf(os.Stdout, "adoption not observed: pid=%d parent=%d state=%s err=%v\n", pid, parent, state, err)
		return 3
	}
	ready := os.NewFile(3, "reaper-fixture-ready")
	if ready == nil {
		return 3
	}
	if err := json.NewEncoder(ready).Encode(reaperFixtureChild{pid, parent, state}); err != nil {
		ready.Close()
		return 3
	}
	ready.Close()
	if start, err := bufio.NewReader(io.LimitReader(os.Stdin, 8)).ReadString('\n'); err != nil || start != "go\n" {
		fmt.Fprintln(os.Stdout, "missing parent observation", err)
		return 3
	}
	started := time.Now()
	if err := drainAdoptedChildren(time.Second); err != nil {
		fmt.Fprintf(os.Stdout, "drain error=%v elapsed=%s diagnostics=%s\n", err, time.Since(started), reaperFixtureDiagnostics(pid))
		return 4
	}
	var status unix.WaitStatus
	if got, err := unix.Wait4(-1, &status, unix.WNOHANG, nil); !errors.Is(err, unix.ECHILD) {
		fmt.Fprintf(os.Stdout, "missing final ECHILD: pid=%d err=%v\n", got, err)
		return 4
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); !os.IsNotExist(err) {
		fmt.Fprintln(os.Stdout, "adopted PID remains", err)
		return 4
	}
	fmt.Fprintf(os.Stdout, "drain complete elapsed=%s adopted_pid=%d final=ECHILD pid_absent=true\n", time.Since(started), pid)
	return 0
}

func reaperFixtureState(pid int) (int, string, error) {
	raw, err := readProc(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, "", err
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return 0, "", fmt.Errorf("invalid process state")
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 2 {
		return 0, "", fmt.Errorf("missing process state")
	}
	parent, err := strconv.Atoi(fields[1])
	return parent, fields[0], err
}

func reaperFixtureDiagnostics(child int) string {
	// These observations occur AFTER a failed drain. They cannot establish what
	// happened inside a previous scan, and have a separate bounded budget.
	deadline := time.Now().Add(100 * time.Millisecond)
	parent, state, childErr := reaperFixtureState(child)
	scanned, owned, complete := 0, 0, false
	directory, err := os.Open("/proc")
	if err == nil {
		defer directory.Close()
		for time.Now().Before(deadline) && scanned < 16384 {
			entries, readErr := directory.ReadDir(128)
			processed := 0
			for _, entry := range entries {
				if !time.Now().Before(deadline) || scanned >= 16384 {
					break
				}
				processed++
				pid, parseErr := strconv.Atoi(entry.Name())
				if parseErr != nil || pid <= 0 {
					continue
				}
				scanned++
				if p, _, e := reaperFixtureState(pid); e == nil && p == os.Getpid() {
					owned++
				}
			}
			if readErr != nil {
				complete = errors.Is(readErr, io.EOF) && processed == len(entries)
				err = readErr
				break
			}
		}
	}
	return fmt.Sprintf("child=%d ppid=%d state=%q child_err=%v post_failure_scanned=%d post_failure_owned=%d scan_complete=%v scan_err=%v", child, parent, state, childErr, scanned, owned, complete, err)
}

func TestStandaloneReaperAdoptsChild(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable)
	cmd.Env = []string{"MULTICA_TEST_REAPER=1"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	ready, childReady, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer ready.Close()
	defer childReady.Close()
	cmd.ExtraFiles = []*os.File{childReady}
	start, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	childReady.Close()
	helperFD, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		start.Close()
		_ = cmd.Wait()
		t.Fatal(err)
	}
	defer unix.Close(helperFD)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	childFD := -1
	waited := false
	defer func() {
		start.Close()
		if childFD >= 0 {
			_ = unix.PidfdSendSignal(childFD, unix.SIGKILL, nil, 0)
			unix.Close(childFD)
		}
		if !waited {
			select {
			case <-done:
				waited = true
			case <-time.After(2 * time.Second):
				_ = unix.PidfdSendSignal(helperFD, unix.SIGKILL, nil, 0)
				select {
				case <-done:
					waited = true
				case <-time.After(2 * time.Second):
					t.Error("fixture helper cleanup could not be confirmed")
				}
			}
		}
		if waited && t.Failed() {
			t.Logf("helper diagnostics: %s", output.Bytes())
		}
	}()
	if err := ready.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var child reaperFixtureChild
	if err := json.NewDecoder(io.LimitReader(ready, 1024)).Decode(&child); err != nil {
		t.Fatal("child handshake", err)
	}
	parent, state, err := reaperFixtureState(child.PID)
	if err != nil || child.Parent != cmd.Process.Pid || parent != cmd.Process.Pid || state == "Z" || state == "X" {
		t.Fatalf("live adoption not independently observed: child=%+v parent=%d state=%s err=%v", child, parent, state, err)
	}
	childFD, err = unix.PidfdOpen(child.PID, 0)
	if err != nil || unix.PidfdSendSignal(childFD, 0, nil, 0) != nil {
		t.Fatal("live child handle", err)
	}
	if _, err := io.WriteString(start, "go\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		waited = true
		if err != nil {
			t.Fatalf("standalone reaper: %v %s", err, output.Bytes())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("standalone reaper process exceeded outer fixture bound")
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", child.PID)); !os.IsNotExist(err) {
		t.Fatal("adopted PID did not disappear", child.PID, err)
	}
	t.Logf("helper evidence: %s", output.Bytes())
}

func TestReaperDeadlineBoundsContinuousWaitStatuses(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		t.Run(map[bool]string{false: "continuous_exits", true: "continuous_interrupts"}[interrupted], func(t *testing.T) {
			calls := 0
			started := time.Now()
			empty, err := reapUntilBlocked(started.Add(10*time.Millisecond), func() (int, error) {
				calls++
				if interrupted {
					return 0, unix.EINTR
				}
				return calls, nil
			})
			if err == nil || empty || calls < 2 {
				t.Fatalf("unbounded wait sequence admitted: calls=%d empty=%v err=%v", calls, empty, err)
			}
			if time.Since(started) > 500*time.Millisecond {
				t.Fatal("cleanup inner drain exceeded its deadline")
			}
		})
	}
}

func TestReaperExpiredDeadlineRequiresFinalEmptyObservation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pid     int
		waitErr error
		empty   bool
	}{
		{"empty", 0, unix.ECHILD, true}, {"live", 0, nil, false}, {"exit", 4, nil, false}, {"interrupted", 0, unix.EINTR, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			empty, err := reapUntilBlocked(time.Now().Add(-time.Second), func() (int, error) { calls++; return tc.pid, tc.waitErr })
			if calls != 1 || empty != tc.empty || (err == nil) != tc.empty {
				t.Fatalf("calls=%d empty=%v err=%v", calls, empty, err)
			}
		})
	}
}
