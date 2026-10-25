//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNativeProfileLeaseSerializesAndCancels(t *testing.T) {
	root := t.TempDir()
	key := strings.Repeat("a", 64)
	first, err := AcquireNativeProfileLease(t.Context(), root, key)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	if lease, err := AcquireNativeProfileLease(ctx, root, key); !errors.Is(err, context.DeadlineExceeded) {
		if lease != nil {
			lease.Close()
		}
		t.Fatalf("same profile was not serialized: %v", err)
	}
	other, err := AcquireNativeProfileLease(t.Context(), root, strings.Repeat("b", 64))
	if err != nil {
		t.Fatalf("unrelated profile was blocked: %v", err)
	}
	other.Close()
	first.Close()
	first.Close()
	next, err := AcquireNativeProfileLease(t.Context(), root, key)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}

func TestNativeProfileLeaseRejectsTraversalAndSymlinks(t *testing.T) {
	root := t.TempDir()
	if _, err := AcquireNativeProfileLease(t.Context(), root, "../outside"); err == nil {
		t.Fatal("profile key escaped the lease directory")
	}
	key := strings.Repeat("a", 64)
	outside := filepath.Join(t.TempDir(), "unchanged")
	if err := os.WriteFile(outside, []byte("sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, key+".lock")); err != nil {
		t.Fatal(err)
	}
	if lease, err := AcquireNativeProfileLease(t.Context(), root, key); err == nil {
		lease.Close()
		t.Fatal("lease followed a symlink")
	}
	data, _ := os.ReadFile(outside)
	if string(data) != "sentinel" {
		t.Fatal("lease modified an unrelated file")
	}
}

func TestNativeProfileLeaseOwnerHelper(t *testing.T) {
	if os.Getenv("MULTICA_NATIVE_LEASE_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	lease, err := AcquireNativeProfileLease(context.Background(), os.Getenv("MULTICA_NATIVE_LEASE_ROOT"), strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := os.WriteFile(filepath.Join(os.Getenv("MULTICA_NATIVE_LEASE_ROOT"), "ready"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestNativeProfileLeaseIsReleasedOnOwnerExit(t *testing.T) {
	root := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestNativeProfileLeaseOwnerHelper$")
	cmd.Env = append(os.Environ(), "MULTICA_NATIVE_LEASE_HELPER=1", "MULTICA_NATIVE_LEASE_ROOT="+root)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lease owner never became ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cmd.Process.Kill()
	_ = cmd.Wait()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	lease, err := AcquireNativeProfileLease(ctx, root, strings.Repeat("c", 64))
	if err != nil {
		t.Fatalf("dead owner stranded a profile lease: %v", err)
	}
	lease.Close()
}
