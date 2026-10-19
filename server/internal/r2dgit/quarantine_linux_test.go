//go:build linux

package r2dgit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGitQuarantineHardWallDeadline(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "synthetic-git")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexec /bin/sleep 60\n"), 0700); err != nil {
		t.Fatal(err)
	}
	repo := localRepository(t)
	pack := fixtureGit(t, repo, "pack-objects", "--all", "--stdout")
	start := time.Now()
	err := (GitQuarantine{GitExecutable: fake, Root: dir}).Validate(context.Background(), pack, strings.Repeat("a", 40))
	if err == nil || time.Since(start) < 4*time.Second || time.Since(start) > 7*time.Second {
		t.Fatalf("quarantine wall bound: %v, %v", time.Since(start), err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "synthetic-git" {
		t.Fatal("quarantine directory survived timeout")
	}
}

func TestGitQuarantineDoesNotBorrowCallerThreadBudget(t *testing.T) {
	repo := localRepository(t)
	pack := fixtureGit(t, repo, "pack-objects", "--all", "--stdout")
	head := strings.TrimSpace(string(fixtureGit(t, repo, "rev-parse", "HEAD")))
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	validator := GitQuarantine{GitExecutable: git, Root: t.TempDir()}
	if err := validator.Validate(context.Background(), pack, head); err != nil {
		t.Fatalf("valid synthetic pack failed pre-load control: %v", err)
	}
	// RLIMIT_NPROC counts the caller UID's threads, including unrelated Go work.
	// A pack worker must retain its own CPU/memory/deadline limits without making
	// valid input fail merely because other packages have more than64 threads.
	release := make(chan struct{})
	ready := make(chan struct{}, 80)
	var workers sync.WaitGroup
	defer func() { close(release); workers.Wait() }()
	for range 80 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			ready <- struct{}{}
			<-release
		}()
	}
	for range 80 {
		<-ready
	}
	if err := validator.Validate(context.Background(), pack, head); err != nil {
		t.Fatalf("valid synthetic pack failed under caller thread load: %v", err)
	}
}
