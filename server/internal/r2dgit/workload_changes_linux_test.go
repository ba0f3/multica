//go:build linux

package r2dgit

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtectedChangesProduceValidatedCommit(t *testing.T) {
	repo := localRepository(t)
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	base, old := fullPack(t, repo)
	newHead, pack, err := applyProtectedChanges(context.Background(), git, repo, old, []ProtectedFileChange{{Path: "new/file.txt", Content: "synthetic change"}})
	if err != nil || newHead == old {
		t.Fatal(err)
	}
	q := GitQuarantine{GitExecutable: git, Root: t.TempDir()}
	validated, err := q.Prepare(context.Background(), base, pack, RefUpdate{Old: old, New: newHead, Ref: "refs/heads/task/a"})
	if err != nil || !packFraming(validated) {
		t.Fatalf("entrypoint generated invalid change: %v", err)
	}
}

func TestProtectedChangesRejectEscapesAndSymlinks(t *testing.T) {
	for _, name := range []string{"../escape", ".git/config", "a/.git/config", "/tmp/escape", "a/../escape", "a\\escape", "link"} {
		t.Run(strings.ReplaceAll(name, "/", "_"), func(t *testing.T) {
			repo := t.TempDir()
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(repo, "link")); err != nil {
				t.Fatal(err)
			}
			if _, _, err := applyProtectedChanges(context.Background(), "/usr/bin/git", repo, strings.Repeat("a", 40), []ProtectedFileChange{{Path: name, Content: "forged"}}); err == nil {
				t.Fatal("unsafe change accepted")
			}
			if got, err := os.ReadFile(outside); err != nil || string(got) != "unchanged" {
				t.Fatal("change escaped private root")
			}
		})
	}
}
