package repocache

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCacheRejectsEscapingOwnership(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repos")
	cache := New(root, testLogger())
	if err := cache.SyncContext(context.Background(), Scope{WorkspaceID: "../foreign", UserID: "test-user"}, nil); err == nil {
		t.Fatal("cache accepted an owner path outside its root")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "foreign")); !os.IsNotExist(err) {
		t.Fatalf("invalid owner created a cache directory: %v", err)
	}
}

func TestUserStoresKeepIndependentRefsAndDependents(t *testing.T) {
	remote := createTestRepo(t)
	root := t.TempDir()
	cache := New(root, testLogger())
	a := Scope{WorkspaceID: "workspace", UserID: "alice"}
	b := Scope{WorkspaceID: "workspace", UserID: "bob"}
	first, err := cache.Prepare(context.Background(), a, []RepoInfo{{URL: remote}})
	if err != nil {
		t.Fatal(err)
	}
	addEmptyCommit(t, remote, "bob snapshot")
	second, err := cache.Prepare(context.Background(), b, []RepoInfo{{URL: remote}})
	if err != nil {
		t.Fatal(err)
	}
	if first[0].BarePath == second[0].BarePath || first[0].CommitSHA == second[0].CommitSHA {
		t.Fatal("users share a store or stale snapshot")
	}
	if got := gitHead(t, first[0].BarePath); got != first[0].CommitSHA {
		t.Fatal("another user's fetch changed Alice's base")
	}
	if cache.lockForRepo(first[0].BarePath) == cache.lockForRepo(second[0].BarePath) {
		t.Fatal("different users share a mutation lock")
	}
	for _, entry := range []struct {
		scope Scope
		path  string
	}{{a, first[0].BarePath}, {b, second[0].BarePath}} {
		if err := cache.RecordDependents(entry.scope, Dependent{WorkDir: t.TempDir(), CachePaths: []string{entry.path}}); err != nil {
			t.Fatal(err)
		}
	}
	live, err := cache.LiveDependentCachePaths()
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 2 {
		t.Fatalf("retained stores=%v", live)
	}
	again, err := cache.Prepare(context.Background(), a, []RepoInfo{{URL: remote}})
	if err != nil {
		t.Fatal(err)
	}
	if again[0].BarePath != first[0].BarePath || again[0].CommitSHA != second[0].CommitSHA {
		t.Fatal("same user did not reuse and refresh its store")
	}
}

func TestDependentsCannotNameAnotherUserStore(t *testing.T) {
	root := t.TempDir()
	cache := New(root, testLogger())
	err := cache.RecordDependents(Scope{WorkspaceID: "workspace", UserID: "alice"}, Dependent{WorkDir: t.TempDir(), CachePaths: []string{filepath.Join(root, "workspace", "bob", "repo.git")}})
	if err == nil {
		t.Fatal("Alice registered Bob's cache as her own")
	}
}

func TestUserStoreCannotAliasAnotherUser(t *testing.T) {
	root := t.TempDir()
	cache := New(root, testLogger())
	bob := filepath.Join(root, "workspace", "bob")
	if err := os.MkdirAll(bob, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bob, filepath.Join(root, "workspace", "alice")); err != nil {
		t.Skip(err)
	}
	if err := cache.Sync(Scope{WorkspaceID: "workspace", UserID: "alice"}, nil); err == nil {
		t.Fatal("accepted symlinked owner store")
	}
}

func TestRepositoryEntryCannotAliasAnotherUser(t *testing.T) {
	remote := createTestRepo(t)
	cache := New(t.TempDir(), testLogger())
	bob := Scope{WorkspaceID: "workspace", UserID: "bob"}
	prepared, err := cache.Prepare(context.Background(), bob, []RepoInfo{{URL: remote}})
	if err != nil {
		t.Fatal(err)
	}
	alice := Scope{WorkspaceID: "workspace", UserID: "alice"}
	alias := cache.BarePath(alice, remote)
	if err := os.MkdirAll(filepath.Dir(alias), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(prepared[0].BarePath, alias); err != nil {
		t.Skip(err)
	}
	if _, err := cache.Prepare(context.Background(), alice, []RepoInfo{{URL: remote}}); err == nil {
		t.Fatal("Alice's repository alias fetched into Bob's store")
	}
}

func TestPrivateCheckoutCannotModifyBaseObjects(t *testing.T) {
	remote := createTestRepo(t)
	cache := New(t.TempDir(), testLogger())
	scope := Scope{WorkspaceID: "workspace", UserID: "alice"}
	if err := cache.Sync(scope, []RepoInfo{{URL: remote}}); err != nil {
		t.Fatal(err)
	}
	result, err := cache.CreateWorktree(WorktreeParams{Scope: scope, RepoURL: remote, WorkDir: t.TempDir(), TaskID: "task", AgentName: "agent", IsolatedGitMetadata: true})
	if err != nil {
		t.Fatal(err)
	}
	sha := gitHead(t, remote)
	relative := filepath.Join("objects", sha[:2], sha[2:])
	baseFile := filepath.Join(cache.BarePath(scope, remote), relative)
	checkoutFile := filepath.Join(result.Path, ".git", relative)
	original, err := os.ReadFile(baseFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(checkoutFile, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checkoutFile, []byte("task-local corruption"), 0600); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(baseFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatal("writing a private checkout object corrupted its base")
	}
}

func TestHostCheckoutFailsClosedAfterAccessLoss(t *testing.T) {
	remote := createTestRepo(t)
	cache := New(t.TempDir(), testLogger())
	scope := Scope{WorkspaceID: "workspace", UserID: "alice"}
	if err := cache.Sync(scope, []RepoInfo{{URL: remote}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(remote, remote+"-unavailable"); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	result, err := cache.CreateWorktree(WorktreeParams{Scope: scope, RepoURL: remote, WorkDir: work, TaskID: "task", AgentName: "agent", IsolatedGitMetadata: true})
	if err == nil || result != nil {
		t.Fatalf("checkout succeeded with stale code after fetch failed: %+v %v", result, err)
	}
	entries, err := os.ReadDir(work)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed fetch changed the checkout: %v %v", entries, err)
	}
}
