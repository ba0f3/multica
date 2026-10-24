package workercheckout

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/multica-ai/multica/server/internal/daemon/repocache"
)

const (
	testAgentName = "Test Agent"
	testTaskID    = "01a01ec0-e69d-7000-8000-000000000001"
)

// git runs git in dir (or the process cwd when dir is empty) with the test
// author identity set, returning trimmed combined output and any error.
func git(tb testing.TB, dir string, args ...string) (string, error) {
	tb.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com",
	)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// mustGit runs git and fails the test on error.
func mustGit(tb testing.TB, dir string, args ...string) string {
	tb.Helper()
	out, err := git(tb, dir, args...)
	if err != nil {
		tb.Fatalf("git %v (dir=%s): %s: %v", args, dir, out, err)
	}
	return out
}

// testRemote creates a local repository with a single commit and returns its
// path. Its filesystem path is used directly as the git remote URL.
func testRemote(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustGit(t, "", "init", "-q", dir)
	mustGit(t, dir, "commit", "--allow-empty", "-q", "-m", "initial")
	return dir
}

// addCommit adds an empty commit to the current branch of repoPath.
func addCommit(t *testing.T, repoPath, message string) {
	t.Helper()
	mustGit(t, repoPath, "commit", "--allow-empty", "-q", "-m", message)
}

// testCache prepares a bare cache from a remote through the daemon's repocache
// package, so the cache has the exact modern remote-tracking layout the worker
// will actually see.
type testCache struct {
	remote string
	cache  *repocache.Cache
	ws     string
}

func newTestCache(t *testing.T, remote string) *testCache {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &testCache{remote: remote, cache: repocache.New(t.TempDir(), logger), ws: "ws-1"}
}

// prepare clones or fetches the remote into the cache and resolves its commit.
func (tc *testCache) prepare(t *testing.T) repocache.PreparedRepo {
	t.Helper()
	prepared, err := tc.cache.Prepare(context.Background(), tc.ws, []repocache.RepoInfo{{URL: tc.remote}})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return prepared[0]
}

// entry returns a manifest Entry backed by the prepared cache.
func (tc *testCache) entry(t *testing.T) Entry {
	p := tc.prepare(t)
	return Entry{URL: tc.remote, Ref: p.Ref, CommitSHA: p.CommitSHA, CachePath: p.BarePath}
}

func TestCheckoutInitializesFromCacheWithoutNetwork(t *testing.T) {
	remote := testRemote(t)
	tc := newTestCache(t, remote)
	p := tc.prepare(t)

	// entry.URL points at a nonexistent remote, but the cache holds the objects.
	entry := Entry{
		URL:       filepath.Join(t.TempDir(), "does-not-exist.git"),
		CommitSHA: p.CommitSHA,
		CachePath: p.BarePath,
	}

	workDir := t.TempDir()
	result, err := Checkout(context.Background(), workDir, entry, Options{AgentName: testAgentName, TaskID: testTaskID})
	if err != nil {
		t.Fatalf("Checkout: %v", err)
	}

	if want := filepath.Join(workDir, repocache.RepoDirName(entry.URL)); result.Path != want {
		t.Errorf("Path = %q, want %q", result.Path, want)
	}

	alternates, err := os.ReadFile(filepath.Join(result.Path, ".git", "objects", "info", "alternates"))
	if err != nil {
		t.Fatalf("read alternates: %v", err)
	}
	if want := filepath.Join(entry.CachePath, "objects"); strings.TrimSpace(string(alternates)) != want {
		t.Errorf("alternates = %q, want %q", strings.TrimSpace(string(alternates)), want)
	}

	if got := mustGit(t, result.Path, "remote", "get-url", "origin"); got != entry.URL {
		t.Errorf("origin = %q, want %q", got, entry.URL)
	}

	if got := mustGit(t, result.Path, "rev-parse", "HEAD"); got != entry.CommitSHA {
		t.Errorf("HEAD = %q, want %q", got, entry.CommitSHA)
	}

	if want := repocache.BranchName(testAgentName, testTaskID); result.Branch != want {
		t.Errorf("Branch = %q, want %q", result.Branch, want)
	}
}

func TestCheckoutDoesNotHardlink(t *testing.T) {
	remote := testRemote(t)
	tc := newTestCache(t, remote)
	entry := tc.entry(t)

	cacheObjects := filepath.Join(entry.CachePath, "objects")
	before := hashObjectsDir(t, cacheObjects)

	workDir := t.TempDir()
	result, err := Checkout(context.Background(), workDir, entry, Options{AgentName: testAgentName, TaskID: testTaskID})
	if err != nil {
		t.Fatalf("Checkout: %v", err)
	}

	// The cache must stay byte-identical across the checkout.
	if after := hashObjectsDir(t, cacheObjects); after != before {
		t.Errorf("cache objects changed across the checkout")
	}

	// The checkout borrows objects via alternates and never hardlinks them.
	if _, err := os.Stat(filepath.Join(result.Path, ".git", "objects", "info", "alternates")); err != nil {
		t.Fatalf("checkout lacks an alternates file: %v", err)
	}
	assertObjectsAreNotHardLinked(t, entry.CachePath, result.Path)
}

// assertObjectsAreNotHardLinked fails if a cache object file appears in the
// checkout at the same relative path and is the same underlying file.
// os.SameFile compares dev+inode on Unix and the volume serial + file index on
// Windows, either of which identifies a hard link.
func assertObjectsAreNotHardLinked(t *testing.T, cachePath, checkoutPath string) {
	t.Helper()
	cacheObjects := filepath.Join(cachePath, "objects")
	checkoutObjects := filepath.Join(checkoutPath, ".git", "objects")

	names := objectFiles(t, cacheObjects)
	if len(names) == 0 {
		t.Fatal("cache has no object files; assertion would pass vacuously")
	}
	for _, rel := range names {
		cached, err := os.Stat(filepath.Join(cacheObjects, rel))
		if err != nil {
			t.Fatalf("stat cache object %s: %v", rel, err)
		}
		cloned, err := os.Stat(filepath.Join(checkoutObjects, rel))
		if err != nil {
			continue // borrowed via alternates, not copied — nothing to compare
		}
		if os.SameFile(cached, cloned) {
			t.Errorf("object %s is hard-linked to the shared cache", rel)
		}
	}
}

// objectFiles lists regular files under a git objects directory, relative to
// it, skipping the info subdirectory that never holds object data.
func objectFiles(t *testing.T, objectsDir string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(objectsDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "info" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(objectsDir, path)
		if err != nil {
			return err
		}
		found = append(found, rel)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", objectsDir, err)
	}
	return found
}

// hashObjectsDir returns a deterministic content hash of every file under a git
// objects directory, so two listings can be compared for byte-identity.
func hashObjectsDir(t *testing.T, objectsDir string) string {
	t.Helper()
	files := objectFiles(t, objectsDir)
	sort.Strings(files)
	h := sha256.New()
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(objectsDir, rel))
		if err != nil {
			t.Fatalf("read object %s: %v", rel, err)
		}
		h.Write([]byte(rel))
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func TestCheckoutCopiesCacheRefs(t *testing.T) {
	remote := testRemote(t)
	tc := newTestCache(t, remote)
	entry := tc.entry(t)

	workDir := t.TempDir()
	result, err := Checkout(context.Background(), workDir, entry, Options{AgentName: testAgentName, TaskID: testTaskID})
	if err != nil {
		t.Fatalf("Checkout: %v", err)
	}

	// Every remote-tracking ref in the cache (excluding the origin/HEAD
	// symbolic ref) must exist in the checkout so agents can diff against it.
	out := mustGit(t, entry.CachePath, "for-each-ref", "--format=%(refname)", "refs/remotes/origin")
	var cacheRefs []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line == "refs/remotes/origin/HEAD" {
			continue
		}
		cacheRefs = append(cacheRefs, line)
	}
	if len(cacheRefs) == 0 {
		t.Fatal("cache has no remote-tracking refs; setup is broken")
	}
	for _, ref := range cacheRefs {
		if _, err := git(t, result.Path, "rev-parse", "--verify", ref); err != nil {
			t.Errorf("checkout missing %s: %v", ref, err)
		}
	}
}

func TestCheckoutKeepsDirtyAndUnpushed(t *testing.T) {
	remote := testRemote(t)
	tc := newTestCache(t, remote)
	first := tc.entry(t)

	workDir := t.TempDir()
	opts := Options{AgentName: testAgentName, TaskID: testTaskID}
	if _, err := Checkout(context.Background(), workDir, first, opts); err != nil {
		t.Fatalf("first Checkout: %v", err)
	}
	target := filepath.Join(workDir, repocache.RepoDirName(first.URL))

	// An unpushed commit and a dirty file.
	addCommit(t, target, "unpushed")
	if err := os.WriteFile(filepath.Join(target, "dirty.txt"), []byte("dirty\n"), 0o644); err != nil {
		t.Fatalf("write dirty file: %v", err)
	}

	// Advance the cache to a new commit.
	addCommit(t, remote, "second")
	second := tc.entry(t)
	if second.CommitSHA == first.CommitSHA {
		t.Fatal("setup: remote HEAD did not advance")
	}

	result, err := Checkout(context.Background(), workDir, second, opts)
	if err != nil {
		t.Fatalf("second Checkout: %v", err)
	}
	if !result.Kept {
		t.Errorf("Kept = false, want true")
	}
	if result.Ahead != 1 || result.Behind != 1 {
		t.Errorf("Ahead/Behind = %d/%d, want 1/1", result.Ahead, result.Behind)
	}
	if result.Uncommitted != 1 {
		t.Errorf("Uncommitted = %d, want 1", result.Uncommitted)
	}
	if result.Unpushed != 1 {
		t.Errorf("Unpushed = %d, want 1", result.Unpushed)
	}

	// HEAD did not move to the new SHA, and the commit and dirty file remain.
	if got := mustGit(t, target, "rev-parse", "HEAD"); got == second.CommitSHA {
		t.Errorf("HEAD moved to %s, want it left on the unpushed commit", second.CommitSHA)
	}
	if got := mustGit(t, target, "rev-list", "--count", "HEAD", "--not", "--remotes"); got != "1" {
		t.Errorf("unpushed commits = %s, want 1", got)
	}
	if _, err := os.Stat(filepath.Join(target, "dirty.txt")); err != nil {
		t.Errorf("dirty file missing after kept checkout: %v", err)
	}
}

func TestCheckoutFreshDiscards(t *testing.T) {
	remote := testRemote(t)
	tc := newTestCache(t, remote)
	first := tc.entry(t)

	workDir := t.TempDir()
	opts := Options{AgentName: testAgentName, TaskID: testTaskID}
	if _, err := Checkout(context.Background(), workDir, first, opts); err != nil {
		t.Fatalf("first Checkout: %v", err)
	}
	target := filepath.Join(workDir, repocache.RepoDirName(first.URL))

	addCommit(t, target, "unpushed")
	if err := os.WriteFile(filepath.Join(target, "dirty.txt"), []byte("dirty\n"), 0o644); err != nil {
		t.Fatalf("write dirty file: %v", err)
	}

	addCommit(t, remote, "second")
	second := tc.entry(t)

	result, err := Checkout(context.Background(), workDir, second, Options{Ref: "", Fresh: true, AgentName: testAgentName, TaskID: testTaskID})
	if err != nil {
		t.Fatalf("fresh Checkout: %v", err)
	}
	if result.Kept {
		t.Errorf("Kept = true, want false for a fresh checkout")
	}
	if got := mustGit(t, target, "rev-parse", "HEAD"); got != second.CommitSHA {
		t.Errorf("HEAD = %s, want %s", got, second.CommitSHA)
	}
	if _, err := os.Stat(filepath.Join(target, "dirty.txt")); !os.IsNotExist(err) {
		t.Errorf("dirty file still present after fresh checkout (err=%v)", err)
	}
}

func TestCheckoutRefOverrideFetches(t *testing.T) {
	remote := testRemote(t)
	tc := newTestCache(t, remote)
	entry := tc.entry(t) // entry.Ref is empty; CommitSHA is the default branch

	// Create a feature branch newer than the cache.
	mustGit(t, remote, "checkout", "-q", "-b", "feature")
	addCommit(t, remote, "feature commit")
	featureSHA := mustGit(t, remote, "rev-parse", "HEAD")

	workDir := t.TempDir()
	result, err := Checkout(context.Background(), workDir, entry, Options{Ref: "feature", AgentName: testAgentName, TaskID: testTaskID})
	if err != nil {
		t.Fatalf("Checkout with Ref: %v", err)
	}
	if got := mustGit(t, result.Path, "rev-parse", "HEAD"); got != featureSHA {
		t.Errorf("HEAD = %s, want feature tip %s", got, featureSHA)
	}
	if result.BaseSHA != featureSHA {
		t.Errorf("BaseSHA = %s, want %s", result.BaseSHA, featureSHA)
	}
}

func TestCheckoutRejectsForeignOrigin(t *testing.T) {
	// Two remotes whose URLs share a basename so they map to the same checkout
	// directory, but whose origins differ.
	base := t.TempDir()
	remote1 := filepath.Join(base, "one", "repo.git")
	remote2 := filepath.Join(base, "two", "repo.git")
	if err := os.MkdirAll(remote1, 0o755); err != nil {
		t.Fatalf("mkdir remote1: %v", err)
	}
	if err := os.MkdirAll(remote2, 0o755); err != nil {
		t.Fatalf("mkdir remote2: %v", err)
	}
	mustGit(t, "", "init", "-q", remote1)
	mustGit(t, remote1, "commit", "--allow-empty", "-q", "-m", "one")
	mustGit(t, "", "init", "-q", remote2)
	mustGit(t, remote2, "commit", "--allow-empty", "-q", "-m", "two")

	tc1 := newTestCache(t, remote1)
	tc2 := newTestCache(t, remote2)
	entry1 := tc1.entry(t)
	entry2 := tc2.entry(t)

	if repocache.RepoDirName(entry1.URL) != repocache.RepoDirName(entry2.URL) {
		t.Fatalf("setup: URLs %q and %q do not share a directory name", entry1.URL, entry2.URL)
	}

	workDir := t.TempDir()
	opts := Options{AgentName: testAgentName, TaskID: testTaskID}
	if _, err := Checkout(context.Background(), workDir, entry1, opts); err != nil {
		t.Fatalf("first Checkout: %v", err)
	}

	if _, err := Checkout(context.Background(), workDir, entry2, opts); err == nil {
		t.Fatal("second Checkout with a foreign origin succeeded, want an error")
	} else if !strings.Contains(err.Error(), "origin") {
		t.Errorf("error %q does not mention the origin mismatch", err)
	}
}

func TestCheckoutRejectsBarePath(t *testing.T) {
	// entry.CachePath points at a normal worktree (not a bare repo).
	worktree := testRemote(t)
	entry := Entry{
		URL:       "https://example.com/repo.git",
		CommitSHA: strings.Repeat("a", 40),
		CachePath: worktree,
	}

	if _, err := Checkout(context.Background(), t.TempDir(), entry, Options{AgentName: testAgentName, TaskID: testTaskID}); err == nil {
		t.Fatal("Checkout accepted a non-bare cache path, want an error")
	}
}

func TestCheckoutsShareCacheWithoutCrossTalk(t *testing.T) {
	remote := testRemote(t)
	tc := newTestCache(t, remote)
	entry := tc.entry(t)

	cacheObjects := filepath.Join(entry.CachePath, "objects")
	before := hashObjectsDir(t, cacheObjects)

	workA := t.TempDir()
	workB := t.TempDir()
	opts := Options{AgentName: testAgentName, TaskID: testTaskID}
	a, err := Checkout(context.Background(), workA, entry, opts)
	if err != nil {
		t.Fatalf("checkout A: %v", err)
	}
	b, err := Checkout(context.Background(), workB, entry, opts)
	if err != nil {
		t.Fatalf("checkout B: %v", err)
	}

	// A commit and a dirty file in A must not appear in B.
	addCommit(t, a.Path, "a-commit")
	if err := os.WriteFile(filepath.Join(a.Path, "a-dirty.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatalf("write A dirty file: %v", err)
	}

	if got := mustGit(t, b.Path, "rev-parse", "HEAD"); got != entry.CommitSHA {
		t.Errorf("B HEAD = %s, want the base %s", got, entry.CommitSHA)
	}
	if _, err := os.Stat(filepath.Join(b.Path, "a-dirty.txt")); !os.IsNotExist(err) {
		t.Errorf("A's dirty file leaked into B (err=%v)", err)
	}
	if got := mustGit(t, b.Path, "rev-list", "--count", "HEAD", "--not", "--remotes"); got != "0" {
		t.Errorf("B has %s unpushed commits, want 0", got)
	}

	// Both checkouts are on the same branch name, but their heads and indexes
	// are independent.
	if a.Branch != b.Branch {
		t.Errorf("branch names differ: %q vs %q", a.Branch, b.Branch)
	}

	// The cache is untouched by both checkouts.
	if after := hashObjectsDir(t, cacheObjects); after != before {
		t.Errorf("cache objects changed across both checkouts")
	}
	assertObjectsAreNotHardLinked(t, entry.CachePath, a.Path)
	assertObjectsAreNotHardLinked(t, entry.CachePath, b.Path)
}
