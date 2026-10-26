package repocache

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrepareUsesTaskGitEnvironmentForColdCloneAndFetch(t *testing.T) {
	t.Parallel()
	remote := createTestRepo(t)
	cache := New(t.TempDir(), testLogger())
	url := "https://private.example/acme/private.git"
	env := append(GitEnv(),
		"GIT_CONFIG_COUNT=2",
		"GIT_CONFIG_KEY_1=url."+remote+".insteadOf",
		"GIT_CONFIG_VALUE_1="+url,
	)
	ctx := WithGitEnvironment(context.Background(), env)
	first, err := cache.Prepare(ctx, Scope{WorkspaceID: "ws-1", UserID: "test-user"}, []RepoInfo{{URL: url}})
	if err != nil {
		t.Fatalf("cold clone with task credentials: %v", err)
	}
	if first[0].URL != url {
		t.Fatalf("cache identity changed: %q", first[0].URL)
	}
	addEmptyCommit(t, remote, "fresh commit")
	second, err := cache.Prepare(ctx, Scope{WorkspaceID: "ws-1", UserID: "test-user"}, []RepoInfo{{URL: url}})
	if err != nil {
		t.Fatalf("fetch with task credentials: %v", err)
	}
	if second[0].CommitSHA != gitHead(t, remote) || second[0].CommitSHA == first[0].CommitSHA {
		t.Fatal("task did not receive the latest remote commit")
	}
	config, err := runGitOutput("-C", second[0].BarePath, "config", "--local", "--list")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config), "insteadof") {
		t.Fatalf("task authentication persisted in shared cache: %s", config)
	}
}

func TestPrepareColdCache(t *testing.T) {
	t.Parallel()
	remote := createTestRepo(t)
	wantSHA := gitHead(t, remote)
	cache := New(t.TempDir(), testLogger())

	got, err := cache.Prepare(context.Background(), Scope{WorkspaceID: "ws-1", UserID: "test-user"}, []RepoInfo{{URL: remote}})
	if err != nil {
		t.Fatalf("Prepare failed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Prepare returned %d repos, want 1", len(got))
	}
	prepared := got[0]
	if prepared.URL != remote {
		t.Errorf("URL = %q, want %q", prepared.URL, remote)
	}
	if prepared.Ref != "" {
		t.Errorf("Ref = %q, want empty for the default branch", prepared.Ref)
	}
	if want := cache.BarePath(Scope{WorkspaceID: "ws-1", UserID: "test-user"}, remote); prepared.BarePath != want {
		t.Errorf("BarePath = %q, want %q", prepared.BarePath, want)
	}
	if prepared.CommitSHA != wantSHA {
		t.Errorf("CommitSHA = %q, want remote HEAD %q", prepared.CommitSHA, wantSHA)
	}
	if !isBareRepo(prepared.BarePath) {
		t.Errorf("bare cache missing at %s", prepared.BarePath)
	}
}

func TestPrepareWarmCacheFetchesNewCommit(t *testing.T) {
	t.Parallel()
	remote := createTestRepo(t)
	cache := New(t.TempDir(), testLogger())

	first, err := cache.Prepare(context.Background(), Scope{WorkspaceID: "ws-1", UserID: "test-user"}, []RepoInfo{{URL: remote}})
	if err != nil {
		t.Fatalf("first Prepare failed: %v", err)
	}
	addEmptyCommit(t, remote, "second commit")
	wantSHA := gitHead(t, remote)
	if wantSHA == first[0].CommitSHA {
		t.Fatal("test setup failed: remote HEAD did not advance")
	}

	second, err := cache.Prepare(context.Background(), Scope{WorkspaceID: "ws-1", UserID: "test-user"}, []RepoInfo{{URL: remote}})
	if err != nil {
		t.Fatalf("second Prepare failed: %v", err)
	}
	if len(second) != 1 {
		t.Fatalf("second Prepare returned %d repos, want 1", len(second))
	}
	if second[0].CommitSHA != wantSHA {
		t.Errorf("CommitSHA = %q, want fetched remote HEAD %q", second[0].CommitSHA, wantSHA)
	}
	if second[0].BarePath != first[0].BarePath {
		t.Errorf("BarePath changed from %q to %q", first[0].BarePath, second[0].BarePath)
	}
}

func TestPrepareRequestedRef(t *testing.T) {
	t.Parallel()
	remote := createTestRepo(t)
	defaultBranch := currentBranchName(t, remote)
	runGitAuthored(t, remote, "checkout", "-b", "feature")
	addEmptyCommit(t, remote, "feature commit")
	featureSHA := gitHead(t, remote)
	runGitAuthored(t, remote, "checkout", defaultBranch)

	cache := New(t.TempDir(), testLogger())
	got, err := cache.Prepare(context.Background(), Scope{WorkspaceID: "ws-1", UserID: "test-user"}, []RepoInfo{{URL: remote, Ref: "feature"}})
	if err != nil {
		t.Fatalf("Prepare failed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Prepare returned %d repos, want 1", len(got))
	}
	if got[0].Ref != "feature" {
		t.Errorf("Ref = %q, want %q", got[0].Ref, "feature")
	}
	if got[0].CommitSHA != featureSHA {
		t.Errorf("CommitSHA = %q, want feature tip %q", got[0].CommitSHA, featureSHA)
	}
}

func TestPrepareFetchFailureIsStrict(t *testing.T) {
	t.Parallel()
	remote := createTestRepo(t)
	cache := New(t.TempDir(), testLogger())

	first, err := cache.Prepare(context.Background(), Scope{WorkspaceID: "ws-1", UserID: "test-user"}, []RepoInfo{{URL: remote}})
	if err != nil {
		t.Fatalf("first Prepare failed: %v", err)
	}
	oldSHA := first[0].CommitSHA
	// Remove the remote so the next fetch cannot reach it. Prepare must report
	// the failure instead of handing back the cached SHA.
	if err := os.RemoveAll(remote); err != nil {
		t.Fatalf("remove remote: %v", err)
	}

	got, err := cache.Prepare(context.Background(), Scope{WorkspaceID: "ws-1", UserID: "test-user"}, []RepoInfo{{URL: remote}})
	if err == nil {
		t.Fatal("expected fetch failure, got nil error")
	}
	if !strings.Contains(err.Error(), remote) {
		t.Errorf("error %q does not name the repo URL %q", err, remote)
	}
	if got != nil {
		t.Errorf("Prepare returned %d repos on fetch failure, want none (old SHA %s)", len(got), oldSHA)
	}
}

func TestPrepareUnknownRef(t *testing.T) {
	t.Parallel()
	remote := createTestRepo(t)
	cache := New(t.TempDir(), testLogger())

	got, err := cache.Prepare(context.Background(), Scope{WorkspaceID: "ws-1", UserID: "test-user"}, []RepoInfo{{URL: remote, Ref: "missing"}})
	if err == nil {
		t.Fatal("expected unknown ref error")
	}
	if !strings.Contains(err.Error(), "cannot resolve requested ref") {
		t.Errorf("expected requested-ref error, got: %v", err)
	}
	if got != nil {
		t.Errorf("Prepare returned %d repos for an unknown ref, want none", len(got))
	}
}

func TestPrepareColdCloneFailure(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	cache := New(t.TempDir(), testLogger())

	got, err := cache.Prepare(context.Background(), Scope{WorkspaceID: "ws-1", UserID: "test-user"}, []RepoInfo{{URL: missing}})
	if err == nil {
		t.Fatal("expected clone failure, got nil error")
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error %q does not name the repo URL %q", err, missing)
	}
	if got != nil {
		t.Errorf("Prepare returned %d repos on clone failure, want none", len(got))
	}
}

func TestPrepareRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	cache := New(t.TempDir(), testLogger())
	remote := createTestRepo(t)

	if got, err := cache.Prepare(context.Background(), Scope{WorkspaceID: "", UserID: "test-user"}, []RepoInfo{{URL: remote}}); err == nil {
		t.Errorf("Prepare with empty workspace ID returned %d repos, want error", len(got))
	}
	if got, err := cache.Prepare(context.Background(), Scope{WorkspaceID: "ws-1", UserID: "test-user"}, []RepoInfo{{URL: ""}}); err == nil {
		t.Errorf("Prepare with empty URL returned %d repos, want error", len(got))
	}
}

func TestPrepareEmptyReposReturnsNil(t *testing.T) {
	t.Parallel()
	cache := New(t.TempDir(), testLogger())

	got, err := cache.Prepare(context.Background(), Scope{WorkspaceID: "ws-1", UserID: "test-user"}, nil)
	if err != nil {
		t.Fatalf("Prepare with no repos failed: %v", err)
	}
	if got != nil {
		t.Errorf("Prepare with no repos returned %d repos, want nil", len(got))
	}
}

// TestPrepareRefreshesCABundleOnCachedRepo proves Prepare applies the cache's
// extra-CA bundle before fetching an existing cache, the same way SyncContext
// does. A cache created before the server sent private CAs would otherwise
// keep fetching with the trust it had at clone time.
func TestPrepareRefreshesCABundleOnCachedRepo(t *testing.T) {
	isolateGitConfig(t)
	if len(readSystemCABundle()) == 0 {
		t.Skip("no system CA bundle")
	}
	remote := createTestRepo(t)
	cache := newTestCacheQuiet(t)

	if _, err := cache.Prepare(context.Background(), Scope{WorkspaceID: "ws-1", UserID: "test-user"}, []RepoInfo{{URL: remote}}); err != nil {
		t.Fatalf("initial Prepare failed: %v", err)
	}
	_, caPEM := newServerCert(t, "prepare-ca")
	if err := cache.SetExtraCACerts(caPEM); err != nil {
		t.Fatalf("SetExtraCACerts: %v", err)
	}
	barePath := cache.BarePath(Scope{WorkspaceID: "ws-1", UserID: "test-user"}, remote)
	if out, _ := agentGit(t, barePath, "config", "--local", "--get", caBundleConfigKey); strings.TrimSpace(out) != "" {
		t.Fatalf("%s already set on the pre-existing cache: %q", caBundleConfigKey, out)
	}

	if _, err := cache.Prepare(context.Background(), Scope{WorkspaceID: "ws-1", UserID: "test-user"}, []RepoInfo{{URL: remote}}); err != nil {
		t.Fatalf("second Prepare failed: %v", err)
	}
	out, err := agentGit(t, barePath, "config", "--local", "--get", caBundleConfigKey)
	if err != nil {
		t.Fatalf("read %s: %s: %v", caBundleConfigKey, out, err)
	}
	if got, want := strings.TrimSpace(out), cache.caBundlePath(); got != want {
		t.Fatalf("%s = %q, want %q", caBundleConfigKey, got, want)
	}
}

func TestPrepareFetchesIndependentReposConcurrentlyWithBound(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	gate := t.TempDir()
	release := filepath.Join(gate, "release")
	ready := filepath.Join(gate, "ready")
	if err := os.Mkdir(ready, 0700); err != nil {
		t.Fatal(err)
	}
	wrapperDir := t.TempDir()
	wrapper := `#!/bin/sh
if [ "$1" = clone ]; then
 for last do :; done
 touch "$TEST_PREPARE_READY/$(basename "$last")"
 while [ ! -f "$TEST_PREPARE_RELEASE" ]; do sleep 0.01; done
fi
exec "$TEST_REAL_GIT" "$@"
`
	if err := os.WriteFile(filepath.Join(wrapperDir, "git"), []byte(wrapper), 0700); err != nil {
		t.Fatal(err)
	}
	repos := make([]RepoInfo, 6)
	for i := range repos {
		repos[i] = RepoInfo{URL: createTestRepo(t)}
	}
	t.Setenv("TEST_REAL_GIT", git)
	t.Setenv("TEST_PREPARE_READY", ready)
	t.Setenv("TEST_PREPARE_RELEASE", release)
	t.Setenv("PATH", wrapperDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	cache := New(t.TempDir(), testLogger())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	type result struct {
		repos []PreparedRepo
		err   error
	}
	done := make(chan result, 1)
	go func() {
		repos, err := cache.Prepare(ctx, Scope{WorkspaceID: "ws-1", UserID: "test-user"}, repos)
		done <- result{repos, err}
	}()
	deadline := time.After(2 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	count := 0
wait:
	for {
		entries, err := os.ReadDir(ready)
		if err != nil {
			t.Fatal(err)
		}
		count = len(entries)
		if count >= 4 {
			break
		}
		select {
		case <-deadline:
			break wait
		case <-ticker.C:
		}
	}
	if err := os.WriteFile(release, nil, 0600); err != nil {
		t.Fatal(err)
	}
	got := <-done
	if count != 4 {
		t.Fatalf("concurrent clone count=%d, want 4; independent repos must not prepare serially or without a bound", count)
	}
	if got.err != nil {
		t.Fatal(got.err)
	}
	if len(got.repos) != len(repos) {
		t.Fatalf("prepared %d repos", len(got.repos))
	}
	for i, repo := range got.repos {
		if repo.URL != repos[i].URL {
			t.Fatalf("repository order changed at %d", i)
		}
	}
}

func TestPrepareBatchFailureReturnsNoPartialRepositories(t *testing.T) {
	t.Parallel()
	first, second := createTestRepo(t), createTestRepo(t)
	repos := []RepoInfo{{URL: first}, {URL: second}}
	cache := New(t.TempDir(), testLogger())
	if _, err := cache.Prepare(context.Background(), Scope{WorkspaceID: "ws-1", UserID: "test-user"}, repos); err != nil {
		t.Fatal(err)
	}
	addEmptyCommit(t, first, "updated head")
	if err := os.RemoveAll(second); err != nil {
		t.Fatal(err)
	}
	got, err := cache.Prepare(context.Background(), Scope{WorkspaceID: "ws-1", UserID: "test-user"}, repos)
	if err == nil || !strings.Contains(err.Error(), second) || got != nil {
		t.Fatalf("expected strict batch failure, got=%v err=%v", got, err)
	}
}
