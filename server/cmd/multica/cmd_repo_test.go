package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/multica-ai/multica/server/internal/daemon/repocache"
	"github.com/multica-ai/multica/server/internal/daemon/workercheckout"
)

func newRepoRegistryTestCmd(serverURL string) *cobra.Command {
	cmd := &cobra.Command{Use: "repo-test"}
	cmd.Flags().String("server-url", "", "")
	cmd.Flags().String("workspace-id", "", "")
	cmd.Flags().String("profile", "", "")
	cmd.Flags().StringArray("url", nil, "")
	cmd.Flags().String("description", "", "")
	cmd.Flags().String("output", "json", "")
	_ = cmd.Flags().Set("server-url", serverURL)
	_ = cmd.Flags().Set("workspace-id", "ws-1")
	return cmd
}

func TestRunRepoAddAppendsAndDedupes(t *testing.T) {
	initialRepos := []workspaceRepo{{URL: "https://git.example.com/web.git"}}
	var patched []workspaceRepo
	patchCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/workspaces/ws-1":
			json.NewEncoder(w).Encode(repoWorkspaceResponse{ID: "ws-1", Repos: initialRepos})
		case r.Method == http.MethodPatch && r.URL.Path == "/api/workspaces/ws-1":
			patchCount++
			var body struct {
				Repos []workspaceRepo `json:"repos"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode patch body: %v", err)
			}
			patched = body.Repos
			json.NewEncoder(w).Encode(repoWorkspaceResponse{ID: "ws-1", Repos: body.Repos})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cmd := newRepoRegistryTestCmd(srv.URL)
	if err := cmd.Flags().Set("url", "https://git.example.com/web.git"); err != nil {
		t.Fatal(err)
	}
	err := runRepoAdd(cmd, []string{
		"https://git.example.com/api.git",
		"https://git.example.com/api.git",
	})
	if err != nil {
		t.Fatalf("runRepoAdd: %v", err)
	}
	if patchCount != 1 {
		t.Fatalf("patchCount = %d, want 1", patchCount)
	}
	if len(patched) != 2 {
		t.Fatalf("patched repos = %+v, want 2 entries", patched)
	}
	if patched[0].URL != "https://git.example.com/web.git" || patched[1].URL != "https://git.example.com/api.git" {
		t.Fatalf("unexpected patched repos: %+v", patched)
	}
}

func TestRunRepoAddUpdatesDescriptionForExistingRepo(t *testing.T) {
	initialRepos := []workspaceRepo{{URL: "https://git.example.com/web.git", Description: "old"}}
	var patched []workspaceRepo

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/workspaces/ws-1":
			json.NewEncoder(w).Encode(repoWorkspaceResponse{ID: "ws-1", Repos: initialRepos})
		case r.Method == http.MethodPatch && r.URL.Path == "/api/workspaces/ws-1":
			var body struct {
				Repos []workspaceRepo `json:"repos"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode patch body: %v", err)
			}
			patched = body.Repos
			json.NewEncoder(w).Encode(repoWorkspaceResponse{ID: "ws-1", Repos: body.Repos})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cmd := newRepoRegistryTestCmd(srv.URL)
	if err := cmd.Flags().Set("description", "new"); err != nil {
		t.Fatal(err)
	}
	if err := runRepoAdd(cmd, []string{"https://git.example.com/web.git"}); err != nil {
		t.Fatalf("runRepoAdd: %v", err)
	}
	if len(patched) != 1 || patched[0].Description != "new" {
		t.Fatalf("patched repos = %+v, want updated description", patched)
	}
}

func TestRunRepoAddRejectsDescriptionForMultipleRepos(t *testing.T) {
	cmd := newRepoRegistryTestCmd("http://127.0.0.1:0")
	if err := cmd.Flags().Set("description", "shared"); err != nil {
		t.Fatal(err)
	}
	err := runRepoAdd(cmd, []string{"https://git.example.com/a.git", "https://git.example.com/b.git"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "--description") {
		t.Fatalf("error = %q, want description guidance", err)
	}
}

func TestRunRepoRemoveDeletesExistingRepos(t *testing.T) {
	initialRepos := []workspaceRepo{
		{URL: "https://git.example.com/web.git"},
		{URL: "https://git.example.com/api.git"},
		{URL: "https://git.example.com/mobile.git"},
	}
	var patched []workspaceRepo

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/workspaces/ws-1":
			json.NewEncoder(w).Encode(repoWorkspaceResponse{ID: "ws-1", Repos: initialRepos})
		case r.Method == http.MethodPatch && r.URL.Path == "/api/workspaces/ws-1":
			var body struct {
				Repos []workspaceRepo `json:"repos"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode patch body: %v", err)
			}
			patched = body.Repos
			json.NewEncoder(w).Encode(repoWorkspaceResponse{ID: "ws-1", Repos: body.Repos})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cmd := newRepoRegistryTestCmd(srv.URL)
	if err := cmd.Flags().Set("url", "https://git.example.com/mobile.git"); err != nil {
		t.Fatal(err)
	}
	if err := runRepoRemove(cmd, []string{"https://git.example.com/web.git"}); err != nil {
		t.Fatalf("runRepoRemove: %v", err)
	}
	if len(patched) != 1 || patched[0].URL != "https://git.example.com/api.git" {
		t.Fatalf("patched repos = %+v, want only api repo", patched)
	}
}

func TestRunRepoRemoveRejectsMissingRepoWithoutPatch(t *testing.T) {
	patchCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/workspaces/ws-1":
			json.NewEncoder(w).Encode(repoWorkspaceResponse{
				ID:    "ws-1",
				Repos: []workspaceRepo{{URL: "https://git.example.com/web.git"}},
			})
		case r.Method == http.MethodPatch && r.URL.Path == "/api/workspaces/ws-1":
			patchCount++
			json.NewEncoder(w).Encode(repoWorkspaceResponse{ID: "ws-1"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cmd := newRepoRegistryTestCmd(srv.URL)
	err := runRepoRemove(cmd, []string{"https://git.example.com/missing.git"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error = %q, want not found", err)
	}
	if patchCount != 0 {
		t.Fatalf("patchCount = %d, want 0", patchCount)
	}
}

func TestRunRepoCheckoutForwardsManagedCheckoutMode(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/repo/checkout" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode checkout body: %v", err)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer mat_repo_checkout_test" {
			t.Fatalf("Authorization = %q, want task-scoped bearer", got)
		}
		json.NewEncoder(w).Encode(map[string]string{
			"path":        "/work/repo",
			"branch_name": "agent/test/task",
		})
	}))
	defer srv.Close()

	t.Setenv("MULTICA_DAEMON_PORT", strings.TrimPrefix(srv.URL, "http://127.0.0.1:"))
	t.Setenv("MULTICA_WORKSPACE_ID", "ws-1")
	t.Setenv("MULTICA_AGENT_NAME", "Test Agent")
	t.Setenv("MULTICA_TASK_ID", "task-1")
	t.Setenv("MULTICA_TOKEN", "mat_repo_checkout_test")
	t.Setenv("MULTICA_REPO_CHECKOUT_MODE", "isolated")

	previousRef, previousFresh := repoCheckoutRef, repoCheckoutFresh
	repoCheckoutRef, repoCheckoutFresh = "release/v2", true
	defer func() { repoCheckoutRef, repoCheckoutFresh = previousRef, previousFresh }()

	if err := runRepoCheckout(&cobra.Command{}, []string{"https://github.com/org/repo.git"}); err != nil {
		t.Fatalf("runRepoCheckout: %v", err)
	}
	if got := body["checkout_mode"]; got != "isolated" {
		t.Fatalf("checkout_mode = %q, want isolated", got)
	}
	if got := body["ref"]; got != "release/v2" {
		t.Fatalf("ref = %q, want release/v2", got)
	}
	if got := body["retry_busy"]; got != true {
		t.Fatalf("retry_busy = %v, want true", got)
	}
	if got := body["fresh"]; got != true {
		t.Fatalf("fresh = %v, want true", got)
	}
}

func TestRepoCheckoutSummary(t *testing.T) {
	t.Parallel()
	const repoURL = "https://github.com/org/repo.git"
	for _, tc := range []struct {
		name   string
		result repoCheckoutResult
		want   []string
	}{
		{
			name:   "new branch",
			result: repoCheckoutResult{Path: "/work/repo", BranchName: "agent/test/task"},
			want:   []string{"Checked out " + repoURL + " → /work/repo (branch: agent/test/task)"},
		},
		{
			name:   "kept for local work",
			result: repoCheckoutResult{Path: "/work/repo", BranchName: "agent/test/old", Kept: "local_work", UncommittedFiles: 2, UnpushedCommits: 1},
			want: []string{
				"Kept the existing checkout of " + repoURL + " at /work/repo (branch: agent/test/old; 2 uncommitted files, 1 unpushed commit)",
				"nothing was reset, cleaned, or switched",
				"re-run with --fresh",
			},
		},
		{
			name:   "kept on the task branch",
			result: repoCheckoutResult{Path: "/work/repo", BranchName: "agent/test/task", Kept: "task_branch"},
			want:   []string{"(branch: agent/test/task, this task's branch; 0 uncommitted files, 0 unpushed commits)"},
		},
		{
			name:   "kept on a detached HEAD",
			result: repoCheckoutResult{Path: "/work/repo", Kept: "local_work", UnpushedCommits: 3},
			want:   []string{"(branch: detached HEAD; 0 uncommitted files, 3 unpushed commits)"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := repoCheckoutSummary(repoURL, tc.result)
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Fatalf("summary missing %q:\n%s", want, got)
				}
			}
			if kept := strings.HasPrefix(got, "Kept "); kept != (tc.result.Kept != "") {
				t.Fatalf("summary reads kept=%v for Kept=%q:\n%s", kept, tc.result.Kept, got)
			}
		})
	}
}

func TestRunRepoCheckoutRequiresTaskCredential(t *testing.T) {
	t.Setenv("MULTICA_DAEMON_PORT", "12345")
	t.Setenv("MULTICA_TOKEN", "")

	err := runRepoCheckout(&cobra.Command{}, []string{"https://github.com/org/repo.git"})
	if err == nil || !strings.Contains(err.Error(), "MULTICA_TOKEN not set") {
		t.Fatalf("runRepoCheckout error = %v, want missing task credential", err)
	}
}

func TestRunRepoCheckoutRetriesServiceUnavailable(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.Header().Set("X-Multica-Retryable", "repo-busy")
			w.Header().Set("Retry-After", "0")
			http.Error(w, "repository busy", http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"path":        "/work/repo",
			"branch_name": "agent/test/task",
		})
	}))
	defer srv.Close()

	t.Setenv("MULTICA_DAEMON_PORT", strings.TrimPrefix(srv.URL, "http://127.0.0.1:"))
	t.Setenv("MULTICA_WORKSPACE_ID", "ws-1")
	t.Setenv("MULTICA_AGENT_NAME", "Test Agent")
	t.Setenv("MULTICA_TASK_ID", "task-1")
	t.Setenv("MULTICA_TOKEN", "mat_repo_checkout_test")

	if err := runRepoCheckout(&cobra.Command{}, []string{"https://github.com/org/repo.git"}); err != nil {
		t.Fatalf("runRepoCheckout: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("checkout attempts = %d, want 2", attempts)
	}
}

func TestRunRepoCheckoutDoesNotRetryUnmarkedServiceUnavailable(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		http.Error(w, "daemon unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	t.Setenv("MULTICA_DAEMON_PORT", strings.TrimPrefix(srv.URL, "http://127.0.0.1:"))
	t.Setenv("MULTICA_TOKEN", "mat_repo_checkout_test")
	if err := runRepoCheckout(&cobra.Command{}, []string{"https://github.com/org/repo.git"}); err == nil {
		t.Fatal("runRepoCheckout unexpectedly succeeded")
	}
	if attempts != 1 {
		t.Fatalf("checkout attempts = %d, want 1", attempts)
	}
}

func TestRepoCheckoutRetryDelay(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	if got := repoCheckoutRetryDelay("7", now); got != 7*time.Second {
		t.Fatalf("seconds delay = %s, want 7s", got)
	}
	if got := repoCheckoutRetryDelay(now.Add(time.Minute).Format(http.TimeFormat), now); got != 30*time.Second {
		t.Fatalf("capped date delay = %s, want 30s", got)
	}
	if got := repoCheckoutRetryDelay("invalid", now); got != time.Second {
		t.Fatalf("default delay = %s, want 1s", got)
	}
}

const (
	testRepoCheckoutAgentName = "Test Agent"
	testRepoCheckoutTaskID    = "01a01ec0-e69d-7000-8000-000000000001"
)

// repoTestGit runs git in dir (or the process cwd when empty) with a fixed
// author identity, returning trimmed combined output.
func repoTestGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@test.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@test.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v (dir=%s): %s: %v", args, dir, out, err)
	}
	return strings.TrimSpace(string(out))
}

// repoCheckoutTestRemote creates a local repository with a single commit and
// returns its path, which is used directly as the git remote URL.
func repoCheckoutTestRemote(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "repo")
	repoTestGit(t, "", "init", "-q", dir)
	repoTestGit(t, dir, "commit", "--allow-empty", "-q", "-m", "initial")
	return dir
}

// repoCheckoutTestCache prepares bare caches for a local remote through the
// daemon's repocache package, so tests use the exact cache layout the worker
// sees. Re-preparing after the remote advances returns a new CommitSHA at the
// same CachePath.
type repoCheckoutTestCache struct {
	remote string
	cache  *repocache.Cache
}

func newRepoCheckoutTestCache(t *testing.T, remote string) *repoCheckoutTestCache {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &repoCheckoutTestCache{remote: remote, cache: repocache.New(t.TempDir(), logger)}
}

func (tc *repoCheckoutTestCache) entry(t *testing.T) workercheckout.Entry {
	t.Helper()
	prepared, err := tc.cache.Prepare(context.Background(), "ws-1", []repocache.RepoInfo{{URL: tc.remote}})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	p := prepared[0]
	return workercheckout.Entry{URL: p.URL, Ref: p.Ref, CommitSHA: p.CommitSHA, CachePath: p.BarePath}
}

// setupRepoCheckoutIsolatedEnv marks the isolated tool boundary and points the
// manifest at a fresh task config root, leaving MULTICA_TOKEN and
// MULTICA_DAEMON_PORT unset so the isolated path cannot depend on them.
func setupRepoCheckoutIsolatedEnv(t *testing.T) {
	t.Helper()
	t.Setenv("MULTICA_ISOLATED_TOOL_BOUNDARY", "1")
	t.Setenv("MULTICA_TASK_CONFIG_ROOT", t.TempDir())
	t.Setenv("MULTICA_AGENT_NAME", testRepoCheckoutAgentName)
	t.Setenv("MULTICA_TASK_ID", testRepoCheckoutTaskID)
	t.Setenv("MULTICA_TOKEN", "")
	t.Setenv("MULTICA_DAEMON_PORT", "")
}

// writeRepoCheckoutManifest publishes entries at ManifestPath().
func writeRepoCheckoutManifest(t *testing.T, entries ...workercheckout.Entry) {
	t.Helper()
	path, err := workercheckout.ManifestPath()
	if err != nil {
		t.Fatalf("ManifestPath: %v", err)
	}
	if err := workercheckout.WriteManifest(path, workercheckout.Manifest{Repos: entries}); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
}

func TestRunRepoCheckoutIsolatedUsesManifest(t *testing.T) {
	remote := repoCheckoutTestRemote(t)
	tc := newRepoCheckoutTestCache(t, remote)
	entry := tc.entry(t)

	workDir := t.TempDir()
	setupRepoCheckoutIsolatedEnv(t)
	writeRepoCheckoutManifest(t, entry)
	t.Chdir(workDir)

	if err := runRepoCheckout(&cobra.Command{}, []string{entry.URL}); err != nil {
		t.Fatalf("runRepoCheckout: %v", err)
	}

	target := filepath.Join(workDir, repocache.RepoDirName(entry.URL))
	info, err := os.Stat(filepath.Join(target, ".git"))
	if err != nil {
		t.Fatalf("checkout .git missing: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("checkout .git is not a directory")
	}
	if got := repoTestGit(t, target, "remote", "get-url", "origin"); got != entry.URL {
		t.Fatalf("origin = %q, want %q", got, entry.URL)
	}
}

func TestRunRepoCheckoutIsolatedRejectsUnknownURL(t *testing.T) {
	remote := repoCheckoutTestRemote(t)
	tc := newRepoCheckoutTestCache(t, remote)
	entry := tc.entry(t)

	setupRepoCheckoutIsolatedEnv(t)
	writeRepoCheckoutManifest(t, entry)
	t.Chdir(t.TempDir())

	unknown := filepath.Join(t.TempDir(), "unknown")
	err := runRepoCheckout(&cobra.Command{}, []string{unknown})
	if err == nil {
		t.Fatal("runRepoCheckout unexpectedly succeeded for an unknown URL")
	}
	if !strings.Contains(err.Error(), "allowed URLs") || !strings.Contains(err.Error(), entry.URL) {
		t.Fatalf("error = %q, want it to name the allowed URL %q", err, entry.URL)
	}
}

func TestRunRepoCheckoutIsolatedKeepsDirtyCheckout(t *testing.T) {
	remote := repoCheckoutTestRemote(t)
	tc := newRepoCheckoutTestCache(t, remote)
	first := tc.entry(t)

	workDir := t.TempDir()
	setupRepoCheckoutIsolatedEnv(t)
	writeRepoCheckoutManifest(t, first)
	t.Chdir(workDir)

	if err := runRepoCheckout(&cobra.Command{}, []string{first.URL}); err != nil {
		t.Fatalf("first runRepoCheckout: %v", err)
	}
	target := filepath.Join(workDir, repocache.RepoDirName(first.URL))

	// A local commit and a dirty file that a kept checkout must preserve.
	repoTestGit(t, target, "commit", "--allow-empty", "-q", "-m", "unpushed")
	if err := os.WriteFile(filepath.Join(target, "dirty.txt"), []byte("dirty\n"), 0o644); err != nil {
		t.Fatalf("write dirty file: %v", err)
	}

	// Advance the remote so the manifest carries a new SHA.
	repoTestGit(t, remote, "commit", "--allow-empty", "-q", "-m", "second")
	second := tc.entry(t)
	if second.CommitSHA == first.CommitSHA {
		t.Fatal("setup: remote HEAD did not advance")
	}
	writeRepoCheckoutManifest(t, second)

	stderr := captureStderr(t)
	err := runRepoCheckout(&cobra.Command{}, []string{second.URL})
	summary := stderr.read()
	if err != nil {
		t.Fatalf("second runRepoCheckout: %v", err)
	}
	for _, want := range []string{"ahead", "behind", "uncommitted", "unpushed", "nothing was reset"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("summary missing %q:\n%s", want, summary)
		}
	}

	// The local commit and dirty file survive; HEAD stays on the unpushed commit.
	if got := repoTestGit(t, target, "rev-parse", "HEAD"); got == second.CommitSHA {
		t.Fatalf("HEAD moved to %s, want it left on the unpushed commit", second.CommitSHA)
	}
	if got := repoTestGit(t, target, "rev-list", "--count", "HEAD", "--not", "--remotes"); got != "1" {
		t.Fatalf("unpushed commits = %s, want 1", got)
	}
	if _, err := os.Stat(filepath.Join(target, "dirty.txt")); err != nil {
		t.Fatalf("dirty file missing after kept checkout: %v", err)
	}
}

func TestRunRepoCheckoutHostStillRequiresDaemonPort(t *testing.T) {
	t.Setenv("MULTICA_ISOLATED_TOOL_BOUNDARY", "")
	t.Setenv("MULTICA_DAEMON_PORT", "")
	t.Setenv("MULTICA_TOKEN", "")

	err := runRepoCheckout(&cobra.Command{}, []string{"https://github.com/org/repo.git"})
	if err == nil || !strings.Contains(err.Error(), "MULTICA_DAEMON_PORT not set") {
		t.Fatalf("runRepoCheckout error = %v, want missing daemon port", err)
	}
}

func TestRepoCheckoutIsolatedSummary(t *testing.T) {
	t.Parallel()
	const repoURL = "https://github.com/org/repo.git"
	for _, tc := range []struct {
		name   string
		result workercheckout.Result
		want   []string
	}{
		{
			name:   "fresh",
			result: workercheckout.Result{Path: "/work/repo", Branch: "agent/test/abc", BaseSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			want:   []string{"Checked out " + repoURL + " → /work/repo (branch: agent/test/abc, base aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)"},
		},
		{
			name:   "kept with ahead/behind",
			result: workercheckout.Result{Path: "/work/repo", Branch: "agent/test/abc", Kept: true, Ahead: 1, Behind: 1, Uncommitted: 2, Unpushed: 3},
			want: []string{
				"(branch: agent/test/abc; 1 commit ahead, 1 commit behind, 2 uncommitted files, 3 unpushed commits)",
				"nothing was reset, cleaned, or switched",
				"To discard local commits and uncommitted changes",
				"push anything you still need first",
			},
		},
		{
			name:   "kept on detached HEAD",
			result: workercheckout.Result{Path: "/work/repo", Kept: true, Behind: 4},
			want:   []string{"(branch: detached HEAD; 0 commits ahead, 4 commits behind, 0 uncommitted files, 0 unpushed commits)"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := repoCheckoutIsolatedSummary(repoURL, tc.result)
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Fatalf("summary missing %q:\n%s", want, got)
				}
			}
			if kept := strings.HasPrefix(got, "Kept "); kept != tc.result.Kept {
				t.Fatalf("summary reads kept=%v for Kept=%v:\n%s", kept, tc.result.Kept, got)
			}
		})
	}
}
