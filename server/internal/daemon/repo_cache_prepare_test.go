package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/daemon/repocache"
	"github.com/multica-ai/multica/server/internal/daemon/workercheckout"
)

// fakePrepareCache is a repoCacheBackend that also implements Prepare and
// RecordDependents, recording calls for assertions.
type fakePrepareCache struct {
	mu sync.Mutex

	prepared     []repocache.PreparedRepo
	prepareFn    func(context.Context, string, []repocache.RepoInfo) ([]repocache.PreparedRepo, error)
	prepareCalls int

	recordFn    func(string, repocache.Dependent) error
	recorded    []repocache.Dependent
	recordCalls int

	syncMu    sync.Mutex
	syncCalls int
}

func (c *fakePrepareCache) Lookup(string, string) string { return "" }
func (c *fakePrepareCache) BarePath(string, string) string {
	return ""
}
func (c *fakePrepareCache) Sync(string, []repocache.RepoInfo) error {
	c.syncMu.Lock()
	c.syncCalls++
	c.syncMu.Unlock()
	return nil
}
func (c *fakePrepareCache) WithRepoLock(_ string, fn func() error) error { return fn() }
func (c *fakePrepareCache) CreateWorktree(repocache.WorktreeParams) (*repocache.WorktreeResult, error) {
	return nil, nil
}

func (c *fakePrepareCache) Prepare(ctx context.Context, ws string, repos []repocache.RepoInfo) ([]repocache.PreparedRepo, error) {
	c.mu.Lock()
	c.prepareCalls++
	c.mu.Unlock()
	if c.prepareFn != nil {
		return c.prepareFn(ctx, ws, repos)
	}
	return c.prepared, nil
}

func (c *fakePrepareCache) RecordDependents(ws string, dep repocache.Dependent) error {
	c.mu.Lock()
	c.recordCalls++
	c.recorded = append(c.recorded, dep)
	c.mu.Unlock()
	if c.recordFn != nil {
		return c.recordFn(ws, dep)
	}
	return nil
}

func (c *fakePrepareCache) prepareCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.prepareCalls
}

func (c *fakePrepareCache) syncCount() int {
	c.syncMu.Lock()
	defer c.syncMu.Unlock()
	return c.syncCalls
}

func (c *fakePrepareCache) recordedDependents() []repocache.Dependent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]repocache.Dependent(nil), c.recorded...)
}

const fakeCommitSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// createBareRepoDir creates a minimal bare-repo directory (HEAD + objects) so
// filepath.EvalSymlinks in prepareTaskRepoCaches can resolve it.
func createBareRepoDir(t *testing.T, path string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(path, "objects", "info"), 0o755); err != nil {
		t.Fatalf("create bare repo objects: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatalf("write bare repo HEAD: %v", err)
	}
	return path
}

// newDockerTaskDaemon builds a daemon that will launch a codex attempt through
// a fake docker CLI that records its argv and emits a completed result. It
// returns the daemon, the workspaces root (so tests can seed caches under it),
// and the docker argv record path.
func newDockerTaskDaemon(t *testing.T, cache repoCacheBackend) (*Daemon, string, string) {
	t.Helper()
	workspacesRoot := t.TempDir()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	argvRecord := filepath.Join(t.TempDir(), "docker-argv")
	dockerBin := filepath.Join(t.TempDir(), "docker")
	dockerScript := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"" + argvRecord + "\"\nwhile [ $# -gt 0 ]; do case \"$1\" in multica/task-worker:test) shift; break;; *) shift;; esac; done\nread _\nprintf '%s\\n' '{\"type\":\"result\",\"result\":{\"Status\":\"completed\",\"Output\":\"ok\"}}'\n"
	writeTestExecutable(t, dockerBin, []byte(dockerScript))

	codexBin := filepath.Join(t.TempDir(), "codex")
	writeTestExecutable(t, codexBin, []byte("#!/bin/sh\nexit 0\n"))

	d := &Daemon{
		client:         NewClient(srv.URL),
		logger:         newDiscardLogger(),
		repoCache:      cache,
		workspaces:     map[string]*workspaceState{},
		activeEnvRoots: make(map[string]int),
		cfg: Config{
			WorkspacesRoot:     workspacesRoot,
			ServerBaseURL:      srv.URL,
			SandboxEnabled:     true,
			TaskSandboxBackend: "docker",
			DockerCLIPath:      dockerBin,
			DockerTaskImage:    "multica/task-worker:test",
			AgentTimeout:       10 * time.Second,
			Agents: map[string]AgentEntry{
				"codex": {Path: codexBin},
			},
		},
	}
	d.workspaces["ws-1"] = newWorkspaceState("ws-1", nil, "", nil, nil)
	return d, workspacesRoot, argvRecord
}

func dockerTask(id string, repos []RepoData) Task {
	return Task{
		ID:          id,
		WorkspaceID: "ws-1",
		AgentID:     "agent-1",
		AuthToken:   "mat_test",
		Agent:       &AgentData{ID: "agent-1", Name: "test-agent"},
		Repos:       repos,
	}
}

func readManifestRepos(t *testing.T, path string) []workercheckout.Entry {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest %s: %v", path, err)
	}
	var manifest workercheckout.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decode manifest %s: %v", path, err)
	}
	return manifest.Repos
}

func TestPrepareTaskRepoCachesRejectsPathOutsideWorkspaceCache(t *testing.T) {
	workspacesRoot := t.TempDir()
	workspaceID := "ws-1"
	cacheRoot := filepath.Join(workspacesRoot, ".repos", workspaceID)
	if err := os.MkdirAll(cacheRoot, 0o755); err != nil {
		t.Fatalf("mkdir cache root: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "outside.git")
	createBareRepoDir(t, outside)

	cache := &fakePrepareCache{prepared: []repocache.PreparedRepo{
		{URL: "https://example.com/a", CommitSHA: fakeCommitSHA, BarePath: outside},
	}}
	d := &Daemon{
		cfg:       Config{WorkspacesRoot: workspacesRoot},
		repoCache: cache,
		logger:    newDiscardLogger(),
	}

	_, err := d.prepareTaskRepoCaches(context.Background(), Task{
		WorkspaceID: workspaceID,
		Repos:       []RepoData{{URL: "https://example.com/a"}},
	})
	if err == nil {
		t.Fatal("expected prepareTaskRepoCaches to reject a bare path outside the workspace cache root")
	}
}

func TestRunTaskFailsWhenRepoCachePrepareFails(t *testing.T) {
	const repoURL = "https://example.com/broken.git"
	cache := &fakePrepareCache{prepareFn: func(context.Context, string, []repocache.RepoInfo) ([]repocache.PreparedRepo, error) {
		return nil, fmt.Errorf("fetch %s: connection refused", repoURL)
	}}
	d := &Daemon{
		cfg: Config{
			WorkspacesRoot:     t.TempDir(),
			SandboxEnabled:     true,
			TaskSandboxBackend: "docker",
		},
		repoCache:  cache,
		logger:     newDiscardLogger(),
		workspaces: map[string]*workspaceState{},
	}
	d.workspaces["ws-1"] = newWorkspaceState("ws-1", nil, "", nil, nil)

	task := Task{
		ID:          "task-1",
		WorkspaceID: "ws-1",
		AgentID:     "agent-1",
		Agent:       &AgentData{ID: "agent-1", Name: "test-agent"},
		Repos:       []RepoData{{URL: repoURL}},
	}

	_, err := d.runTask(context.Background(), task, "codex", 0, newDiscardLogger())
	if err == nil {
		t.Fatal("expected runTask to fail when repo cache prepare fails")
	}
	if !strings.Contains(err.Error(), repoURL) {
		t.Fatalf("error = %q, want it to name the repo URL %q", err, repoURL)
	}
	if cache.prepareCount() != 1 {
		t.Fatalf("Prepare called %d times, want 1", cache.prepareCount())
	}
}

func TestRunTaskWritesManifestAndRecordsDependents(t *testing.T) {
	cache := &fakePrepareCache{}
	d, workspacesRoot, argvRecord := newDockerTaskDaemon(t, cache)

	bare := createBareRepoDir(t, filepath.Join(workspacesRoot, ".repos", "ws-1", "repo-a.git"))
	const repoURL = "https://example.com/a"
	cache.prepared = []repocache.PreparedRepo{
		{URL: repoURL, CommitSHA: fakeCommitSHA, BarePath: bare},
	}

	result, err := d.runTask(context.Background(), dockerTask("task-1", []RepoData{{URL: repoURL}}), "codex", 0, newDiscardLogger())
	if err != nil {
		t.Fatalf("runTask: %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("runTask status = %q, want completed", result.Status)
	}

	repos := readManifestRepos(t, filepath.Join(result.EnvRoot, workercheckout.ManifestFileName))
	if len(repos) != 1 {
		t.Fatalf("manifest has %d repos, want 1", len(repos))
	}
	entry := repos[0]
	if entry.URL != repoURL || entry.CommitSHA != fakeCommitSHA || entry.CachePath != bare {
		t.Fatalf("manifest entry = %+v, want URL %q SHA %q CachePath %q", entry, repoURL, fakeCommitSHA, bare)
	}

	deps := cache.recordedDependents()
	if len(deps) != 1 {
		t.Fatalf("RecordDependents called with %d records, want 1", len(deps))
	}
	if deps[0].WorkDir != result.WorkDir {
		t.Fatalf("dependent WorkDir = %q, want %q", deps[0].WorkDir, result.WorkDir)
	}
	if len(deps[0].CachePaths) != 1 || deps[0].CachePaths[0] != bare {
		t.Fatalf("dependent CachePaths = %v, want [%q]", deps[0].CachePaths, bare)
	}

	raw, err := os.ReadFile(argvRecord)
	if err != nil {
		t.Fatalf("read docker argv: %v", err)
	}
	if !strings.Contains(string(raw), bare+":"+bare+":ro") {
		t.Fatalf("docker argv missing read-only cache bind %q:\n%s", bare+":"+bare+":ro", raw)
	}
}

func TestRunTaskFailsWhenRecordDependentsFails(t *testing.T) {
	cache := &fakePrepareCache{recordFn: func(string, repocache.Dependent) error {
		return errors.New("record boom")
	}}
	d, workspacesRoot, _ := newDockerTaskDaemon(t, cache)

	bare := createBareRepoDir(t, filepath.Join(workspacesRoot, ".repos", "ws-1", "repo-a.git"))
	cache.prepared = []repocache.PreparedRepo{{URL: "https://example.com/a", CommitSHA: fakeCommitSHA, BarePath: bare}}

	_, err := d.runTask(context.Background(), dockerTask("task-1", []RepoData{{URL: "https://example.com/a"}}), "codex", 0, newDiscardLogger())
	if err == nil || !strings.Contains(err.Error(), "record repo cache dependents") {
		t.Fatalf("err = %v, want a record-dependents failure", err)
	}
}

func TestRunTaskSkipsRepoCacheForBwrap(t *testing.T) {
	cache := &fakePrepareCache{}
	d := &Daemon{
		cfg: Config{
			WorkspacesRoot:     t.TempDir(),
			SandboxEnabled:     true,
			TaskSandboxBackend: "bwrap",
		},
		repoCache:  cache,
		logger:     newDiscardLogger(),
		workspaces: map[string]*workspaceState{},
	}
	d.workspaces["ws-1"] = newWorkspaceState("ws-1", nil, "", nil, nil)

	task := Task{
		ID:          "task-1",
		WorkspaceID: "ws-1",
		AgentID:     "agent-1",
		Agent:       &AgentData{ID: "agent-1", Name: "test-agent"},
		Repos:       []RepoData{{URL: "https://example.com/a"}},
	}

	// No codex agent is configured, so runTask returns early with a "no agent"
	// error — but only AFTER the registerTaskRepos + prepare/bg-sync branch has
	// decided to take the background-sync path.
	_, err := d.runTask(context.Background(), task, "codex", 0, newDiscardLogger())
	if err == nil || !strings.Contains(err.Error(), "no agent configured") {
		t.Fatalf("err = %v, want a no-agent-configured error", err)
	}
	d.waitBackgroundSyncs()

	if cache.prepareCount() != 0 {
		t.Fatalf("Prepare called %d times for a bwrap task, want 0", cache.prepareCount())
	}
	if cache.syncCount() == 0 {
		t.Fatal("background repo sync should still run for a bwrap task")
	}
}

func TestLocalDirectoryTaskKeepsCurrentFlow(t *testing.T) {
	cache := &fakePrepareCache{}
	d, _, _ := newDockerTaskDaemon(t, cache)

	// A local_directory task carries its path through ProjectResources, not
	// Repos, so task.Repos is empty and the repo-cache prepare/manifest path
	// must be a no-op that leaves the existing local-directory flow untouched.
	result, err := d.runTask(context.Background(), dockerTask("task-local", nil), "codex", 0, newDiscardLogger())
	if err != nil {
		t.Fatalf("runTask: %v", err)
	}
	if cache.prepareCount() != 0 {
		t.Fatalf("Prepare called %d times for a local-directory task, want 0", cache.prepareCount())
	}
	if _, err := os.Stat(filepath.Join(result.EnvRoot, workercheckout.ManifestFileName)); !os.IsNotExist(err) {
		t.Fatalf("expected no manifest for an empty-repos task, stat err = %v", err)
	}
	if deps := cache.recordedDependents(); len(deps) != 0 {
		t.Fatalf("expected no dependents record for an empty-repos task, got %v", deps)
	}
}

func TestTwoDockerTasksUseSeparateWorkdirsAndOneSharedCache(t *testing.T) {
	cache := &fakePrepareCache{}
	d, workspacesRoot, argvRecord := newDockerTaskDaemon(t, cache)

	bare := createBareRepoDir(t, filepath.Join(workspacesRoot, ".repos", "ws-1", "repo-a.git"))
	const repoURL = "https://example.com/a"
	cache.prepared = []repocache.PreparedRepo{
		{URL: repoURL, CommitSHA: fakeCommitSHA, BarePath: bare},
	}

	first, err := d.runTask(context.Background(), dockerTask("task-1", []RepoData{{URL: repoURL}}), "codex", 0, newDiscardLogger())
	if err != nil {
		t.Fatalf("first runTask: %v", err)
	}
	second, err := d.runTask(context.Background(), dockerTask("task-2", []RepoData{{URL: repoURL}}), "codex", 0, newDiscardLogger())
	if err != nil {
		t.Fatalf("second runTask: %v", err)
	}

	firstRepos := readManifestRepos(t, filepath.Join(first.EnvRoot, workercheckout.ManifestFileName))
	secondRepos := readManifestRepos(t, filepath.Join(second.EnvRoot, workercheckout.ManifestFileName))
	if len(firstRepos) != 1 || len(secondRepos) != 1 {
		t.Fatalf("manifest repos = %d and %d, want 1 each", len(firstRepos), len(secondRepos))
	}
	if firstRepos[0].CachePath != bare || secondRepos[0].CachePath != bare {
		t.Fatalf("cache paths = %q and %q, want both %q", firstRepos[0].CachePath, secondRepos[0].CachePath, bare)
	}
	if first.WorkDir == second.WorkDir {
		t.Fatalf("two tasks shared workdir %q; they must be separate", first.WorkDir)
	}

	raw, err := os.ReadFile(argvRecord)
	if err != nil {
		t.Fatalf("read docker argv: %v", err)
	}
	if !strings.Contains(string(raw), bare+":"+bare+":ro") {
		t.Fatalf("docker argv missing read-only cache bind %q:\n%s", bare+":"+bare+":ro", raw)
	}
}

func TestReusedWorkdirKeepsOldCacheMounted(t *testing.T) {
	workspacesRoot := t.TempDir()
	workspaceID := "ws-1"
	workDir := t.TempDir()

	oldCache := createBareRepoDir(t, filepath.Join(workspacesRoot, ".repos", workspaceID, "old-repo.git"))
	// A worker checkout points its alternates at <cache>/objects.
	alternates := filepath.Join(workDir, "oldrepo", ".git", "objects", "info", "alternates")
	if err := os.MkdirAll(filepath.Dir(alternates), 0o755); err != nil {
		t.Fatalf("mkdir alternates dir: %v", err)
	}
	if err := os.WriteFile(alternates, []byte(filepath.Join(oldCache, "objects")+"\n"), 0o644); err != nil {
		t.Fatalf("write alternates: %v", err)
	}

	d := &Daemon{cfg: Config{WorkspacesRoot: workspacesRoot}, logger: newDiscardLogger()}
	paths, err := d.repoCachePathsForReusedWorkdir(workspaceID, workDir)
	if err != nil {
		t.Fatalf("repoCachePathsForReusedWorkdir: %v", err)
	}
	want := filepath.Join(oldCache, "objects")
	if len(paths) != 1 || paths[0] != want {
		t.Fatalf("reused cache paths = %v, want [%q]", paths, want)
	}

	// The reused path is an extra read-only mount (not a manifest entry): build
	// a docker backend with only the extra path and confirm the ro bind.
	_, _, joined := dockerBackendArgv(t, nil, paths)
	if !strings.Contains(joined, want+":"+want+":ro") {
		t.Fatalf("docker argv missing reused-cache ro bind %q:\n%s", want+":"+want+":ro", joined)
	}
}

func TestReusedWorkdirIgnoresAlternatesOutsideCacheRoot(t *testing.T) {
	workspacesRoot := t.TempDir()
	workspaceID := "ws-1"
	workDir := t.TempDir()

	if err := os.MkdirAll(filepath.Join(workspacesRoot, ".repos", workspaceID), 0o755); err != nil {
		t.Fatalf("mkdir cache root: %v", err)
	}

	// Three alternates files: a /tmp path, a sibling workspace's cache, and one
	// valid path under this workspace's cache root.
	outsideTmp := createBareRepoDir(t, filepath.Join(t.TempDir(), "tmp-cache.git"))
	siblingCache := createBareRepoDir(t, filepath.Join(workspacesRoot, ".repos", "ws-sibling", "sibling.git"))
	ownCache := createBareRepoDir(t, filepath.Join(workspacesRoot, ".repos", workspaceID, "own.git"))

	type checkout struct {
		name string
		path string
	}
	checkouts := []checkout{
		{"tmp", filepath.Join(outsideTmp, "objects")},
		{"sibling", filepath.Join(siblingCache, "objects")},
		{"own", filepath.Join(ownCache, "objects")},
	}
	for _, c := range checkouts {
		alt := filepath.Join(workDir, c.name, ".git", "objects", "info", "alternates")
		if err := os.MkdirAll(filepath.Dir(alt), 0o755); err != nil {
			t.Fatalf("mkdir alternates dir: %v", err)
		}
		if err := os.WriteFile(alt, []byte(c.path+"\n"), 0o644); err != nil {
			t.Fatalf("write alternates: %v", err)
		}
	}

	d := &Daemon{cfg: Config{WorkspacesRoot: workspacesRoot}, logger: newDiscardLogger()}
	paths, err := d.repoCachePathsForReusedWorkdir(workspaceID, workDir)
	if err != nil {
		t.Fatalf("repoCachePathsForReusedWorkdir: %v", err)
	}
	want := filepath.Join(ownCache, "objects")
	if len(paths) != 1 || paths[0] != want {
		t.Fatalf("reused cache paths = %v, want only [%q]", paths, want)
	}
}
