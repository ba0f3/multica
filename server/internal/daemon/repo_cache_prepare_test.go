package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/multica-ai/multica/server/internal/daemon/repocache"
	"github.com/multica-ai/multica/server/internal/daemon/workercheckout"
)

func TestDockerRepoCacheUsesTaskSigningForNewPrivateRepo(t *testing.T) {
	for _, tc := range []struct {
		host string
		port int
	}{
		{"github.com", 22},
		{"git.r2d.dev", 2222},
	} {
		t.Run(tc.host, func(t *testing.T) { testDockerRepoCacheTaskSigning(t, tc.host, tc.port) })
	}
}

func TestGitHubNotFoundPrepareErrorExplainsHowToGrantAccess(t *testing.T) {
	err := fmt.Errorf("prepare repo https://github.com/ba0f3/xpfarm.git: git clone --bare: remote: Repository not found.\nfatal: repository not found: exit status 128")
	got := taskRepoPrepareError(Task{Repos: []RepoData{{URL: "https://github.com/ba0f3/xpfarm.git"}}}, err)
	for _, want := range []string{
		"Repository not found",
		"If it is private",
		"add its SSH public key to the GitHub account",
		"Check connection",
		"verify the repository URL",
	} {
		if !strings.Contains(got.Error(), want) {
			t.Errorf("taskRepoPrepareError() missing %q:\n%s", want, got)
		}
	}
	if !errors.Is(got, err) {
		t.Fatal("taskRepoPrepareError() did not preserve the underlying error")
	}
}

func TestGitHubNotFoundPrepareErrorLeavesOtherFailuresUnchanged(t *testing.T) {
	err := fmt.Errorf("prepare repo https://github.com/ba0f3/xpfarm.git: connection timeout")
	got := taskRepoPrepareError(Task{Repos: []RepoData{{URL: "https://github.com/ba0f3/xpfarm.git"}}}, err)
	if got != err {
		t.Fatalf("taskRepoPrepareError() = %v, want original error", got)
	}
}

func TestPrepareTaskRepoCachesDeduplicatesCanonicalCachePaths(t *testing.T) {
	workspacesRoot := t.TempDir()
	workspaceID := "ws-1"
	cacheRoot := filepath.Join(workspacesRoot, ".repos")
	realCache := repocache.New(cacheRoot, newDiscardLogger())
	barePath := realCache.BarePath(repocache.Scope{WorkspaceID: workspaceID, UserID: "test-user"}, "https://github.com/r2d-ai/multica.git")
	if err := os.MkdirAll(filepath.Dir(barePath), 0o755); err != nil {
		t.Fatal(err)
	}
	createBareRepoDir(t, barePath)
	cache := &fakePrepareCache{
		barePathFn: realCache.BarePath,
		prepareFn: func(_ context.Context, _ repocache.Scope, repos []repocache.RepoInfo) ([]repocache.PreparedRepo, error) {
			if len(repos) != 1 {
				t.Fatalf("Prepare received %d repos, want canonical duplicates collapsed to 1: %+v", len(repos), repos)
			}
			return []repocache.PreparedRepo{{URL: repos[0].URL, Ref: repos[0].Ref, CommitSHA: fakeCommitSHA, BarePath: barePath}}, nil
		},
	}
	d := &Daemon{
		cfg:       Config{WorkspacesRoot: workspacesRoot},
		repoCache: cache,
		logger:    newDiscardLogger(),
	}
	task := Task{ExecutionUserID: "test-user",
		WorkspaceID: workspaceID,
		Repos: []RepoData{
			{URL: "https://github.com/r2d-ai/multica.git", Ref: "main"},
			{URL: "git@github.com:r2d-ai/multica.git", Ref: "main"},
		},
	}

	entries, err := d.prepareTaskRepoCaches(context.Background(), task)
	if err != nil {
		t.Fatalf("prepareTaskRepoCaches: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("prepared entries = %d, want 1: %+v", len(entries), entries)
	}
}

func testDockerRepoCacheTaskSigning(t *testing.T, host string, port int) {
	t.Helper()
	if _, err := exec.LookPath("ssh-add"); err != nil {
		t.Skip("ssh-add is required to inspect the task signing socket")
	}
	profile, err := os.MkdirTemp("", "git-auth-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(profile) })
	t.Setenv("MULTICA_TASK_CONFIG_ROOT", profile)
	remote := t.TempDir()
	for _, args := range [][]string{
		{"init", "--initial-branch=main", remote},
		{"-C", remote, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "initial"},
	} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("seed private remote: %s: %v", out, err)
		}
	}
	_, private, err := generateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/git-signing-lease") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"lease_id": "lease-test", "public_key": string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
			})
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)
	sshScript := filepath.Join(t.TempDir(), "ssh")
	socketRecord := filepath.Join(t.TempDir(), "socket")
	writeTestExecutable(t, sshScript, []byte("#!/bin/sh\nset -eu\nif [ \"$1\" = -G ]; then exit 0; fi\nssh-add -L >/dev/null\nprintf '%s' \"$SSH_AUTH_SOCK\" > \"$TEST_SOCKET_RECORD\"\nprintf '%s\\n' \"$@\" > \"$TEST_SOCKET_RECORD.args\"\nexec git-upload-pack \"$TEST_PRIVATE_REMOTE\"\n"))
	t.Setenv("GIT_SSH_COMMAND", sshScript)
	t.Setenv("TEST_PRIVATE_REMOTE", remote)
	t.Setenv("TEST_SOCKET_RECORD", socketRecord)
	d, root, _ := newDockerTaskDaemon(t, nil)
	d.client = NewClient(server.URL)
	d.cfg.ServerBaseURL = server.URL
	d.repoCache = repocache.New(filepath.Join(root, ".repos"), newDiscardLogger())
	task := dockerTask("01a17196-8dad-7bc4-8d82-4b441e147f5e", []RepoData{{URL: "https://" + host + "/hai-tac/gms.git"}})
	task.GitIdentities = []GitIdentityBinding{{ProviderID: "provider", Host: host, Port: port}}
	task.GitSigningDaemonToken = "mdt_cache_fixture"
	result, err := d.runTask(context.Background(), task, "codex", 0, newDiscardLogger())
	if err != nil {
		t.Fatalf("cold private clone failed: %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("task status = %s", result.Status)
	}
	socket, err := os.ReadFile(socketRecord)
	if err != nil {
		t.Fatalf("SSH transport did not use the task socket: %v", err)
	}
	if _, err := os.Stat(string(socket)); !os.IsNotExist(err) {
		t.Fatalf("task socket was not cleaned up: %v", err)
	}
	if port != 22 {
		args, err := os.ReadFile(socketRecord + ".args")
		if err != nil || !strings.Contains(string(args), "\n-p\n"+fmt.Sprint(port)+"\n") {
			t.Fatalf("SSH did not use the provider port: %q, %v", args, err)
		}
	}
}

// fakePrepareCache is a repoCacheBackend that also implements Prepare and
// RecordDependents, recording calls for assertions.
type fakePrepareCache struct {
	mu sync.Mutex

	prepared     []repocache.PreparedRepo
	barePathFn   func(repocache.Scope, string) string
	prepareFn    func(context.Context, repocache.Scope, []repocache.RepoInfo) ([]repocache.PreparedRepo, error)
	prepareCalls int

	recordFn    func(repocache.Scope, repocache.Dependent) error
	recorded    []repocache.Dependent
	recordCalls int

	syncMu    sync.Mutex
	syncCalls int
}

func (c *fakePrepareCache) Lookup(repocache.Scope, string) string { return "" }
func (c *fakePrepareCache) BarePath(workspaceID repocache.Scope, url string) string {
	if c.barePathFn != nil {
		return c.barePathFn(workspaceID, url)
	}
	return ""
}
func (c *fakePrepareCache) Sync(repocache.Scope, []repocache.RepoInfo) error {
	c.syncMu.Lock()
	c.syncCalls++
	c.syncMu.Unlock()
	return nil
}
func (c *fakePrepareCache) WithRepoLock(_ string, fn func() error) error { return fn() }
func (c *fakePrepareCache) CreateWorktree(repocache.WorktreeParams) (*repocache.WorktreeResult, error) {
	return nil, nil
}

func (c *fakePrepareCache) Prepare(ctx context.Context, ws repocache.Scope, repos []repocache.RepoInfo) ([]repocache.PreparedRepo, error) {
	c.mu.Lock()
	c.prepareCalls++
	c.mu.Unlock()
	if c.prepareFn != nil {
		return c.prepareFn(ctx, ws, repos)
	}
	return c.prepared, nil
}

func (c *fakePrepareCache) RecordDependents(ws repocache.Scope, dep repocache.Dependent) error {
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
	dockerScript := "#!/bin/sh\nif [ \"$1\" != run ]; then exit 0; fi\nprintf '%s\\n' \"$@\" > \"" + argvRecord + "\"\nwhile [ $# -gt 0 ]; do case \"$1\" in multica/task-worker:test) shift; break;; *) shift;; esac; done\nread _\nprintf '%s\\n' '{\"type\":\"result\",\"result\":{\"Status\":\"completed\",\"Output\":\"ok\"}}'\n"
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
	return Task{ExecutionUserID: "test-user",
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
	cacheRoot := filepath.Join(workspacesRoot, ".repos", workspaceID, "test-user")
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

	_, err := d.prepareTaskRepoCaches(context.Background(), Task{ExecutionUserID: "test-user",
		WorkspaceID: workspaceID,
		Repos:       []RepoData{{URL: "https://example.com/a"}},
	})
	if err == nil {
		t.Fatal("expected prepareTaskRepoCaches to reject a bare path outside the workspace cache root")
	}
}

func TestRunTaskFailsWhenRepoCachePrepareFails(t *testing.T) {
	const repoURL = "https://example.com/broken.git"
	cache := &fakePrepareCache{prepareFn: func(context.Context, repocache.Scope, []repocache.RepoInfo) ([]repocache.PreparedRepo, error) {
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

	task := Task{ExecutionUserID: "test-user",
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

	bare := createBareRepoDir(t, filepath.Join(workspacesRoot, ".repos", "ws-1", "test-user", "repo-a.git"))
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
	cache := &fakePrepareCache{recordFn: func(repocache.Scope, repocache.Dependent) error {
		return errors.New("record boom")
	}}
	d, workspacesRoot, _ := newDockerTaskDaemon(t, cache)

	bare := createBareRepoDir(t, filepath.Join(workspacesRoot, ".repos", "ws-1", "test-user", "repo-a.git"))
	cache.prepared = []repocache.PreparedRepo{{URL: "https://example.com/a", CommitSHA: fakeCommitSHA, BarePath: bare}}

	_, err := d.runTask(context.Background(), dockerTask("task-1", []RepoData{{URL: "https://example.com/a"}}), "codex", 0, newDiscardLogger())
	if err == nil || !strings.Contains(err.Error(), "record repo cache dependents") {
		t.Fatalf("err = %v, want a record-dependents failure", err)
	}
}

func TestRunTaskPreparesRepoCacheForBwrap(t *testing.T) {
	expected := errors.New("native fetch fixture failed")
	cache := &fakePrepareCache{prepareFn: func(context.Context, repocache.Scope, []repocache.RepoInfo) ([]repocache.PreparedRepo, error) {
		return nil, expected
	}}
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

	task := Task{ExecutionUserID: "test-user",
		ID:          "task-1",
		WorkspaceID: "ws-1",
		AgentID:     "agent-1",
		Agent:       &AgentData{ID: "agent-1", Name: "test-agent"},
		Repos:       []RepoData{{URL: "https://example.com/a"}},
	}

	if err := os.MkdirAll(filepath.Join(d.cfg.WorkspacesRoot, ".repos"), 0700); err != nil {
		t.Fatal(err)
	}
	_, err := d.runTask(context.Background(), task, "codex", 0, newDiscardLogger())
	if !errors.Is(err, expected) {
		t.Fatalf("native fetch did not fail before agent execution: %v", err)
	}
	d.waitBackgroundSyncs()
	if cache.prepareCount() != 1 || cache.syncCount() != 0 {
		t.Fatalf("native cache prepare=%d, sync=%d", cache.prepareCount(), cache.syncCount())
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

	bare := createBareRepoDir(t, filepath.Join(workspacesRoot, ".repos", "ws-1", "test-user", "repo-a.git"))
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

	oldCache := createBareRepoDir(t, filepath.Join(workspacesRoot, ".repos", workspaceID, "test-user", "old-repo.git"))
	// A worker checkout points its alternates at <cache>/objects.
	alternates := filepath.Join(workDir, "oldrepo", ".git", "objects", "info", "alternates")
	if err := os.MkdirAll(filepath.Dir(alternates), 0o755); err != nil {
		t.Fatalf("mkdir alternates dir: %v", err)
	}
	if err := os.WriteFile(alternates, []byte(filepath.Join(oldCache, "objects")+"\n"), 0o644); err != nil {
		t.Fatalf("write alternates: %v", err)
	}

	d := &Daemon{cfg: Config{WorkspacesRoot: workspacesRoot}, logger: newDiscardLogger()}
	paths, err := d.repoCachePathsForReusedWorkdir(repocache.Scope{WorkspaceID: workspaceID, UserID: "test-user"}, workDir)
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

func TestReusedWorkdirReturnsRawAlternatesPath(t *testing.T) {
	// A cache root that sits behind a symlink: the checkout's alternates file
	// names the cache through the symlinked spelling, and the mount/dependents
	// set must keep that raw spelling rather than the resolved target, or the
	// reused checkout breaks when the worker no longer sees the referenced path.
	realRoot := t.TempDir()
	createBareRepoDir(t, filepath.Join(realRoot, ".repos", "ws-1", "test-user", "old-repo.git"))

	linkRoot := filepath.Join(t.TempDir(), "workspaces-link")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	workDir := t.TempDir()
	altPath := filepath.Join(linkRoot, ".repos", "ws-1", "test-user", "old-repo.git", "objects")
	alternates := filepath.Join(workDir, "oldrepo", ".git", "objects", "info", "alternates")
	if err := os.MkdirAll(filepath.Dir(alternates), 0o755); err != nil {
		t.Fatalf("mkdir alternates dir: %v", err)
	}
	if err := os.WriteFile(alternates, []byte(altPath+"\n"), 0o644); err != nil {
		t.Fatalf("write alternates: %v", err)
	}

	d := &Daemon{cfg: Config{WorkspacesRoot: linkRoot}, logger: newDiscardLogger()}
	paths, err := d.repoCachePathsForReusedWorkdir(repocache.Scope{WorkspaceID: "ws-1", UserID: "test-user"}, workDir)
	if err != nil {
		t.Fatalf("repoCachePathsForReusedWorkdir: %v", err)
	}
	if len(paths) != 1 || paths[0] != altPath {
		t.Fatalf("reused cache paths = %v, want the raw alternates path [%q]", paths, altPath)
	}
	// The returned raw path must still pass the strict-child boundary against
	// the resolved cache root.
	resolvedRoot, err := filepath.EvalSymlinks(filepath.Join(linkRoot, ".repos", "ws-1", "test-user"))
	if err != nil {
		t.Fatalf("eval symlinks cache root: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(paths[0])
	if err != nil {
		t.Fatalf("eval symlinks returned path: %v", err)
	}
	if !isStrictChild(resolved, resolvedRoot) {
		t.Fatalf("raw path %q resolves to %q, not a strict child of %q", paths[0], resolved, resolvedRoot)
	}
}

func TestReusedWorkdirIgnoresAlternatesOutsideCacheRoot(t *testing.T) {
	workspacesRoot := t.TempDir()
	workspaceID := "ws-1"
	workDir := t.TempDir()

	if err := os.MkdirAll(filepath.Join(workspacesRoot, ".repos", workspaceID, "test-user"), 0o755); err != nil {
		t.Fatalf("mkdir cache root: %v", err)
	}

	// Three alternates files: a /tmp path, a sibling workspace's cache, and one
	// valid path under this workspace's cache root.
	outsideTmp := createBareRepoDir(t, filepath.Join(t.TempDir(), "tmp-cache.git"))
	siblingCache := createBareRepoDir(t, filepath.Join(workspacesRoot, ".repos", "ws-sibling", "sibling.git"))
	ownCache := createBareRepoDir(t, filepath.Join(workspacesRoot, ".repos", workspaceID, "test-user", "own.git"))

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
	paths, err := d.repoCachePathsForReusedWorkdir(repocache.Scope{WorkspaceID: workspaceID, UserID: "test-user"}, workDir)
	if err != nil {
		t.Fatalf("repoCachePathsForReusedWorkdir: %v", err)
	}
	want := filepath.Join(ownCache, "objects")
	if len(paths) != 1 || paths[0] != want {
		t.Fatalf("reused cache paths = %v, want only [%q]", paths, want)
	}
}

func TestHostCodeTaskRequiresProvenExecutionUser(t *testing.T) {
	d, _, _ := newDockerTaskDaemon(t, &fakePrepareCache{})
	d.cfg.SandboxEnabled = false
	task := dockerTask("missing-user", []RepoData{{URL: "https://example.test/repo.git"}})
	task.ExecutionUserID = ""
	_, err := d.runTask(context.Background(), task, "codex", 0, newDiscardLogger())
	d.waitBackgroundSyncs()
	if err == nil || !strings.Contains(err.Error(), "execution user") {
		t.Fatalf("task without owner was not rejected at ownership boundary: %v", err)
	}
}

func TestReusedWorkdirCannotUseAliasedUserStore(t *testing.T) {
	root := t.TempDir()
	bob := filepath.Join(root, ".repos", "ws-1", "bob")
	objects := filepath.Join(bob, "repo.git", "objects")
	if err := os.MkdirAll(objects, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bob, filepath.Join(root, ".repos", "ws-1", "alice")); err != nil {
		t.Skip(err)
	}
	work := t.TempDir()
	alternate := filepath.Join(work, "repo", ".git", "objects", "info", "alternates")
	if err := os.MkdirAll(filepath.Dir(alternate), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(alternate, []byte(objects+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{cfg: Config{WorkspacesRoot: root}, logger: newDiscardLogger()}
	paths, err := d.repoCachePathsForReusedWorkdir(repocache.Scope{WorkspaceID: "ws-1", UserID: "alice"}, work)
	if err == nil && len(paths) > 0 {
		t.Fatalf("Alice admitted Bob's cache through a user-store symlink: %v", paths)
	}
}

func TestConcurrentUsersReceiveSeparateTaskCaches(t *testing.T) {
	d, root, _ := newDockerTaskDaemon(t, nil)
	d.repoCache = repocache.New(filepath.Join(root, ".repos"), newDiscardLogger())
	remote := createGCGitRepo(t)
	results := make(chan error, 2)
	for _, user := range []string{"alice", "bob"} {
		go func() {
			task := dockerTask("task-"+user, []RepoData{{URL: remote}})
			task.ExecutionUserID = user
			result, err := d.runTask(context.Background(), task, "codex", 0, newDiscardLogger())
			if err == nil && result.Status != "completed" {
				err = fmt.Errorf("task status %s", result.Status)
			}
			results <- err
		}()
	}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	alice := d.repoCache.Lookup(repocache.Scope{WorkspaceID: "ws-1", UserID: "alice"}, remote)
	bob := d.repoCache.Lookup(repocache.Scope{WorkspaceID: "ws-1", UserID: "bob"}, remote)
	if alice == "" || bob == "" || alice == bob {
		t.Fatalf("tasks did not create separate user bases: Alice=%s Bob=%s", alice, bob)
	}
}
