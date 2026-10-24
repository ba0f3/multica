# Repo Cache for Docker Workers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let Docker-isolated task attempts check out task repos from a freshly-fetched, read-only bare cache instead of cloning full history from the remote on every task.

**Architecture:** The daemon prepares each `task.Repos` repo before launch: clone on a cold cache, fetch, resolve the requested ref to a commit SHA, then pass the SHA and the host cache path to the worker through a task-scoped, read-only manifest file. Only the individual bare caches for this task are bind-mounted (`<cache>:<cache>:ro`, same absolute path so Git alternates and host-side inspection agree). `multica repo checkout` inside the worker initializes a private checkout in the task workdir, points `objects/info/alternates` at the mounted cache, sets `origin` to the real URL, and copies the cache's remote refs; it never contacts the host daemon. Reused workdirs are kept without reset, and report ahead/behind against the freshly resolved SHA. Dependents records on disk keep the cache alive across daemon restarts, and GC skips eviction/prune while any dependent workdir exists.

**Tech Stack:** Go (daemon, CLI, `pkg/agent`), Docker CLI, Git, systemd user units.

**Spec:** [docs/superpowers/specs/2026-10-25-repo-cache-docker-worker.md](docs/superpowers/specs/2026-10-25-repo-cache-docker-worker.md)

## Global Constraints

- Scope is `task.Repos` only. `local_directory` tasks keep their current host-worktree flow.
- Every task keeps its own writable workdir; never mount a shared checkout.
- Freshness: prepare clones on a cold cache, fetches every task repo, and resolves the requested ref to a commit SHA before launch. A fetch or ref-resolution failure fails the task; never fall back to a stale cache.
- Mount only the bare caches of this task's repos, read-only. The manifest is written by the daemon, not the worker, and records `url`, `ref`, `commit_sha`, and `cache_path`.
- `multica repo checkout <url>` inside the worker uses that manifest, creates a private `.git` in the workdir, sets `origin` to the real URL, and keeps commit/fetch/push inside the container through the per-attempt SSH socket. The host daemon checkout endpoint stays blocked for isolated tasks.
- Alternates are allowed. The cache stays until every dependent workdir is gone, including across daemon restarts. GC must not prune/repack while a dependent exists. The worker must not hardlink or otherwise write cache objects.
- Reuse: keep uncommitted changes and unpushed commits; do not reset to the new SHA. Report how far the branch is ahead/behind the new SHA.
- Cold cache still downloads the repo once; warm tasks must not re-download full history.
- The Docker worker trusts a CA bundle built by the daemon: the repo cache's current Git trust plus the optional host file `MULTICA_DOCKER_TASK_CA_BUNDLE`. The bundle is mounted read-only and exported through the standard CA env vars; a configured but unreadable/invalid bundle fails the task.
- Docker only for this change. The bwrap path keeps today's behavior.
- Run `gofmt` on changed Go files. Keep comments English. Use conventional commits, one per task.
- Verification floor for every task: `cd server && go test ./internal/daemon/... -count=1` plus the task's narrower command.

## Review Focus

- A cache path outside `task.Repos` or outside `<workspaces-root>/.repos/<workspace-id>/`, including a symlinked path, is mounted into a worker. Expected: prepare/launch refuses. Covered by Task 5 and Task 6.
- A live workdir's alternate is evicted or pruned by GC. Expected: the checkout keeps working after a daemon restart and after a GC cycle. Covered by Task 9.
- Fetch or ref resolution fails and the task silently runs on an old cache. Expected: the task fails before launch with the repo URL and cause. Covered by Task 1 and Task 6.
- A reused workdir with a dirty tree or unpushed commit is reset to the new SHA. Expected: work is preserved and divergence is reported. Covered by Task 4 and Task 8.
- The worker writes to the cache through a hardlink or a writable mount. Expected: no hardlinks, cache unchanged, bind is `:ro`. Covered by Task 4 and Task 5.
- A configured CA bundle is missing, not a PEM certificate, or does not include the host's existing trust. Expected: the task fails before launch with the path, or the worker's bundle contains both machine trust and the extra CA. Covered by Task 9.

---

### Task 1: Strict repo-cache prepare

**Files:**
- Modify: `server/internal/daemon/repocache/cache.go:167` (`RepoInfo`)
- Create: `server/internal/daemon/repocache/prepare.go`
- Test: `server/internal/daemon/repocache/prepare_test.go`
- Modify: `server/internal/daemon/daemon.go` (`repoDataToInfo`)

**Interfaces:**
- Consumes: `Cache.BarePath(workspaceID, url)`, `gitFetchContext`, `gitCloneBareContext`, `resolveBaseRefContext`, `resolveCommitContext`.
- Produces:
  ```go
  type RepoInfo struct {
      URL string
      Ref string
  }

  type PreparedRepo struct {
      URL       string
      Ref       string // requested ref; empty means the remote default branch
      CommitSHA string
      BarePath  string // absolute host path of the bare cache
  }

  func (c *Cache) Prepare(ctx context.Context, workspaceID string, repos []RepoInfo) ([]PreparedRepo, error)
  ```

- [ ] **Step 1: Write the failing tests**

Use the existing `createTestRepoAt` helper for a local remote. Add table cases asserting:

```go
// cold cache: no prior clone
got, err := cache.Prepare(ctx, "ws-1", []RepoInfo{{URL: remote}})
// err == nil, len(got) == 1, got[0].BarePath == cache.BarePath("ws-1", remote),
// got[0].CommitSHA is the remote HEAD, and the bare cache exists.

// warm cache: push a new commit and call Prepare again
// got[0].CommitSHA changed to the new commit SHA.

// requested ref: pass Ref: "feature" and assert the SHA is that branch tip.

// fetch failure: after the first Prepare, remove the remote directory and call
// Prepare again; err must contain the repo URL and must not return the old SHA.

// unknown ref: Ref "missing" returns an error containing `cannot resolve requested ref`.

// cold-clone failure: a nonexistent URL returns an error and leaves no PreparedRepo.
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd server && go test ./internal/daemon/repocache -run 'TestPrepare' -count=1`
Expected: FAIL with `cache.Prepare undefined`.

- [ ] **Step 3: Implement `Prepare` and add `Ref` to `RepoInfo`**

`Prepare` works per repo, under the repo lock:
1. `barePath := c.BarePath(workspaceID, url)`.
2. If `isBareRepo(barePath)`, run `gitFetchContext(ctx, barePath)`; otherwise run `gitCloneBareContext(ctx, url, barePath)`.
3. Return the wrapped error immediately on failure, naming the URL.
4. `baseRef, err := resolveBaseRefContext(ctx, barePath, repo.Ref)`; then `sha, err := resolveCommitContext(ctx, barePath, baseRef)`.
5. Append `PreparedRepo{URL, Ref: repo.Ref, CommitSHA: sha, BarePath: barePath}`.
6. Empty/invalid URLs and empty workspace IDs return an error; an empty input slice returns `nil, nil`.

Update `repoDataToInfo` so `RepoInfo.Ref` carries `RepoData.Ref`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd server && go test ./internal/daemon/repocache -run 'TestPrepare' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add server/internal/daemon/repocache/cache.go server/internal/daemon/repocache/prepare.go server/internal/daemon/repocache/prepare_test.go server/internal/daemon/daemon.go
git commit -m "feat(repocache): prepare task repos with a strict fetch and resolved SHA"
```

---

### Task 2: Durable dependents records

**Files:**
- Create: `server/internal/daemon/repocache/dependents.go`
- Test: `server/internal/daemon/repocache/dependents_test.go`

**Interfaces:**
- Consumes: `Cache.root`, `workspaceID`.
- Produces:
  ```go
  type Dependent struct {
      WorkDir    string   `json:"workdir"`
      CachePaths []string `json:"cache_paths"`
      TaskID     string   `json:"task_id,omitempty"`
      AttemptID  string   `json:"attempt_id,omitempty"`
  }

  func (c *Cache) RecordDependents(workspaceID string, dep Dependent) error
  func (c *Cache) LiveDependentCachePaths() (map[string]struct{}, error)
  ```

- [ ] **Step 1: Write the failing tests**

```go
// RecordDependents writes <root>/<ws>/.dependents/<sha256(workdir)[:16]>.json
// with mode 0600, and a second call for the same WorkDir replaces it.

// LiveDependentCachePaths returns every CachePath for a record whose WorkDir
// still exists.

// After os.RemoveAll(workdir), a new Cache instance over the same root returns
// an empty set and removes the stale record (restart behavior).

// RecordDependents rejects a relative WorkDir and relative CachePaths.

// A malformed record is ignored without failing the scan.
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd server && go test ./internal/daemon/repocache -run 'TestDependents|TestLiveDependent' -count=1`
Expected: FAIL with `undefined: RecordDependents`.

- [ ] **Step 3: Implement the records**

- `RecordDependents`: validate absolute, cleaned paths; `os.MkdirAll(<root>/<ws>/.dependents, 0o700)`; marshal; write a temp file with `0o600` and rename.
- `LiveDependentCachePaths`: read `<root>/*/.dependents/*.json`; for each record, `os.Stat(workdir)`; on `IsNotExist` remove the record and continue; otherwise add every cleaned `CachePath`. Ignore malformed files after returning their path in the error value? Choose: skip malformed records but keep scanning; return nil error. The caller uses the set to *retain*, so a skipped record can only shorten retention; tests must cover the well-formed path. Malformed files are daemon-written and indicate corruption; log is not available here, so return them in a second error only if the directory read fails.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd server && go test ./internal/daemon/repocache -run 'TestDependents|TestLiveDependent' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add server/internal/daemon/repocache/dependents.go server/internal/daemon/repocache/dependents_test.go
git commit -m "feat(repocache): track workdirs that depend on a bare cache"
```

---

### Task 3: Task repo manifest file

**Files:**
- Create: `server/internal/daemon/workercheckout/manifest.go`
- Test: `server/internal/daemon/workercheckout/manifest_test.go`

**Interfaces:**
- Consumes: `MULTICA_TASK_CONFIG_ROOT`, `$HOME`.
- Produces:
  ```go
  const ManifestFileName = "repo-cache.json"

  type Entry struct {
      URL       string `json:"url"`
      Ref       string `json:"ref,omitempty"`
      CommitSHA string `json:"commit_sha"`
      CachePath string `json:"cache_path"`
  }

  type Manifest struct {
      Repos []Entry `json:"repos"`
  }

  func ManifestPath() (string, error)
  func WriteManifest(path string, manifest Manifest) error
  func ReadManifest(path string) (Manifest, error)
  func Find(manifest Manifest, url string) (Entry, error)
  func ValidateEntry(entry Entry) error
  ```

- [ ] **Step 1: Write the failing tests**

```go
// ManifestPath uses MULTICA_TASK_CONFIG_ROOT when set and absolute, otherwise
// $HOME/.multica.

// WriteManifest then ReadManifest round-trips URL, Ref, CommitSHA, CachePath.

// ReadManifest rejects JSON with an unknown field and a relative CachePath.

// Find returns the exact URL entry and an error naming the allowed URLs for an
// unknown URL.

// ValidateEntry rejects a missing/relative CachePath, a cache dir without HEAD
// or objects, and a non-hex CommitSHA. It accepts a real bare repo.
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd server && go test ./internal/daemon/workercheckout -run 'TestManifest|TestFind|TestValidateEntry' -count=1`
Expected: FAIL with `no Go files` / undefined symbols.

- [ ] **Step 3: Implement the manifest**

- `ManifestPath`: read `MULTICA_TASK_CONFIG_ROOT`; if empty, `os.UserHomeDir()` + `.multica`; join `ManifestFileName`.
- `WriteManifest`: marshal, write temp with `0o644`, rename. The file is bind-mounted read-only; `0o644` keeps it readable when `MULTICA_DOCKER_TASK_USER` is set to a fixed non-root user.
- `ReadManifest`: `json.Decoder` with `DisallowUnknownFields`; call `ValidateEntry` for every entry.
- `ValidateEntry`: `filepath.IsAbs`, `filepath.Clean(path) == path`, `os.Stat(CachePath)` is a directory, `HEAD` and `objects` exist, `CommitSHA` is 40 or 64 lowercase hex.
- `Find`: exact string match; dedupe is not needed, duplicate URLs are a manifest bug but `Find` returns the first.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd server && go test ./internal/daemon/workercheckout -run 'TestManifest|TestFind|TestValidateEntry' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add server/internal/daemon/workercheckout/manifest.go server/internal/daemon/workercheckout/manifest_test.go
git commit -m "feat(workercheckout): add the task repo cache manifest"
```

---

### Task 4: In-worker checkout with alternates

**Files:**
- Create: `server/internal/daemon/workercheckout/checkout.go`
- Test: `server/internal/daemon/workercheckout/checkout_test.go`
- Create: `server/internal/daemon/workercheckout/bench_test.go`
- Modify: `server/internal/daemon/repocache/cache.go` (export `RepoDirName`, `BranchName`)

**Interfaces:**
- Consumes: `Entry`, `repocache.RepoDirName`, `repocache.BranchName`.
- Produces:
  ```go
  type Options struct {
      Ref       string
      Fresh     bool
      AgentName string
      TaskID    string
  }

  type Result struct {
      Path        string
      Branch      string
      BaseSHA     string
      Kept        bool
      Ahead       int
      Behind      int
      Uncommitted int
      Unpushed    int
  }

  func Checkout(ctx context.Context, workDir string, entry Entry, opts Options) (Result, error)
  ```

- [ ] **Step 1: Write the failing tests**

```go
// TestCheckoutInitializesFromCacheWithoutNetwork:
// entry.URL points at a nonexistent remote, but entry.CachePath is a real bare
// cache holding CommitSHA. Checkout succeeds, .git/objects/info/alternates is
// <CachePath>/objects, origin is entry.URL, and HEAD is CommitSHA.

// TestCheckoutDoesNotHardlink:
// the checkout's object files have nlink == 1; a before/after hash of the
// cache's objects directory is unchanged.

// TestCheckoutCopiesCacheRefs:
// refs/remotes/origin/<default> exists in the checkout (agents diff against it).

// TestCheckoutKeepsDirtyAndUnpushed:
// first Checkout at SHA1; create an unpushed commit and a dirty file; update the
// cache to SHA2; Checkout with SHA2 returns Kept=true, Ahead=1, Behind=1,
// Uncommitted=1, Unpushed=1; the commit and dirty file still exist; HEAD did not
// move to SHA2.

// TestCheckoutFreshDiscards:
// same setup with Options{Fresh:true}; dirty/untracked files are gone and HEAD
// is SHA2.

// TestCheckoutRefOverrideFetches:
// entry.Ref is empty; Options.Ref names a branch newer than the cache; Checkout
// fetches it from the real origin (a local bare remote) and uses its SHA.

// TestCheckoutRejectsForeignOrigin:
// an existing checkout whose origin is another URL returns an error.

// TestCheckoutRejectsBarePath:
// entry.CachePath points at a normal worktree, not a bare repo; error.

// TestCheckoutsShareCacheWithoutCrossTalk:
// two workdirs check out the same entry; a commit and a dirty file in A do not
// appear in B, B's branch/HEAD are independent, and the cache's object files
// are byte-identical and have nlink == 1 after both checkouts.
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd server && go test ./internal/daemon/workercheckout -run 'TestCheckout' -count=1`
Expected: FAIL with `undefined: Checkout`.

- [ ] **Step 3: Implement the checkout**

For a new checkout (target `<workDir>/<RepoDirName(entry.URL)>`):
1. `os.MkdirAll(target, 0o755)`; `git init -q target`.
2. `git -C target remote add origin <entry.URL>`.
3. Write `<target>/.git/objects/info/alternates` as `<entry.CachePath>/objects` plus a newline.
4. Copy cache refs: `git -C cache for-each-ref --format=%(refname) %(objectname) refs/remotes/origin refs/tags`; for each, `git -C target update-ref <ref> <sha>`. Skip symbolic refs.
5. `git -C target checkout -q -B <repocache.BranchName(opts.AgentName, opts.TaskID)> <sha>` where `<sha>` is `opts.Ref` resolved (see below) or `entry.CommitSHA`.
6. If `opts.Ref` is non-empty: try `git -C target rev-parse --verify <ref>^{commit}` first; if it fails, `git -C target fetch --no-tags origin <ref>` then resolve. Never use the network for the default path.

For an existing checkout:
1. Require `<target>/.git`; resolve `origin`; if it differs from `entry.URL`, error.
2. If `opts.Fresh`, run `git reset --hard`, `git clean -fdx`, then `checkout -B` the new SHA.
3. Otherwise compute:
   - `git rev-list --left-right --count HEAD...<sha>` → ahead, behind.
   - `git status --porcelain` line count → uncommitted.
   - `git rev-list --count --not --remotes HEAD` → unpushed.
4. Keep `HEAD`, branch, index, and worktree exactly as they are.

Export from `repocache`:
```go
func RepoDirName(url string) string { return repoNameFromURL(url) }
func BranchName(agentName, taskID string) string {
    return fmt.Sprintf("agent/%s/%s", sanitizeName(agentName), taskKey(taskID))
}
```
and use `BranchName` in `CreateWorktree` so host and worker branch names stay identical.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd server && go test ./internal/daemon/workercheckout -run 'TestCheckout' -count=1`
Expected: PASS.

- [ ] **Step 5: Add the cold/warm benchmark**

`BenchmarkRepoCacheCheckout` creates a local bare remote with 2,000 commits (use `git fast-import`; skip the benchmark if the import fails). Sub-benchmarks:

- `cold`: empty cache root → `repoCache.Prepare` (clone) → `Checkout` → write 10 files in the worktree.
- `warm`: pre-populated cache → `Prepare` (fetch, no changes) → `Checkout` → write 10 files.

Measure each phase with `time.Since` and report `fetch_ms`, `checkout_ms`, `write_ms` via `b.ReportMetric` (per-op). Reset the workdir outside the timer.

- [ ] **Step 6: Run the benchmark once and record the numbers**

Run: `cd server && go test ./internal/daemon/workercheckout -run '^$' -bench BenchmarkRepoCacheCheckout -benchtime 3x -count=1`
Expected: PASS and prints `cold`/`warm` fetch/checkout/write metrics. Paste the output into the task commit message body or the PR description; do not gate CI on the numbers.

- [ ] **Step 7: Commit**

```bash
git add server/internal/daemon/workercheckout/checkout.go server/internal/daemon/workercheckout/checkout_test.go server/internal/daemon/workercheckout/bench_test.go server/internal/daemon/repocache/cache.go
git commit -m "feat(workercheckout): check out from the shared cache with alternates"
```

---

### Task 5: Mount the cache read-only and expose the manifest

**Files:**
- Modify: `server/internal/daemon/sandbox/container_env.go`
- Modify: `server/internal/daemon/sandbox_launch_docker.go`
- Modify: `server/internal/daemon/daemon.go` (marker ordering; manifest write)
- Test: `server/internal/daemon/sandbox_launch_docker_test.go`
- Test: `server/internal/daemon/sandbox/container_env_test.go` (create)

**Interfaces:**
- Consumes: `workercheckout.Entry`, `env.RootDir`, `env.MulticaConfigRoot`.
- Produces:
  ```go
  // sandbox
  const RepoManifestPath = HomePath + "/.multica/" + workercheckout.ManifestFileName

  func DockerRepoCacheBinds(repos []workercheckout.Entry, extraCachePaths []string) ([]string, error)
  ```
- `DockerRepoCacheBinds` returns one `DockerBind(path, path, "ro")` per unique absolute, cleaned cache path from both arguments; relative or `..`-containing paths return an error.

- [ ] **Step 1: Write the failing tests**

```go
// TestDockerBackendMountsRepoCacheReadOnly: fake docker argv contains
// "-v", "<cache>:<cache>:ro" for each entry, the manifest file is bound
// "-v", "<env.RootDir>/repo-cache.json:/home/agent/.multica/repo-cache.json:ro",
// and no sibling repo under .repos is mounted.

// TestDockerBackendRejectsRepoCacheOverlappingWorkdir: a cache path equal to or
// inside env.WorkDir / home / tmp returns an error before docker starts.

// TestContainerEnvRewritesTaskConfigRoot: MULTICA_TASK_CONFIG_ROOT becomes
// /home/agent/.multica, and MULTICA_ISOLATED_TOOL_BOUNDARY=1 plus
// MULTICA_HOST_REPO_CHECKOUT=disabled are present.

// TestIsolatedMarkersReachDockerEnv: the daemon sets the markers before
// sandboxedBackend; the fake docker argv contains -e for both keys.
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd server && go test ./internal/daemon -run 'TestDockerBackendMountsRepoCache' -count=1`
Expected: FAIL with `undefined: DockerRepoCacheBinds`.

- [ ] **Step 3: Implement the mounts and manifest bind**

Change `sandboxedBackend(provider, config, env, profileDir, agentSocket, attemptID, repos []workercheckout.Entry, extraCachePaths []string)` and `dockerBackend(..., repos, extraCachePaths)`. Update every call site (including `sandbox_launch_test.go` and `sandbox_launch_docker_test.go`) to pass `nil, nil` for now; Task 6 passes the prepared entries and reused-workdir cache paths.

In `dockerBackend`:
- Build `binds` as today.
- Append the result of `sandbox.DockerRepoCacheBinds(repos, extraCachePaths)`; on error return `errSandboxUnavailable`.
- If `len(repos) > 0`, require `env.MulticaConfigRoot != ""` and append `sandbox.DockerBind(filepath.Join(env.RootDir, workercheckout.ManifestFileName), sandbox.RepoManifestPath, "ro")` **after** `DockerConfigBinds` (the `.multica` parent must exist first).
- Reject a cache path that equals or contains `env.WorkDir`, `homeDir`, `tempDir`, or `env.MulticaConfigRoot`, and vice versa; return `errSandboxUnavailable`.

In `ContainerEnv`:
- Rewrite `MULTICA_TASK_CONFIG_ROOT` (and keep `MULTICA_CONFIG_ROOT`) to `/home/agent/.multica`.
- Set `MULTICA_ISOLATED_TOOL_BOUNDARY=1` and `MULTICA_HOST_REPO_CHECKOUT=disabled`. This is the Docker path and must be true even when the daemon's later assignment is reordered; Task 6 also moves the daemon assignment above `sandboxedBackend` so bwrap gets the same markers.

In `runTask`, move the existing marker assignments above `sandboxedBackend`:
```go
if d.cfg.SandboxEnabled {
    agentEnv["MULTICA_HOST_REPO_CHECKOUT"] = "disabled"
    agentEnv["MULTICA_ISOLATED_TOOL_BOUNDARY"] = "1"
}
sandboxed, sandboxErr := d.sandboxedBackend(...)
```
Keep the later `HOME`/XDG block; delete only the duplicate marker lines.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd server && go test ./internal/daemon -run 'TestDockerBackend|TestIsolatedMarkers' -count=1 && go test ./internal/daemon/sandbox -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add server/internal/daemon/sandbox server/internal/daemon/sandbox_launch_docker.go server/internal/daemon/sandbox_launch.go server/internal/daemon/daemon.go server/internal/daemon/sandbox_launch_docker_test.go
git commit -m "feat(sandbox): mount task repo caches read-only with a manifest"
```

---

### Task 6: Prepare before launch, fail closed, record dependents

**Files:**
- Modify: `server/internal/daemon/daemon.go` (`runTask`, `registerTaskRepos`, new helpers)
- Modify: `server/internal/daemon/sandbox_launch.go` (`sandboxedBackend` signature)
- Test: `server/internal/daemon/repo_cache_prepare_test.go` (create)

**Interfaces:**
- Consumes: `repocache.Prepare`, `repocache.RecordDependents`, `sandbox.ProviderSupportsIsolatedTools`, `workercheckout.Entry`.
- Produces:
  ```go
  func (d *Daemon) prepareTaskRepoCaches(ctx context.Context, task Task) ([]workercheckout.Entry, error)
  func (d *Daemon) recordRepoCacheDependents(workspaceID string, env *execenv.Environment, attemptID string, cachePaths []string) error
  func (d *Daemon) repoCachePathsForReusedWorkdir(workspaceID, workDir string) ([]string, error)
  func (d *Daemon) registerTaskRepos(workspaceID, taskID string, repos []RepoData) []RepoData
  func (d *Daemon) usesDockerRepoCache(provider string) bool
  ```

- [ ] **Step 1: Write the failing tests**

```go
// TestPrepareTaskRepoCachesRejectsPathOutsideWorkspaceCache: a fake cache
// returns BarePath outside <WorkspacesRoot>/.repos/<ws>; the helper errors.

// TestRunTaskFailsWhenRepoCachePrepareFails: fake Prepare returns an error;
// runTask returns an error containing the repo URL and never launches docker.

// TestRunTaskWritesManifestAndRecordsDependents: fake Prepare returns one entry;
// runTask writes <env.RootDir>/repo-cache.json with the URL/SHA/cache path and
// calls RecordDependents with the workdir and cache path.

// TestRunTaskSkipsRepoCacheForBwrap: with TaskSandboxBackend "bwrap", Prepare is
// never called and the existing background sync still runs.

// TestLocalDirectoryTaskKeepsCurrentFlow: a local_directory task does not call
// Prepare and still uses the existing worktree path.

// TestTwoDockerTasksUseSeparateWorkdirsAndOneSharedCache: run the same repo
// twice; both manifests point at the same cache path, the workdirs differ, and
// the cache path is passed with the ro bind.

// TestReusedWorkdirKeepsOldCacheMounted: a reused workdir contains a checkout
// whose alternates point at a cache for a repo no longer in task.Repos; the
// old cache path is returned by repoCachePathsForReusedWorkdir, passes the
// under-.repos validation, and is added to the mount/dependents set while the
// manifest still lists only task.Repos.

// TestReusedWorkdirIgnoresAlternatesOutsideCacheRoot: an alternates file that
// points at /tmp or at a sibling workspace's cache is not mounted.
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd server && go test ./internal/daemon -run 'TestRunTask.*RepoCache|TestPrepareTaskRepoCaches' -count=1`
Expected: FAIL with undefined helpers.

- [ ] **Step 3: Implement the prepare path**

`usesDockerRepoCache(provider)` is true when `d.cfg.SandboxEnabled` is true, `d.cfg.TaskSandboxBackend == "docker"`, and `sandbox.ProviderSupportsIsolatedTools(provider)`.

Refactor `registerTaskRepos` to return the `toSync []RepoData` and stop spawning the background goroutine. Update the single `runTask` call site and any test callers. In `runTask`:

```go
toSync := d.registerTaskRepos(task.WorkspaceID, task.ID, task.Repos)
var taskRepoCaches []workercheckout.Entry
if d.usesDockerRepoCache(provider) {
    taskRepoCaches, err = d.prepareTaskRepoCaches(prepareCtx, task)
    if err != nil { return TaskResult{}, fmt.Errorf("prepare task repo cache: %w", err) }
} else if len(toSync) > 0 {
    d.bgSyncs.Add(1)
    go func() { defer d.bgSyncs.Done(); d.syncWorkspaceRepos(task.WorkspaceID, toSync) }()
}
```

`prepareTaskRepoCaches`:
- Dedupe `task.Repos` by URL (first Ref wins) and skip empty URLs.
- Require `d.repoCache` to implement `Prepare`; otherwise error.
- Call `Prepare(ctx, task.WorkspaceID, []repocache.RepoInfo{{URL, Ref}}...)`.
- Validate each `BarePath`: absolute, cleaned, `filepath.EvalSymlinks` both the path and `<WorkspacesRoot>/.repos/<workspaceID>`, and require the resolved path to be a strict child of the resolved workspace cache root. Reject duplicates.
- Return `[]workercheckout.Entry{{URL, Ref, CommitSHA, CachePath: BarePath}}`.

After `env` is available and before `sandboxedBackend`:
- If `len(taskRepoCaches) > 0`, write the manifest:
  `workercheckout.WriteManifest(filepath.Join(env.RootDir, workercheckout.ManifestFileName), workercheckout.Manifest{Repos: taskRepoCaches})`; a write failure fails the task.
- Call `recordRepoCacheDependents(task.WorkspaceID, env, attemptID, taskRepoCaches)`; a failure fails the task (fail closed for the cache lifecycle).
- Pass `taskRepoCaches` to `sandboxedBackend(...)` and `dockerBackend(...)`.

`recordRepoCacheDependents` requires the cache to implement `RecordDependents`; take the unique `CachePath`s plus `repoCachePathsForReusedWorkdir(task.WorkspaceID, env.WorkDir)` and call it with `{WorkDir: env.WorkDir, CachePaths: paths, TaskID: task.ID, AttemptID: attemptID}`.

`repoCachePathsForReusedWorkdir` walks `<workDir>/*/.git/objects/info/alternates` (depth 1), resolves each line, and keeps only paths under the resolved `<WorkspacesRoot>/.repos/<workspaceID>/` root that still exist. Pass those paths to `sandboxedBackend` as `extraCachePaths` so an old checkout keeps working after a task's repo set changes; the manifest still lists only `task.Repos`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd server && go test ./internal/daemon -run 'TestRunTask|TestPrepareTaskRepoCaches' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add server/internal/daemon/daemon.go server/internal/daemon/sandbox_launch.go server/internal/daemon/repo_cache_prepare_test.go
git commit -m "feat(daemon): prepare repo caches before isolated launches"
```

---

### Task 7: Worker CA trust

**Files:**
- Modify: `server/internal/daemon/config.go` (`MULTICA_DOCKER_TASK_CA_BUNDLE`)
- Modify: `server/internal/daemon/repocache/ca.go` (export `CABundlePEM`)
- Create: `server/internal/daemon/worker_ca.go`
- Modify: `server/internal/daemon/sandbox/container_env.go` (`CAEnv`)
- Modify: `server/internal/daemon/sandbox_launch_docker.go` (bundle bind + env)
- Modify: `server/internal/daemon/daemon.go` (write the bundle before launch)
- Test: `server/internal/daemon/worker_ca_test.go`
- Test: `server/internal/daemon/sandbox_launch_docker_test.go`

**Interfaces:**
- Consumes: `repocache.Cache.CABundlePEM`, `execenv.Environment.RootDir`.
- Produces:
  ```go
  // sandbox
  const RepoCABundlePath = HomePath + "/.multica/ca-bundle.pem"

  func CAEnv(bundlePath string) map[string]string

  // daemon
  func (d *Daemon) writeWorkerCABundle(envRoot, extraPath string) (string, error)

  // repocache
  func (c *Cache) CABundlePEM() ([]byte, error)
  ```
- Config field: `DockerTaskCABundle string`, loaded from `MULTICA_DOCKER_TASK_CA_BUNDLE`.
- `writeWorkerCABundle` returns the host path of `<envRoot>/ca-bundle.pem` when it wrote one, or `""` when neither the repo-cache trust nor the extra file produced a bundle.
- `CAEnv` returns `GIT_SSL_CAINFO`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, and `REQUESTS_CA_BUNDLE`, all set to `bundlePath`.

- [ ] **Step 1: Write the failing tests**

```go
// TestWriteWorkerCABundleAppendsExtraCert: seed a CA bundle through a real
// repocache Cache; write an extra self-signed cert to a temp file; the returned
// bundle contains both certificates (parse the PEM blocks and check subjects).

// TestWriteWorkerCABundleFailsOnInvalidExtra: a non-PEM file or a PEM block that
// is not a certificate returns an error naming the path; no bundle file is left.

// TestWriteWorkerCABundleWithoutExtraKeepsMachineTrust: no env path; the bundle
// is still written when the repo cache has a machine/system bundle.

// TestDockerBackendMountsCABundleReadOnly: fake docker argv contains
// "-v", "<env.RootDir>/ca-bundle.pem:/home/agent/.multica/ca-bundle.pem:ro"
// and the CA env vars point at /home/agent/.multica/ca-bundle.pem.

// TestDockerBackendOmitsCABundleWhenUnset: no file and no env var means no bind
// and no CA env vars.
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd server && go test ./internal/daemon -run 'TestWriteWorkerCABundle|TestDockerBackend.*CABundle' -count=1`
Expected: FAIL with undefined helpers/fields.

- [ ] **Step 3: Implement the bundle and mount**

- `LoadConfig`: `DockerTaskCABundle: strings.TrimSpace(os.Getenv("MULTICA_DOCKER_TASK_CA_BUNDLE"))`. The daemon logs the path and whether the file exists at startup; a file that exists but is unreadable fails the task at prepare.
- `repocache.CABundlePEM`: return the active bundle file when `caState` is active, otherwise `machineCATrust(c.caBundlePath())`. Return `nil, nil` when the machine has no bundle and no extra CAs.
- `writeWorkerCABundle`:
  1. Start from `cache.CABundlePEM()` (ignore the cache type assertion failure: the bundle is then only the extra file).
  2. If `extraPath != ""`, read it and append its valid `CERTIFICATE` blocks; a missing/unreadable file or content without a valid certificate is an error.
  3. If the result is empty, return `""`, nil.
  4. Write `<envRoot>/ca-bundle.pem` atomically with `0o644` (the file is read-only to the worker and contains public certs).
- In `runTask`, after `env` is available and before `sandboxedBackend`, call `writeWorkerCABundle(env.RootDir, d.cfg.DockerTaskCABundle)`; a failure fails the task. Store the result on the environment (add `execenv.Environment.WorkerCABundlePath string`).
- `dockerBackend`: if `env.WorkerCABundlePath != ""`, append `sandbox.DockerBind(env.WorkerCABundlePath, sandbox.RepoCABundlePath, "ro")` after the config binds, and merge `sandbox.CAEnv(sandbox.RepoCABundlePath)` into `containerEnv` before it is written to the manifest and argv.
- Document the env in `docs/security/docker-task-worker-manual-test.md`: the operator points `MULTICA_DOCKER_TASK_CA_BUNDLE` at a PEM file (for the current host, `/home/tui/Projects/multica/.orca/drops/MUOI_TIEU_XANH.crt`), restarts the daemon, and verifies the bind/env with `docker inspect`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd server && go test ./internal/daemon -run 'TestWriteWorkerCABundle|TestDockerBackend.*CABundle' -count=1 && go test ./internal/daemon/sandbox -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add server/internal/daemon/config.go server/internal/daemon/repocache/ca.go server/internal/daemon/worker_ca.go server/internal/daemon/sandbox/container_env.go server/internal/daemon/sandbox_launch_docker.go server/internal/daemon/daemon.go server/internal/daemon/worker_ca_test.go server/internal/daemon/sandbox_launch_docker_test.go docs/security/docker-task-worker-manual-test.md
git commit -m "feat(sandbox): trust the configured CA bundle in docker workers"
```

---

### Task 8: `multica repo checkout` inside the worker

**Files:**
- Modify: `server/cmd/multica/cmd_repo.go`
- Test: `server/cmd/multica/cmd_repo_test.go`

**Interfaces:**
- Consumes: `workercheckout.ManifestPath`, `workercheckout.ReadManifest`, `workercheckout.Find`, `workercheckout.Checkout`.
- Produces: no new exported CLI API. The isolated branch runs before the `MULTICA_DAEMON_PORT` check.

- [ ] **Step 1: Write the failing tests**

```go
// TestRunRepoCheckoutIsolatedUsesManifest:
// set MULTICA_ISOLATED_TOOL_BOUNDARY=1, MULTICA_TASK_CONFIG_ROOT=<tmp>,
// MULTICA_AGENT_NAME, MULTICA_TASK_ID, chdir to a temp workdir, write a manifest
// for a real cache; the returned error is nil, <workdir>/<repo>/.git exists, and
// origin is the real URL. No HTTP server is running.

// TestRunRepoCheckoutIsolatedRejectsUnknownURL: the manifest has another URL;
// the error names the allowed URL.

// TestRunRepoCheckoutIsolatedKeepsDirtyCheckout: run twice with a new SHA in
// the manifest; the local commit/file survive and the summary mentions
// ahead/behind.

// TestRunRepoCheckoutHostStillRequiresDaemonPort: without the isolated marker,
// an empty MULTICA_DAEMON_PORT still returns the existing error.
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd server && go test ./cmd/multica -run 'TestRunRepoCheckoutIsolated' -count=1`
Expected: FAIL (the command still tries the daemon port).

- [ ] **Step 3: Add the isolated branch**

In `runRepoCheckout`, immediately after `repoURL := args[0]`:

```go
if os.Getenv("MULTICA_ISOLATED_TOOL_BOUNDARY") == "1" {
    return runRepoCheckoutIsolated(cmd, repoURL)
}
```

`runRepoCheckoutIsolated`:
- `path, err := workercheckout.ManifestPath()`; `manifest, err := workercheckout.ReadManifest(path)`; `entry, err := workercheckout.Find(manifest, repoURL)`.
- `cwd, err := os.Getwd()`; `result, err := workercheckout.Checkout(cmd.Context(), cwd, entry, workercheckout.Options{Ref: repoCheckoutRef, Fresh: repoCheckoutFresh, AgentName: os.Getenv("MULTICA_AGENT_NAME"), TaskID: os.Getenv("MULTICA_TASK_ID")})`.
- Print `result.Path` to stdout (agents parse this) and a summary to stderr. A kept checkout summary must state ahead/behind and the uncommitted/unpushed counts, and that nothing was reset.
- Do not require `MULTICA_TOKEN` or the daemon port in this path.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd server && go test ./cmd/multica -run 'TestRunRepoCheckout' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add server/cmd/multica/cmd_repo.go server/cmd/multica/cmd_repo_test.go
git commit -m "feat(cli): check out task repos from the in-worker cache manifest"
```

---

### Task 9: GC eviction and maintenance respect dependents

**Files:**
- Modify: `server/internal/daemon/gc.go`
- Test: `server/internal/daemon/gc_repo_dependents_test.go` (create)
- Test: `server/internal/daemon/repocache/dependents_test.go` (extend)

**Interfaces:**
- Consumes: `LiveDependentCachePaths`.
- Produces:
  ```go
  func (d *Daemon) repoCacheDependents() (map[string]struct{}, error)
  ```
  Returns an error when the cache implementation does not support dependents; the caller must skip eviction and heavy maintenance for that cycle (fail safe).

- [ ] **Step 1: Write the failing tests**

```go
// TestRepoCacheKeptWhileDependentExists: a real bare cache, an old last-used
// stamp, a live workdir with a RecordDependents entry, tiny GCRepoTTL; run
// pruneRepoWorktreesContext; the bare cache still exists.

// TestRepoCacheEvictedAfterDependentRemoved: remove the workdir; run GC again;
// the cache is gone and the workspace cache dir is removed.

// TestRepoCacheKeptAcrossDaemonRestart: build a new Daemon/Cache over the same
// root; the dependent is still honored.

// TestRepoCacheMaintenanceSkippedWhileDependent: a dependent cache never runs
// the heavy `git gc --prune` step (assert the cache's unreachable object
// survives, or assert the decision helper returns false).

// TestRepoCacheNoEvictionWhenDependentsScanFails: a cache implementation that
// returns an error from LiveDependentCachePaths causes the GC cycle to leave
// all caches untouched.
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd server && go test ./internal/daemon -run 'TestRepoCache.*Dependent' -count=1`
Expected: FAIL (the cache is evicted or the helper is undefined).

- [ ] **Step 3: Implement the gate**

- In `pruneRepoWorktreesContext`, call `d.repoCacheDependents()` once. If the cache type does not implement the dependents interface (test doubles), treat the set as empty and keep the old behavior. If it implements the interface and the scan returns an error, log and return without touching caches.
- Pass the set to `maintainRepoCache(ctx, barePath, stats, pinned bool)`.
- `evictRepoCacheLocked`: return early when `pinned`.
- `pruneWorktreeLocked`: still delete stale agent branches, but skip `reflog expire` + `gc --prune` when `pinned` (the dependent's objects are not reachable from the bare repo's refs).
- When a workspace cache dir has no bare repos left, remove `.dependents` first, then the dir; ignore `.dependents` in the "is it empty?" check.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd server && go test ./internal/daemon -run 'TestRepoCache.*Dependent' -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add server/internal/daemon/gc.go server/internal/daemon/gc_repo_dependents_test.go server/internal/daemon/repocache/dependents_test.go
git commit -m "fix(gc): retain repo caches with live workdir dependents"
```

---

### Task 10: Docs, skill copy, and full verification

**Files:**
- Modify: `docs/security/git-lifecycle-in-worker.md`
- Modify: `docs/security/docker-task-worker-manual-test.md`
- Modify: `docs/security/tool-isolation.md`
- Modify: `docs/security/git-security-mvp-status.md`
- Modify: `server/internal/service/builtin_skills/multica-platform/references/runtimes.md`

- [ ] **Step 1: Update the docs**

- `git-lifecycle-in-worker.md`: replace the "host checkout blocked; agent clones from the network" description with the read-only per-task cache mount, the manifest, and alternates; state that cold cache still downloads once and that GC retains the cache while a workdir depends on it.
- `docker-task-worker-manual-test.md`: add checks for the manifest bind, `:ro` cache mounts (no sibling repos), `multica repo checkout` inside the worker, `origin`/`alternates`, a second task not seeing the first workdir, divergence output on reuse, and cache survival until the env root is GC'd.
- `tool-isolation.md`: add the repo-cache mounts to the "Worker boundary" table.
- `git-security-mvp-status.md`: update the Git prepare row from "Hybrid" to the new worker checkout path and list the new tests.
- `docker-task-worker-manual-test.md`: document `MULTICA_DOCKER_TASK_CA_BUNDLE` (the current local value is `/home/tui/Projects/multica/.orca/drops/MUOI_TIEU_XANH.crt`), the CA env vars, and how to verify the bind.
- `runtimes.md`: `repo checkout` in an isolated task reads the task manifest instead of the host daemon; it only accepts `task.Repos`; `--ref` fetches inside the worker; `--fresh` is the only way to discard local work.

- [ ] **Step 2: Run the full verification**

```bash
cd server
gofmt -l internal/daemon/repocache internal/daemon/workercheckout internal/daemon/sandbox internal/daemon/daemon.go cmd/multica/cmd_repo.go
go test ./internal/daemon/... -count=1
go test ./cmd/multica -run 'TestRunRepoCheckout' -count=1
go test ./internal/daemon/workercheckout -run '^$' -bench BenchmarkRepoCacheCheckout -benchtime 3x -count=1
```

Expected: `gofmt -l` prints nothing; all tests PASS; the benchmark prints cold/warm metrics. Record the benchmark output in the PR.

- [ ] **Step 3: Commit**

```bash
git add docs/security server/internal/service/builtin_skills/multica-platform/references/runtimes.md
git commit -m "docs(security): document the worker repo cache boundary"
```

---

## Execution Handoff

The tasks are ordered by dependency: prepare and manifest types first, checkout next, then mounting/wiring and CA trust, CLI, and GC. Task 6 changes signatures used by daemon tests, so it should land before Task 8. Task 9 depends only on Task 2 and can run in parallel with Task 8 after Task 6. Task 7 (CA trust) depends on the mount plumbing in Task 5 and the daemon wiring in Task 6.

Recommended execution: **subagent-driven** — each task has a narrow file set and its own failing test, and an independent reviewer is useful for the cache-lifecycle and mount-validation tasks. Use native execution if you want the fastest path with one final review.
