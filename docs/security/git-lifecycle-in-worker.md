# Git lifecycle: worker boundary vs performance

Spec requires Git **driven by the task** (checkout, fetch, probe, hooks) to run inside the Docker/bwrap boundary with the user's signing socket. Docker attempts now receive their code from daemon-prepared bare caches: the daemon fetches and resolves every task repo before launch, mounts those caches read-only, and `multica repo checkout` runs inside the worker from a task-scoped manifest. The host `/repo/checkout` endpoint stays blocked for isolated tasks.

## What runs where

| Phase | Where it runs | Credential |
| --- | --- | --- |
| Prepare task repo caches (claim) | Host daemon `repocache` | Daemon orchestration; strict clone/fetch and SHA resolution |
| Manifest write and cache mounts (before launch) | Host daemon | None; every cache path is validated under `.repos/<workspace-id>` |
| `multica repo checkout` during agent | Worker, from the task manifest | Read-only cache and manifest mounts |
| Agent `git fetch/push` | Container (or bwrap) | Per-attempt `SSH_AUTH_SOCK` and the worker CA bundle |
| Finalize (commit leftovers, worktree cleanup) | Host daemon | Existing task identity |

Finalize still runs on the host; moving it into the worker remains follow-up work.

## How the worker gets code

1. **Prepare from `task.Repos` only.** The daemon prepares each repository in the task's repo list into the workspace bare cache (`.repos/<workspace-id>/<repo>.git`). A cold cache is cloned once; a warm cache is fetched strictly. The requested ref, or the remote default branch, is resolved to a commit SHA. A clone, fetch, or ref-resolution failure fails the task before launch; it never falls back to a stale cache. `local_directory` tasks keep their existing host-worktree flow.
2. **Publish a task manifest.** The daemon writes `repo-cache.json` into the task environment root and mounts it read-only at `/home/agent/.multica/repo-cache.json`. Each entry carries `url`, `ref`, `commit_sha`, and `cache_path`. The worker strictly decodes the file (no unknown fields), rejects trailing data, and validates that every cache path is absolute, cleaned, an existing bare repository, and that the SHA is a full lowercase object ID.
3. **Mount only this task's bare caches.** Every prepared cache is bind-mounted at the same absolute host path (`<cache>:<cache>:ro`), so Git alternates written on the host stay valid inside the container. The manifest lists only `task.Repos`, and no sibling repository, workspace-wide cache, or shared checkout is mounted. A reused workdir also keeps read-only mounts for old caches that its existing checkouts still reference through alternates; those paths are not added to the manifest.
4. **Check out inside the worker.** `multica repo checkout <url>` matches the URL exactly against the manifest, then creates `<workdir>/<repo-dir>/.git`. It points `objects/info/alternates` at the mounted cache's `objects` directory, copies the cache's remote-tracking and tag refs, sets `origin` to the real repository URL, and creates the task branch at the daemon-resolved commit. The checkout reads cache objects without copying or hardlinking them, and never writes to the cache.

Because the default path uses the SHA the daemon already resolved, it contacts no remote. An explicit `--ref` that is not already present is fetched from `origin` **inside the worker**, using its signing socket and CA trust.

## Freshness and cold-cache cost

- A cold workspace still downloads the repository once, into the shared bare cache. Every later task for that workspace fetches only new refs and reuses the objects through alternates.
- The per-attempt cost is a local `git init` plus alternates and ref metadata, not a full history download. `BenchmarkRepoCacheCheckout` in `server/internal/daemon/workercheckout` measures the cold and warm prepare/checkout/write phases against a 2,000-commit repository.
- Prepare is strict on every task launch, so a task cannot silently start from an unfetched snapshot. It can still be slower than a background sync on very large repositories; the fetch cost is bounded by how much the remote moved since the last task.
- The cache is per workspace. Two workspaces that bind the same URL clone it independently.

## Reuse and `--fresh`

Running `repo checkout` again in the same task, a follow-up turn, or a reused workdir keeps the existing checkout and reports how far it has diverged from the new base: commits ahead and behind, uncommitted files, and unpushed commits. Nothing is reset, cleaned, or switched, and only remote refs are refreshed.

`--fresh` is the only path that discards local work: it resets the checkout, removes untracked files, and moves the task branch to the new base. Push any commits that only exist locally before using it. Bare cache objects are never mutated by either path.

## Retention and GC

Before launch, the daemon records each workdir's dependency on its cache paths in `.repos/<workspace-id>/.dependents/`. The record names the absolute workdir, the caches, and the task/attempt. Recording is fail-closed: if it cannot be written, the task does not launch and then lose its cache mid-run.

The GC resolves the live dependents once per cycle, including after a daemon restart. A cache named directly or through its `objects` directory is **pinned**: it is neither evicted nor pruned/repacked, because a checkout's alternates reach objects that the bare repository's refs do not. Stale `agent/*` branches are still pruned. When the workdir's env root is removed, the next scan drops its record and the cache returns to the normal idle/TTL rules; if the whole dependents scan fails, the repo-cache pass is skipped and everything is retained for that cycle.

An evicted cache costs a re-clone on the next task that needs it, not correctness.

## Trust

The daemon builds the worker's CA bundle from the repo cache's current Git trust (machine trust plus any server-provided CAs) and the optional host file `MULTICA_DOCKER_TASK_CA_BUNDLE`. The bundle is mounted read-only at `/home/agent/.multica/ca-bundle.pem` and exported through `GIT_SSL_CAINFO`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, and `REQUESTS_CA_BUNDLE`. A configured but missing, unreadable, or certificate-less file fails the task at prepare. See [docker-task-worker-manual-test.md](docker-task-worker-manual-test.md).

## Remaining limitations

- Finalize and hooks still run on the host identity.
- An isolated worker can check out only URLs in its task manifest; arbitrary workspace repositories are rejected.
- Git LFS and partial-clone behavior still depends on the image's Git version and the provider.
- The bwrap path keeps its previous behavior; this cache flow applies to Docker workers.

## Operator tuning

- Pin the worker image's Git version and increase prepare timeouts for very large repositories before enabling protected Docker on those workspaces.
- Set `MULTICA_DOCKER_TASK_CA_BUNDLE` for private Git hosts and verify the mount with `docker inspect`.
- Tune the repo-cache TTL and maintenance window for the host's disk and repository size. Use `GIT_TRACE` only in disposable tests.
