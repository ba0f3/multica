# Tool isolation (Git security MVP)

Multica runs agent CLIs inside a worker boundary. Docker is the default and admits every supported backend and built-in runtime. Linux native execution uses `MULTICA_TASK_SANDBOX=bwrap` and the original Codex, Cursor or OpenCode installation and profile. MCode has a native resolver, but known incompatible releases fail preflight. Native rollout remains opt-in because the full four-provider acceptance matrix has not passed.

Once selected, a sandbox backend fails closed. It never falls back to host execution or another backend. Network access retains the existing host policy; egress filtering is a separate follow-up.

## Defaults

| Setting | Default |
| --- | --- |
| `MULTICA_TASK_SANDBOX` | enabled (`docker`) |
| `MULTICA_TASK_SANDBOX=false` | host execution (development only) |
| `MULTICA_TASK_PROTECTED=1` | fail closed when the boundary cannot be built |


## Linux native execution

### Host configuration

`MULTICA_TASK_SANDBOX=bwrap` selects native execution. The daemon account needs bubblewrap, unprivileged user and PID namespaces, a running user systemd manager, cgroup v2, and delegated CPU, memory and PID controllers. `systemd-run` must support `--expand-environment=no`. Native preflight creates a constrained probe and reads its effective cgroup limits; unavailable or ignored limits reject the task.

| Variable | Native behavior |
| --- | --- |
| `MULTICA_BWRAP_PATH` | Optional bubblewrap executable path; otherwise `bwrap` on the daemon's PATH |
| `MULTICA_DOCKER_TASK_MEMORY` | Memory limit, also applied to native scopes, for example `2g` |
| `MULTICA_DOCKER_TASK_PIDS_LIMIT` | Process limit, for example `512` |
| `MULTICA_DOCKER_TASK_NANO_CPUS` | CPU quota in nanocpus, for example `2000000000` for two CPUs |

Zero resource values retain the configured unlimited behavior. Positive values must be enforced. A CLI upgrade invalidates cached runtime metadata on the next task. Cached resource preflight is tied to the tools, configured limits and user-manager connection.

Runtime and profile selection uses the daemon account's HOME and provider selectors, including `CODEX_HOME`, Cursor config/data directories, OpenCode XDG directories, and MCode data directories. A task's custom environment or the person pressing rerun cannot replace this selection.

### Filesystem and shared profiles

Native workers see a fresh empty home at the original HOME pathname, followed by explicit grants. The whole host home is never mounted. Original executables, launcher links, interpreters and ELF dependencies remain at their original paths and are read-only. The resolver does not rewrite provider launchers or substitute Node.

Only selected profile directories are shared read-write. Task workdir, temporary files, output and task API configuration have their own mounts. Selected repository caches and the checkout manifest are read-only. Host SSH keys, Git credential stores, administrator tokens, other task directories, Docker sockets and keyring sockets are absent. Resolver and hosts files retain the host's DNS configuration, including systemd resolver symlinks.

The selected profile is a shared account trust domain. An agent can read that profile's credentials and sessions. Principals without permission to use the account must not share its profile. This boundary does not promise credential isolation or prevention of data exfiltration.

Codex receives task settings through thread RPC without rewriting shared `config.toml`. Cursor keeps its original data directory and uses project-local managed MCP configuration. Existing runtime-plus-agent MCP merging remains unchanged. MCode installer `.mcode-active` state is private to each sandbox. Profile leases serialize MCode workers across daemon profiles and release only after attempt cleanup; vendor auth and database locks remain beside the state they protect.

Each native attempt has private user, PID, IPC and UTS namespaces, no capabilities, and `no_new_privs`. A user-systemd scope owns all descendants. Completion, cancellation, timeout and daemon death stop the attempt before releasing its profile lease. The workdir and original session store remain available for resume.

### Compatibility and recovery

| Failure | Recovery |
| --- | --- |
| Missing bubblewrap, namespaces, user manager or cgroup controls | Enable the named host prerequisite and retry, or explicitly select Docker |
| Original interpreter or library unavailable | Repair the provider installation using its installer; do not move the launcher or replace Node |
| MCode before 0.6.13 | Its sibling migration lock cannot fit the permitted profile grants; use Docker or test a newer installation |
| MCode 0.6.13 | Native execution is rejected because PID-based recovery can release a live host lease; use Docker until a namespace-safe release passes acceptance |
| Provider requests login on both host and worker | Authenticate the selected daemon account with the provider CLI; native preparation does not manufacture login state |
| Unsupported model or provider quota | Check the selected account and model on the provider; startup timing alone does not establish an auth failure |

There is no automatic fallback. Other providers retain Docker execution. A later MCode version requires real continuity, shared-lock, refresh and host-coexistence acceptance before support is claimed.

### Timing

Logs tag monotonic measurements with task, attempt, provider and backend. `repo_prepare_ms` measures repository cache work, `runtime_resolve_ms` includes runtime resolution and preflight, and `environment_prepare_ms` measures task environment preparation. `sandbox_launch_ms` runs from native process spawn to `worker_ready`. `cli_start_ms` runs from readiness to successful CLI spawn. `first_output_ms` starts at CLI spawn; it includes provider startup and network waits and is not pure model time. `turn_total_ms` covers the attempt.

The warm-launch acceptance test runs 100 fake workers through the production launcher and requires worker-ready p95 at most 250 ms. It checks a fresh artifact and completed scope cleanup after every attempt. This threshold does not promise a model response time.

Measured on 2026-10-26 with the production launcher and test-created worker scripts:

| Host | Warm attempts | p50 | p95 | Maximum |
| --- | --- | --- | --- | --- |
| k7 | 100 | 52.5 ms | 67.1 ms | 86.8 ms |
| garlic | 100 | 29.4 ms | 35.5 ms | 37.1 ms |

Codex, Cursor and OpenCode passed fresh, worker resume, restart, provider change, and a new task after cancellation on both hosts. All three also passed a host plus two same-profile workers. OpenCode used the account-accessible `opencode-go/deepseek-v4.1-flash` model; these results do not establish availability of other model routes. MCode is not accepted for native rollout: 0.6.13 can invalidate a live host lease, and the selected garlic profile also requires host login.

## Scope

| Layer | What it does |
| --- | --- |
| Provider gate | Docker admits every supported backend and built-in runtime. Native resolution is limited to Codex, Cursor, OpenCode and MCode, with incompatible versions rejected before launch. |
| Worker boundary | The worker, adapter, CLI, MCP servers, hooks and tools run inside the selected boundary before the CLI reads repository configuration. Session IPC and Git signing use task-scoped channels. |
| Repo cache mounts | Before launch, the daemon strictly fetches each `task.Repos` repo into the workspace bare cache and binds only those caches read-only at their host paths (`<cache>:<cache>:ro`). A read-only `repo-cache.json` manifest lists the allowed URLs, refs, resolved SHAs, and cache paths. Unrelated sibling repositories and shared checkouts are not mounted; a reused workdir may add read-only caches named by its own alternates, still under the workspace cache root. |
| In-worker repo checkout | `multica repo checkout` reads the task manifest instead of the host daemon, creates a private `.git` in the task workdir with `objects/info/alternates` pointing at the mounted cache, sets `origin` to the real URL, and copies the cache's remote refs. The cache is never written or hardlinked. Both backends use this manifest and checkout path; cache fetch semantics are unchanged. |
| Worker CA bundle (Docker only) | The daemon builds `/home/agent/.multica/ca-bundle.pem` from the repo cache's Git trust plus `MULTICA_DOCKER_TASK_CA_BUNDLE`, mounts it read-only, and exports `GIT_SSL_CAINFO`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, and `REQUESTS_CA_BUNDLE`. bwrap receives no worker CA bundle. |
| Docker agent CLI | For every supported provider, the daemon bind-mounts the resolved host binary read-only at `/usr/local/bin/<basename>` and rewrites `executable_path` in the worker manifest (`sandbox.DockerAgentBinaryBind`). |
| Provider prep | Docker prepares task-local provider state. Native mode uses selected original profiles without copying profiles, importing credentials or editing credential databases. |
| Launch argv | OpenCode rejects `--server` and forces `--standalone` on 2.x inside the boundary (`server/pkg/agent/opencode_isolated.go`). |

## Codex in Docker

- Per-task `CODEX_HOME` is prepared under the task env root.
- On the host, `auth.json` and related files are symlinked from shared `~/.codex`.
- In the worker, the same files are **copied** so symlinks never point at host paths the container cannot follow.

## Cursor in Docker

- Managed MCP writes `.cursor/mcp.json` in the checkout as usual.
- Workspace trust and MCP approval keys use **`/workspace/repo`** (`execenv.IsolatedContainerWorkdir`), matching the worker cwd, not the host-side absolute workdir path.
- Optional `CURSOR_MCP_AUTH_SOURCE` is **copied** into the task `CURSOR_DATA_DIR` when isolated (no symlink to host).

## OpenCode in Docker

- **Credentials and config** are copied into the task `home/` tree (`~/.config/opencode`, `~/.local/share/opencode`) before Docker launch; the worker runs with `HOME` and XDG dirs pointed at that tree.
- **`--server` is forbidden** in the isolated boundary so the agent cannot attach to a host or shared background service.
- **OpenCode 2.x** runs with **`--standalone`** so the service stays in the worker process tree (cancellation and tool execution remain inside the boundary).
- **OpenCode 2.x + Multica-managed MCP** is still refused at launch (`ErrOpenCodeV2MCPUnsupported`) until MUL-7523 delivers env-backed MCP via standalone; use OpenCode 1.x or remove composed MCP servers for isolated 2.x tasks.

## Claude Code (`claude`)

- **Credentials and config** are copied into the task `home/` tree (`~/.claude`, `~/.claude.json`) before the worker starts. Bulky session/history trees that are not needed for auth (`projects`, `todos`, `stats`, `logs`, `shell-snapshots`, `file-history`, `session-env`, `downloads`, `cache`) are skipped so the copy stays small; a reused task home keeps its refreshed credentials because files are only copied when the target is missing. A missing host source is a warning (auth may fail), not a failed task.
- The task-local `--settings` file (`env.ClaudeSettingsPath`) is bound read-only at `/home/agent/.multica/claude-settings.json` in Docker, and the manifest path is rewritten to that in-container path so the host layout never crosses the boundary. Claude is Docker-only; bwrap refuses it.
- `CLAUDE_CONFIG_DIR`, when set, is rewritten to `/home/agent/.claude` to match the task-home copy; the host source is read from `CLAUDE_CONFIG_DIR` when absolute, otherwise `~/.claude`.
- Session transcripts under `~/.claude/projects` are not copied. A resumed task whose transcript lived only in the host project store starts a fresh session (the backend's normal fresh-session fallback); the task home's own sessions persist across reuse.

## Antigravity (`agy`)

- **Docker only.** **Credentials and app data** are copied into the task `home/` tree (`~/.gemini`) before the worker starts. Top-level auth/config JSON files and `antigravity-cli/` app data — including `antigravity-cli/brain`, which `--conversation` resume reads — are copied; disposable `tmp`/`cache`/`history` trees are skipped. A missing host source is a warning, not a failed task.
- No extra environment is set: `agy` resolves auth and app data under `HOME`, which the worker points at `/home/agent`.

## Generic Docker config seeding

Providers without bespoke prep mirror their auth/config dot-directories from the daemon user's home into the task home, with the same missing-only, no-symlink, 0700/0600 rules as Claude/Antigravity. The mapping (`server/internal/daemon/execenv/provider_home.go`) covers:

| Provider | Task-home directories |
| --- | --- |
| `codebuddy` | `.codebuddy` |
| `copilot` | `.copilot` |
| `codearts` | `.codeartsdoer` |
| `deveco` | `.deveco` |
| `pi`, `omp` | `.pi`, `.omp` |
| `kimi` | `.kimi` |
| `reasonix` | `.reasonix` |
| `dsh` | `.dsh` |
| `kiro` | `.kiro` |
| `qoder`, `qoderclicn` | `.qoder` |
| `traecli` | `.traecli`, `.trae` |
| `grok` | `.grok` |
| `qwen` | `.qwen` |
| `qwenpaw` | `.qwenpaw` |
| `mcode` (MiniMax Code) | `.mcode`, `.config/mcode`, `.minimax` configuration; OAuth state uses the mounts below |
| `muse` | `.muse` |
| `dim` | `.dim` |
| `zeroclaw` | `.zeroclaw` |

Codex, Cursor, OpenCode, Hermes, OpenClaw, Claude, and Antigravity are excluded because they have bespoke prep or mounts. A missing source directory is a warning (auth may fail), not a failed task.

## MCode OAuth state in Docker

MCode refresh tokens rotate. Docker workers share only the selected profile's `auth/` directory, including its native cross-process lock, with the daemon user's CLI. Copying this directory per task would leave other tasks with invalid refresh tokens after the first refresh.

The launcher preserves the original data-directory path in `MINIMAX_DATA_DIR` and `MAVIS_DATA_DIR`: MCode hashes that path into its credential key. The data directory at that path is a mount of the task's private `.minimax` tree, and its parent is a mount of the task's private home so MCode can create its sibling migration lock. Only the nested `auth/` directory is mounted from the profile read-write. Sessions, configuration, logs and tools stay private to the task. Host runtime databases, session history, process leases, auth sockets and caches are excluded from the initial copy. After acquiring the task-home claim, preparation removes any sibling migration lock left by a prior container; it preserves the task's own runtime database for resume. Changing the selected profile or region is applied again on reuse.

## OpenClaw / QwenPaw same-path mounts

OpenClaw reads its per-task config through an absolute `$include`, and QwenPaw takes its workspace via an absolute `--workspace`. The Docker backend binds those per-task paths at their **own absolute paths** (read-only for the OpenClaw config file and include root, read-write for the QwenPaw workspace) so those absolute references stay valid inside the container. `OPENCLAW_CONFIG_PATH` is no longer rewritten to a container path; the host path is preserved because the same-path bind makes it valid.

## Docker binary mounts

A Docker bind mount of a CLI shim alone is insufficient. Script-based installations also need their original interpreter, package tree and ABI-compatible native modules through provider-specific installation mounts. Credentials stored only in a system keyring that the CLI does not materialise under its home dot-directory (or via an explicitly exported env/custom config) will not reach the worker, because the boundary mounts task-home copies, except for MCode's scoped OAuth state described above, and never the whole host home or a keyring socket. Providers whose auth lives outside the listed dot-directories need an env/custom config source to carry credentials across the boundary.

## Environment signals

| Variable | When set |
| --- | --- |
| `MULTICA_ISOLATED_TOOL_BOUNDARY=1` | Agent process inside the worker |
| `MULTICA_HOST_REPO_CHECKOUT=disabled` | Host `POST /repo/checkout` blocked for the task token |

## Verification

Default Go tests use fake or missing CLI paths. Kernel boundary and launch probes use test-created scripts and private profiles:

```bash
MULTICA_BWRAP_SMOKE=1 bash scripts/go-test-with-agent-cli-guard.sh -- go -C server test ./internal/daemon -run '^TestNativeWarmWorkerLaunchLatency$' -count=1 -v
```

`make test-agent-native-workers` explicitly uses the current user's real accounts. Tests require `agentintegration`, `MULTICA_RUN_REAL_AGENT_SMOKE=1`, an explicit `MULTICA_REAL_AGENT_HOME` and a built `MULTICA_NATIVE_SMOKE_WORKER`; the Make target supplies these. `MULTICA_SMOKE_MODEL_<PROVIDER>` selects an account-accessible model. `MULTICA_SMOKE_MCODE_REFRESH=1` adds concurrent vendor OAuth refresh and subsequent session resume. Incompatible MCode releases fail acceptance rather than silently skipping it.

Fresh, resumed, restarted and provider-switched sessions must create exact tool artifacts. Resume also checks the same session ID and a remembered canary whose input file was removed. Host coexistence and two workers sharing a profile are separate cases. Run the matrix on both reference hosts before changing the default.

Automated:

```bash
go test ./server/internal/daemon/ -run TestTaskIsolationE2E_ -count=1
pnpm exec playwright test e2e/task-isolation.spec.ts
go test ./server/internal/daemon/sandbox/...
go test ./server/pkg/agent/ -run EnforceOpenCode -count=1
(cd server && go test ./internal/daemon/repocache/... ./internal/daemon/workercheckout/... -count=1)
(cd server && go test ./internal/daemon -run 'TestRepoCache|TestRunTask.*RepoCache|TestDockerBackendMountsRepoCache' -count=1)
(cd server && go test ./cmd/multica -run TestRunRepoCheckout -count=1)
```

Optional real OpenCode (free tier) argv smoke:

```bash
MULTICA_RUN_REAL_AGENT_SMOKE=1 go test ./server/internal/daemon/ -run TestTaskIsolationE2E_OpenCodeRealFreeTier -count=1 -v
```

Manual Docker checklist: [docker-task-worker-manual-test.md](./docker-task-worker-manual-test.md).
