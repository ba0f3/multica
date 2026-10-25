# Tool isolation (Git security MVP)

This document describes how Multica constrains agent CLIs inside the Docker worker boundary. The provider gate admits every Multica-supported backend (Claude Code, CodeBuddy, Codex, Copilot, OpenCode, CodeArts, DevEco, OpenClaw, Hermes, Pi, Cursor, Kimi, Reasonix, DSH, Kiro, Antigravity, Qoder, Trae, Grok, Qwen, QwenPaw, MiniMax Code (`mcode`), Muse, Dim, ZeroClaw) plus built-in runtime identities such as Oh-My-Pi (`omp`). Only **Codex**, **Cursor**, and **OpenCode** still support the legacy bubblewrap backend; every other provider requires Docker because its per-task config/credentials are seeded into the Docker task home. **By default** every daemon enables the sandbox (`MULTICA_TASK_SANDBOX` unset → Docker). Opt out with `MULTICA_TASK_SANDBOX=false`. **Network deny** (egress policy) is a separate follow-up.

## Defaults

| Setting | Default |
| --- | --- |
| `MULTICA_TASK_SANDBOX` | enabled (`docker`) |
| `MULTICA_TASK_SANDBOX=false` | host execution (development only) |
| `MULTICA_TASK_PROTECTED=1` | fail closed when the boundary cannot be built |

## Scope

| Layer | What it does |
| --- | --- |
| Provider gate | Every Multica-supported backend and built-in runtime may run when the sandbox is enabled (`server/internal/daemon/sandbox/providers.go`). Only `codex`, `cursor`, and `opencode` may use bwrap; every other provider requires the Docker backend. |
| Worker boundary | Agent CLI runs inside Docker (or bwrap for codex/cursor/opencode); Session IPC and git signing stay on controlled mounts. |
| Repo cache mounts (Docker only) | Before launch, the daemon strictly fetches each `task.Repos` repo into the workspace bare cache and binds only those caches read-only at their host paths (`<cache>:<cache>:ro`). A read-only `repo-cache.json` manifest lists the allowed URLs, refs, resolved SHAs, and cache paths. Unrelated sibling repositories and shared checkouts are not mounted; a reused workdir may add read-only caches named by its own alternates, still under the workspace cache root. |
| In-worker repo checkout (Docker only) | `multica repo checkout` reads the task manifest instead of the host daemon, creates a private `.git` in the task workdir with `objects/info/alternates` pointing at the mounted cache, sets `origin` to the real URL, and copies the cache's remote refs. The cache is never written or hardlinked. bwrap has no task manifest, so this path does not apply there. |
| Worker CA bundle (Docker only) | The daemon builds `/home/agent/.multica/ca-bundle.pem` from the repo cache's Git trust plus `MULTICA_DOCKER_TASK_CA_BUNDLE`, mounts it read-only, and exports `GIT_SSL_CAINFO`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, and `REQUESTS_CA_BUNDLE`. bwrap receives no worker CA bundle. |
| Docker agent CLI | For every supported provider, the daemon bind-mounts the resolved host binary read-only at `/usr/local/bin/<basename>` and rewrites `executable_path` in the worker manifest (`sandbox.DockerAgentBinaryBind`). |
| Provider prep | `IsolatedToolBoundary` on execenv prepare/reuse copies provider secrets into the task env and fixes container identity paths. |
| Launch argv | OpenCode rejects `--server` and forces `--standalone` on 2.x inside the boundary (`server/pkg/agent/opencode_isolated.go`). |

## Codex

- Per-task `CODEX_HOME` is prepared under the task env root.
- On the host, `auth.json` and related files are symlinked from shared `~/.codex`.
- In the worker, the same files are **copied** so symlinks never point at host paths the container cannot follow.

## Cursor

- Managed MCP writes `.cursor/mcp.json` in the checkout as usual.
- Workspace trust and MCP approval keys use **`/workspace/repo`** (`execenv.IsolatedContainerWorkdir`), matching the worker cwd, not the host-side absolute workdir path.
- Optional `CURSOR_MCP_AUTH_SOURCE` is **copied** into the task `CURSOR_DATA_DIR` when isolated (no symlink to host).

## OpenCode

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

## Generic config seeding

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
| `mcode` (MiniMax Code) | `.mcode`, `.minimax`, `.config/mcode` |
| `muse` | `.muse` |
| `dim` | `.dim` |
| `zeroclaw` | `.zeroclaw` |

Codex, Cursor, OpenCode, Hermes, OpenClaw, Claude, and Antigravity are excluded because they have bespoke prep or mounts. A missing source directory is a warning (auth may fail), not a failed task.

## OpenClaw / QwenPaw same-path mounts

OpenClaw reads its per-task config through an absolute `$include`, and QwenPaw takes its workspace via an absolute `--workspace`. The Docker backend binds those per-task paths at their **own absolute paths** (read-only for the OpenClaw config file and include root, read-write for the QwenPaw workspace) so those absolute references stay valid inside the container. `OPENCLAW_CONFIG_PATH` is no longer rewritten to a container path; the host path is preserved because the same-path bind makes it valid.

## Native-binary requirement

Every provider is supported only as a **native CLI binary**. A Node/npm shim whose resolved file is a script needs its interpreter (and `node_modules`), which the worker image does not bundle; bind-mounting only the resolved script is not enough for such an install. Credentials stored only in a system keyring that the CLI does not materialise under its home dot-directory (or via an explicitly exported env/custom config) will not reach the worker, because the boundary mounts only copies in the task home and never the host home or a keyring socket. Providers whose auth lives outside the listed dot-directories need an env/custom config source to carry credentials across the boundary.

## Environment signals

| Variable | When set |
| --- | --- |
| `MULTICA_ISOLATED_TOOL_BOUNDARY=1` | Agent process inside the worker |
| `MULTICA_HOST_REPO_CHECKOUT=disabled` | Host `POST /repo/checkout` blocked for the task token |

## Verification

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
