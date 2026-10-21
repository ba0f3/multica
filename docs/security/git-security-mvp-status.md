# Git security MVP — implementation status

Status date: **2026-10-21**. Branch: `feature/git-security-mvp`. Spec revision: `877dbe95a1fb3d5047091b0ca0d8ab0921de7939`.

[Spec](per-user-git-credentials-plan.md) targets **Docker per attempt** for Codex, Cursor Agent, and OpenCode. [Handoff](git-security-agent-handoff.md) tracks remaining integration work.

## Docker worker (#89) — partial

| Item | State | Evidence |
| --- | --- | --- |
| Docker `run` launcher, private mounts, resource flags | **Implemented** | `server/internal/daemon/sandbox/docker.go`, `sandbox_launch_docker.go`; `go test ./internal/daemon/ -run TestDocker -count=1` **pass** |
| `MULTICA_TASK_SANDBOX=docker`, protected mode | **Implemented** | `server/internal/daemon/config.go` (`MULTICA_TASK_PROTECTED`, `MULTICA_DOCKER_*`) |
| Task worker image scaffold | **Added** | `docker/task-worker/Dockerfile` (not built in CI here) |
| Real Docker daemon integration | **Blocked** | VM has no `docker` CLI/engine (`which docker` missing) |
| Native agent matrix (Codex/Cursor/OpenCode) | **Not run** | Requires image build + authorized real-agent smoke per AGENTS.md |
| Network deny policy on live bridge | **Not run** | Code accepts `MULTICA_DOCKER_TASK_NETWORK`; no live firewall tests |
| Git prepare/finalize entirely in container | **Hybrid** | Host prepare + repocache; **host `/repo/checkout` blocked** when isolated — see [git-lifecycle-in-worker.md](git-lifecycle-in-worker.md) |

## Signing / principal (#88) — partial

| Item | State | Evidence |
| --- | --- | --- |
| Unique `attempt_id` per run | **Implemented** | `daemon.runTask` → `backendConfig.AttemptID`; manifest + git socket dir |
| Per-attempt signing lease field | **Implemented** | `OpenSigningLease(..., attemptID, ...)`; daemon client + handler |
| Lease TTL cap (no infinite slide) | **Implemented** | `maxSigningLeaseLifetime` in `r2dgit/signing.go`; `go test ./internal/r2dgit/ -count=1` **pass** |
| Task token → CLI JWT blocked | **Implemented** | `IssueCliToken` rejects `X-Actor-Source=task_token` |
| Full task API authority matrix | **Not run** | Needs DB-backed handler suite with task bearer |

## Credentials (#86)

Existing UI/API/custody from branch baseline **retained**. No new gaps addressed this revision beyond lease/attempt binding above.

## Tests executed (this revision)

| Command | Result |
| --- | --- |
| `go -C server test ./internal/daemon/sandbox/ -count=1` | **pass** |
| `go -C server test ./internal/daemon/ -run 'TestSandbox|TestDocker|TestProtected|TestIPCBackend|TestBuildDocker|TestContainer' -count=1` | **pass** |
| `go -C server test ./internal/r2dgit/ -count=1` | **pass** |
| `go -C server test ./internal/handler/ -run 'TestOpenGitSigning|TestAgentEnv_TaskToken' -count=1` | **pass** (DB tests skip when no DB) |
| Docker image build / live container smoke | **blocked** (no Docker); manual steps: [docker-task-worker-manual-test.md](docker-task-worker-manual-test.md) |
| Real-agent / provider Git smoke | **not run** (no authorization) |
| `pnpm typecheck` / full `make check` | **not run** (scope: server isolation slice) |

## Production enablement gaps

1. Build and pin `multica/task-worker` image digest; install Docker (rootless or hardened rootful) on task nodes.
2. Run eight acceptance checks from spec on real backend (A/B isolation, network canaries, limits, teardown).
3. Move task Git prepare/finalize off host paths; gate host checkout APIs for protected tasks.
4. Complete native Session IPC validation under real Codex/Cursor/OpenCode versions inside the image.
