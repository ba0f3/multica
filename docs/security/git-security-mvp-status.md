# Git security MVP — implementation status

Status date: **2026-10-21**. Baseline: `5080ef180` (`origin/main`, PR #94 merged).
Spec implemented: the 2026-10-20 MVP revision in
[per-user-git-credentials-plan.md](per-user-git-credentials-plan.md) as proposed
in PR #95 — a bwrap worker per task, a per-task SSH-agent signing socket, and
public-key-only credential management.

This file records what the branch actually contains. It does not claim a
deployed runtime, a production key or a proven sandbox.

## Delivered

### MVP1 — Keys and UI (#86)

| Piece | Where |
| --- | --- |
| Key generation, state machine, redaction | `server/internal/r2dgit/identity.go` |
| OpenBao KV v2 custody (CAS 0 store, hard destroy, signer callback) | `server/internal/r2dgit/custody.go` |
| Credential service (profile, generate, verify, revoke) | `server/internal/r2dgit/service.go` |
| Pinned-host SSH verification with provider banner parsing | `server/internal/r2dgit/verify.go` |
| Side tables and queries | `server/migrations/9001*.sql`, `server/pkg/db/queries/r2d_git.sql` |
| Account-scoped HTTP API | `server/internal/handler/r2d_git.go` |
| Human-session gate (`auth_time` claim, PAT excluded) | `server/internal/middleware/human_session.go`, `server/internal/middleware/auth.go`, `server/internal/auth/session.go` |
| zod schemas, API client, query hooks | `packages/core/api/schemas.ts`, `packages/core/api/client.ts`, `packages/core/git-identities/` |
| Account settings section in all five locales | `packages/views/settings/components/git-identities-section.tsx` |

The browser receives the public key, its fingerprint and a state. No response,
schema or component carries a private key or a custody reference.

### MVP3 — Per-task SSH agent (#88)

| Piece | Where |
| --- | --- |
| Task-scoped signing lease and signature service | `server/internal/r2dgit/signing.go` |
| Daemon endpoints `git-signing-lease` / `git-signatures` | `server/internal/handler/r2d_git_sign.go` |
| Originator binding in the claim response | `server/internal/handler/daemon.go`, `server/internal/handler/agent.go` |
| Restricted agent socket (List/Sign only; Add/Remove/Lock refused) | `server/internal/daemon/gitagent/socket.go` |
| Per-attempt socket, `SSH_AUTH_SOCK` wiring and cleanup | `server/internal/daemon/git_agent.go`, `server/internal/daemon/daemon.go` |
| Daemon client calls | `server/internal/daemon/client.go` |

The key follows the task's authenticated originator. The runtime owner, the
agent owner and the audit-only fallbacks never select a key; a task with no
provable originator receives no credential. Revocation marks live leases and
every signature re-reads the key state, so a revoked key stops signing.

Signing is reachable only with a daemon token, and only for a task whose
runtime that daemon hosts. The lease is bound to the daemon that opened it, so
a lease id alone is not a credential. Each successful signature slides the
lease window, so a run longer than the TTL keeps signing; rotating a key marks
the previous generation's leases revoked.

The account endpoints refuse a CLI-issued token. The CLI stores its bearer
token on disk beside the code the agent runs, so it is marked at mint time and
cannot list, create or revoke a credential even though it is otherwise a valid
session.

## Not delivered

### MVP2 — Bubblewrap task worker (#89)

Opt-in: `MULTICA_TASK_SANDBOX=1`. When enabled, every attempt runs inside
`bwrap`; when enabled and the boundary cannot be built, the task fails with
`sandbox_unavailable` and never falls back to the host.

| Piece | Where |
| --- | --- |
| bwrap policy and argv, mount validation | `server/internal/daemon/sandbox/policy.go` |
| Worker manifest over stdin and the frame protocol | `server/internal/daemon/sandbox/manifest.go`, `ipc.go` |
| Worker entrypoint and the IPC-backed backend | `server/internal/daemon/sandbox/worker.go`, `backend.go` |
| Hidden `multica internal-task-worker` command | `server/cmd/multica/main.go` |
| Policy construction, launch and config | `server/internal/daemon/sandbox_launch.go`, `config.go` |

The boundary unshares user, PID, IPC, UTS and cgroup namespaces, drops all
capabilities, sets `--no-new-privileges`, `--new-session` and
`--die-with-parent`, and clears the environment. It mounts the task's checkout,
a private HOME, a private `/tmp`, the read-only system runtime, the per-task
provider config the daemon built, and — when a credential exists — only the
attempt's signing socket. The host home, the shared workspaces root and the
daemon profile are refused as mount sources; a single named file (the signing
socket) is the only exception.

The network is deliberately **not** unshared: tasks clone repositories and call
their model provider.

The agent environment travels in the manifest over stdin, never in argv or the
process environment, because both are readable by every process of the same
user.

### Also outstanding

- **Sandbox is off by default.** With `MULTICA_TASK_SANDBOX` unset, tasks still
  run on the host and one task can reach a sibling attempt's signing socket
  through the daemon profile. The per-task boundary holds only when the sandbox
  is enabled; do not describe the socket as task-isolated otherwise.
- **Sandbox provider auth is unresolved.** A private HOME means the CLI cannot
  read host config files. Providers that accept an API key or token in the
  environment work; providers that need a file under the host home (the shared
  `~/.codex/auth.json` symlink in particular) will not authenticate inside the
  boundary. The per-task config directories the daemon already builds are
  mounted, but the host-home symlinks they may contain point outside the
  sandbox. This needs a provider-by-provider pass before enabling the sandbox
  in production.
- **Run-scoped supplements are unavailable in the sandbox.** The IPC transport
  is one-way after the manifest, so `Session.Supplement` is nil and a task
  running inside the sandbox cannot receive an additional human instruction
  mid-turn. The daemon treats that as "no run-scoped input" and does not claim
  durable input.
- **Only one live kernel test.** The policy and argv are unit tested, the
  launcher is tested against a fake `bwrap`, and `bwrap_smoke_test.go` starts a
  real boundary when `MULTICA_BWRAP_SMOKE=1`: it verifies the checkout is
  writable, the private HOME is in place, and both a host file and a sibling
  task's directory are unreadable. It has not been run with a real agent CLI,
  so the spec's provider-level sandbox checks are still outstanding.
- **Live provider verification.** The GitHub and Gitea banner parsers are unit
  tested against fixtures, and the host-key pinning is tested. Neither adapter
  has been run against a real provider, so compatibility is not yet claimed.
- **Lease registry scope.** Issued leases live in one server process's memory.
  A deployment that serves the daemon from several instances would need a
  shared store; the failure mode is a refused signature, not a wrong one.
- **Provider selection at claim time.** The claim response carries the
  originator's verified identities with their provider hosts; the daemon picks
  the first repository whose host matches. A user with keys on several
  providers gets the credential for the first matching repository, which is
  correct for single-provider repositories and untested for mixed ones.
- **Custody configuration.** `MULTICA_GIT_CUSTODY_URL`,
  `MULTICA_GIT_CUSTODY_MOUNT` and `MULTICA_GIT_CUSTODY_TOKEN` must all be set.
  Without them the service is absent and every credential endpoint answers
  `git_service_unavailable`; there is no local-file fallback.
- **Migration numbers.** `900100`–`900113` are allocated by this change and
  must be recorded in the patch/migration tracker (#12) so a later patch does
  not reuse them.

## Verification

Run from the repository root:

| Check | Command |
| --- | --- |
| Credential core and signing | `go -C server test ./internal/r2dgit/` |
| HTTP surface, claim binding | `go -C server test ./internal/handler/` |
| Agent socket | `go -C server test ./internal/daemon/gitagent/` |
| Socket wiring | `go -C server test ./internal/daemon/ -run TestStartGitAgentSocket` |
| Sandbox boundary (real bwrap) | `(cd server && MULTICA_BWRAP_SMOKE=1 go test ./internal/daemon/sandbox/ -run TestBwrapSmoke -v)` |
| Sandbox launch and policy | `go -C server test ./internal/daemon/sandbox/ ./internal/daemon/ -run 'TestSandbox\|TestBuildArgs'` |
| Migrations | `make migrate-up` then `make status` |
| Frontend data layer | `pnpm --filter @multica/core test` |
| Frontend UI | `pnpm --filter @multica/views test` |
| Whole backend | `make test` |
| Whole frontend | `pnpm typecheck && pnpm lint && pnpm test` |

The views suite is timing-sensitive: its default 5s per-test timeout fails
under parallel load on a busy machine. The suite is green (6177/6177) with
`pnpm --filter @multica/views exec vitest run --testTimeout=30000 --maxWorkers=4`.

The sandbox checks from the spec's acceptance matrix cannot be run: there is
no worker, so there is no boundary to test.
