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

## Not delivered

### MVP2 — Bubblewrap task worker (#89)

Not implemented on this branch. No `bwrap` policy, worker manifest, IPC
transport or hidden `multica internal-task-worker` command exists yet. Task
execution still runs on the host, so the filesystem-isolation guarantee in
section 1 of the spec is **not** met by this change.

This is deliberate: the sandbox rewires the execution path for every provider,
and shipping it half-wired would be worse than shipping it separately.

### Also outstanding

- **Live provider verification.** The GitHub and Gitea banner parsers are unit
  tested against fixtures, and the host-key pinning is tested. Neither adapter
  has been run against a real provider, so compatibility is not yet claimed.
- **Lease registry scope.** Issued leases live in one server process's memory.
  A deployment that serves the daemon from several instances would need a
  shared store; the failure mode is a refused signature, not a wrong one.
- **Provider selection at claim time.** The claim response carries the
  originator's verified identities with their provider hosts; the daemon picks
  the first repository whose host matches. A user with keys on several
  providers gets the credential for the first repository in the task, which is
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
| Migrations | `make migrate-up` then `make status` |
| Frontend data layer | `pnpm --filter @multica/core test` |
| Frontend UI | `pnpm --filter @multica/views test` |
| Whole backend | `make test` |
| Whole frontend | `pnpm typecheck && pnpm lint && pnpm test` |

The sandbox checks from the spec's acceptance matrix cannot be run: there is
no worker, so there is no boundary to test.
