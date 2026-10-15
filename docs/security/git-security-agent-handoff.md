# Git security — coding-agent handoff

Status: planning delivery, 2026-10-16. No feature implementation or production enablement is claimed.

## Start here

1. Read root `AGENTS.md`, [the accepted implementation plan](per-user-git-credentials-plan.md), feature tracker [#84](https://github.com/r2d-ai/multica/issues/84) and patch-stack tracker [#12](https://github.com/r2d-ai/multica/issues/12).
2. Start with [S0 / #85](https://github.com/r2d-ai/multica/issues/85). Do not assume the historical R2D ACL code is present on current main. The planning baseline was `231dedb55287ab6e40fd103634a024e4d9d1baeb`; refresh live state before coding.
3. Work in a dedicated branch on `r2d-ai/multica`, commit and push there, then open a PR to the fork's reviewed integration branch. Never create a PR or write an issue/comment on upstream for this workflow.
4. Keep one slice or coherent sub-slice per PR. Do not mix upstream sync, historical ACL restoration and new credential code.

## User-visible contract

The user generates a dedicated per-user/per-provider SSH key pair from their profile. A trusted backend generates and stores the private key in encrypted custody; the profile shows only the public key/fingerprint. The user manually adds the public key to their own GitHub/Gitea account and verifies it. The run uses that user's identity through a policy-enforcing broker. There is no key export, private-key reveal or shared admin fallback.

This is not permission to create real keys, use production Git credentials, modify provider accounts, deploy services, reset branches or weaken branch protection. Production changes need their corresponding approved execution step.

## First implementation PR: S0

Deliver a baseline report and testable policy contracts, not a key-upload UI:

- Inspect current fork refs, reserved migrations and current project authorization seams.
- Compare relevant historical R2D ACL PRs with current code; record missing prerequisites without silently rebuilding the entire ACL product.
- Separate authoritative human identity from audit attribution and runtime ownership.
- Define immutable run context plus narrow repo/operation/ref grant, current-rights checks and version/capability negotiation.
- Add fixture-based failing regression tests for identity substitution, absent/fallback originator, task/project mismatch and old daemon refusal.
- Inventory runtime/provider isolation and integration assumptions; document any separately reviewed prerequisite.

S0 is complete only when later agents can implement S1/S2/S4 without guessing who owns a run or which policy is authoritative.

## Work queue

| Slice | Issue | Start condition |
| --- | --- | --- |
| S0 — baseline / contract | [#85](https://github.com/r2d-ai/multica/issues/85) | First |
| S1 — profile keys / custody | [#86](https://github.com/r2d-ai/multica/issues/86) | S0 accepted |
| S2 — identity / delegation | [#87](https://github.com/r2d-ai/multica/issues/87) | S0 accepted |
| S3 — Git broker | [#88](https://github.com/r2d-ai/multica/issues/88) | S1 + S2 contracts and implementation |
| S4 — runtime / cache / sessions | [#89](https://github.com/r2d-ai/multica/issues/89) | S0; integrate S2/S3 |
| S5 — output / bypass / revoke | [#90](https://github.com/r2d-ai/multica/issues/90) | S2 + S3 + S4 |
| S6 — adversarial gate / rollout | [#91](https://github.com/r2d-ai/multica/issues/91) | S1-S5 |

S1/S2 and the S4 scaffold may run in parallel after S0. No production protected-source path may be enabled before the integrated S6 gate. Upstream #7441 is reference code, not a mandatory dependency or blanket cherry-pick.

## Non-negotiable review checks

- Private keys exist only in trusted custody/transport, never in profile JSON, browser storage, task payloads, shared HOME, raw agent SSH sockets or ordinary logs.
- User identity comes from authenticated requests/validated task lineage. Neither display names nor mutable env/headers are proof.
- Child grants cannot grow; changed human means changed context/session. Null or audit-only originators receive no Git credential.
- All protected Git paths, including daemon preparation and finalization, use the broker. Replacing only agent `GIT_SSH_COMMAND` is insufficient.
- A cache hit is still a data access. Cross-user bare repositories, Git object stores and native sessions are not shared into sandboxes.
- Source output is server-classified and audience-restricted. Generic comments, MCP, PR APIs, emails, file previews and exports cannot bypass it.
- Signing a token is not revocation. Local epoch checks, provider-rights proof and cancellation must be tested.
- Git SSH authentication is not commit signing, author attribution or PR/API authentication. Unsupported API routes fail instead of using owner credentials.
- Trusted host-root/control-plane/secret-store compromise remains a documented boundary; do not claim non-exportable hardware custody from KV encryption.

## Repository constraints

New schema uses `r2d_*` side tables. Allocate migration numbers in `900000-999999` through #12 after inspecting existing allocations. No upstream-table custom columns or foreign keys; every concurrent index gets its own migration. Shared UI belongs in `packages/views/`, data/schema/query logic in `packages/core/`. Keep framework code in app layers and protected-mode gates server-authoritative.

Do not introduce ambient-auth compatibility fallbacks. Existing unprotected legacy execution may remain outside the protected environment, but it must not reach protected broker secrets, caches or outputs. Unsupported daemon/runtime means deny, not downgrade.

## Verification and evidence

Use repo-managed environments and current Makefile commands from AGENTS.md. Start with narrow package checks, then backend/frontend/integration checks relevant to changed seams. Use synthetic keys, disposable Git/SSH fixtures and fake agent CLIs by default. Real-account and real-model smoke tests require explicit authorization and the repository's `agentintegration` gate.

Each implementation PR must include:

- Linked slice issue, exact base/head SHAs and migration allocation if any.
- Changed trust boundary and actual behavior, not only a list of files.
- Tests actually run, outputs/check links, negative-control evidence and skipped checks.
- Remaining integration/release gates, outage behavior and rollback semantics.
- Independent security-review findings and fixes before merge.

Do not mark the tracker complete for a profile-only demo or successful happy-path clone.

## Cursor update format

Update #84 after each slice and #12 after patch/backport/migration changes:

```text
Date:
Slice / issue:
Base SHA:
PR / head SHA / merged SHA:
Migrations allocated / merged:
Tests actually run / CI evidence:
Security gates still open:
Upstream refs checked (not automatically merged):
Next action:
```

The planning document has no application behavior change. Documentation verification does not establish that key custody, sandboxing, Git transport or revocation currently work.
