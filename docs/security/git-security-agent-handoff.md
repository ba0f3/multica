# Git security — coding-agent handoff

Latest continuation source/test checkpoint:
`dafa551b94a272d7f62cad54c082d850a71bd270`, based on `e32c17ec5`.
The [reviewable local candidate](protected-local-candidate.md) gives the supported
contract, reproducible checks and concrete deployment prerequisites. The
[completion matrix](protected-completion-matrix.md) and
[actual application surface inventory](protected-source-surfaces.md) supersede the
historical status below. This checkpoint adds historical default-deny across
application readers and delivery sinks, bounded recursive source union, exact
assignment attestations and independent-domain restore detection/reconciliation.
Team remains Workspace; explicit cross-workspace project grants and immutable
originating-human identity remain authoritative. Production startup still supplies
nil configuration and refuses the protected legacy worker graph.

The selected adapter is the compiled `cmd/protected-provider` direct HTTP Responses
implementation through the per-user protected gateway. It does not select a native
Codex/Claude CLI or the server assist SDK. Existing limits remain: small text
repositories, no generic tools/MCP/native resume and existing unprotected GitHub
feature refs only.

The [local authentication/serving composition](protected-local-serving.md) now
provides fresh existing-account OTP proof, opaque protected sessions, a fixed
control page, separate TLS human/mTLS broker listeners and owned protected-worker
shutdown. All listeners are loopback-only and explicitly configured. Generic
login/source routes remain held; the new control server imports no legacy auth,
profile narrative, CDN authority or native worker path. Production main still
selects no protected configuration.

The selected contract and explicit provider/policy limits are recorded in the
candidate guide. Production selection/configuration and a quiescent transition
require separate operational acceptance. In-flight legacy bodies, prior CDN
authority and native/MCP state cannot be recalled by these guards.
Dedicated VM/image/kernel/network acceptance, live custody/enrollment, real
provider/ACL-change checks, external key/CDN reconciliation and independent-domain
restore drills remain unperformed. Combined rollback of DB and external witness
is outside the trust boundary. Credentials alone do not close these gaps.

The complete guarded agent race suite now passes under an owned adopting test
parent, with final ECHILD and no forced cleanup. The serialized backend run passes
the repaired paths and retains four recorded baseline MCP/public-file assertions.
Historical reaper failures remain recorded without an invented failed-phase cause. See the latest section of
[the review report](git-security-local-review.md) for exact frozen checks,
independent review, baseline comparisons and remaining failures. Only synthetic
fixtures and local commits were used; no upload, push, deployment, live enrollment,
model call or host-policy change was performed.

The earlier checkpoint descriptions below are retained as history.

Status: local implementation checkpoint, 2026-10-16 UTC. Durable S0/S1/S2 plus local SSH reads/writes, an unmounted push-only smart HTTP bridge, and restricted output/download revocation software exist; protected execution remains disabled.

Local implementation evidence and remaining blockers are recorded in
[the local review report](git-security-local-review.md). That delivery is a
durable admission/profile implementation plus pinned synthetic SSH reads/writes,
restricted output delivery and integrated historical/lifecycle output boundaries
at source/test `875d0152a26e1825807656e6064280b161f90a56`. The latest continuation
closes the finite read-only application workflow with the actual Linux
`cmd/protected-agent` executable and fixed image-provider JSON protocol. It includes
bounded provider output/cancellation and standalone adopted-child reaping, tested
with detached descendants and real compiled-command A/B execution.
[The finite acceptance contract](protected-entrypoint-acceptance.md) separates
remaining software from deployment/live-validation prerequisites.
The preceding application continuation
adds signed operator-registration interfaces and a protected application coordinator:
durable run reload and claim, authenticated read snapshots, fresh private checkout,
restricted result receipt/acknowledgement, observed clean exit and metadata-only
completion with ordinary receipt settlement. Admission journals preserve exact
attempt recovery across crashes and DB outages. Tests use human admission/router,
real local DB/Git, a fake HTTP engine, real UDS/mTLS and a test-created helper process.
The previous Docker supervisor checkpoint is `3058202e3f725b8c1e183d066e0f4b0147f07bb5`.
It builds on progress-only
task projections and service-level dispatch/failure/recovery fences. Historical
session/workdir pointers remain stored; this does not certify native resume
isolation. The preceding write
checkpoint is `900cf51e8ccd13ee868187177868889f41e427c3`. Protected execution stays
disabled; this does not complete the rollout gates below.

The accepted S4 backend is a dedicated Linux worker VM with a hardened per-run
container and an outside-workload trusted channel. The plan does not select an
engine or channel identity backend. Local Docker probes demonstrate some resource
and kernel restrictions, but identity UID mapping and no approved/reported
AppArmor profile evidence cannot certify the required boundary. User namespace
creation also fails locally. The local pilot component now targets Docker; VM
placement, effective configuration acceptance and trusted channel provisioning
remain operator prerequisites; do not enable runtime capabilities or
treat the local Docker adapter or successful fake tests as containment proof.
The supervisor/application remain unconstructed in production. Registration and
prepare/read/output interfaces are implemented and synthetically verified; real
operator containment acceptance, production composition/dispatch,
native-provider/write/child orchestration and live enrollment/custody/provider
adapters remain missing. See the latest review section for deployment permissions,
probe evidence and verification limits.


The next action requiring infrastructure is provision/accept the dedicated worker VM,
user namespace and enforced profiles, build the fixed digest-pinned entrypoint image,
and supply reviewed live enrollment/broker trust material. Those actions remain
outside the local-only authorization. Do not enable a runtime capability from a
successful synthetic signature or fake engine observation. The default
`Service.Current` runtime and human admission execution flag remain ineligible.
Application construction also requires the ordinary same-transaction terminal
receipt settlement adapter; it has no nil/default compatibility path.

Recovery is refusal, never resume: engine cleanup is followed by exact immutable
attempt private failure, dependent receipt settlement and audit before the
application journal is removed. DB uncertainty retains the journal and denies new
prepare. A successful final result requires a restricted durable output, explicit
channel-bound receipt acknowledgement, canonical exit-zero observation, successful
cleanup and a fresh current-rights private completion transaction. Output remains
subject to the reader's own current provider identity and all existing ACL checks.
The canonical queue status makes a completed run non-executable; private completion
does not upgrade context locks, preserving concurrent child-admission ordering and
already-issued descendants of normally completed ancestors.

The full-run scanner-cleanup and Cursor timing failures remain unresolved. A new
untouched baseline full agent run now reproduces the Cursor late-descendant
assertion; earlier focused passes and that reproduction do not explain its cause.
Final independent review has no blocking finding within the disabled boundary:
38 handler race cases and two command race cases pass at the exact source
checkpoint, with scoped vet passing. The full current agent race suite fails23
cases, all with baseline reproductions across runs; the full regular suite before
the command-only reaper closure fails six baseline-reproduced cases. See the
review report for exact commits, logs and verification limits. This finite local
task is complete; production PR92/S0–S6 completion remains blocked by the software
and real-validation prerequisites in the acceptance contract.

## Start here

1. Read root `AGENTS.md`, [the accepted implementation plan](per-user-git-credentials-plan.md), feature tracker [#84](https://github.com/r2d-ai/multica/issues/84) and patch-stack tracker [#12](https://github.com/r2d-ai/multica/issues/12).
2. Review the implemented [S0 / #85](https://github.com/r2d-ai/multica/issues/85) identity/current-rights contracts and the exact local checkpoint in the review report before extending the broker/runtime boundary. Do not assume historical R2D ACL code is present. The production-code baseline remains `231dedb55287ab6e40fd103634a024e4d9d1baeb`.
3. The current authorization is local commits only on `r2d-ai/multica`. Publishing, pushing or opening a PR requires a later authorized step. Upstream remains read-only; never create a PR or write an issue/comment there for this workflow.
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
