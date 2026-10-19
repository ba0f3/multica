# Protected workflow completion matrix

Starting checkpoint: `b0bd80b20f954cbcb84a06dda2c87f7653c86bed`.
Model/edit checkpoint: `ec8ff664e075400389ee84ad099ad173225e8184`.
S5/restore checkpoint: `8b6be5bcd611c6cc6eb8590a1726eb980f5cd3ce`.
Latest local serving source/test checkpoint: `dafa551b94a272d7f62cad54c082d850a71bd270`.
Production remains disabled throughout local implementation. Fixtures use
synthetic identities, keys, TLS, custody, Git and model responses; no live account,
provider call, worker provisioning or host policy change is part of this work.

The first coding adapter is a bounded, non-streaming Responses adapter. A trusted
gateway selects the model and credential for the sealed user/context/attempt;
the workload cannot select an endpoint, model, account, credential or tool. Its
only transport is the authenticated per-run Unix socket. No native login/session
or shared CLI credential is imported. Other providers remain unavailable.

The Git boundary remains one explicitly granted repository, pinned SSH transport,
and exact feature-ref compare-and-swap finalization. Task data cannot select Git
URLs, provider identities or secret paths. LFS, submodules, signing, PR/API access,
protected/default ref updates and scheduled/webhook roots remain unsupported.
Team remains Workspace; an explicit cross-workspace project grant does not
require resource-workspace membership.

| Stage | Required software evidence |
| --- | --- |
| 1. Scope | This fixed matrix, default refusal and explicit unsupported operations |
| 2. Credentials/enrollment | Explicit dependency composition, bounded maintenance, authenticated issuer transport, persisted signed operator acceptance, rotation/revocation/refusal tests |
| 3. Model | One executable provider adapter, authenticated gateway, same-user/attempt authorization, fixed upstream contract, bounded source/result and cancellation tests |
| 4. Writes/delegation | Exact-ref finalization, mutation ambiguity refusal, separately isolated child dispatch, durable fresh retry semantics |
| 5. Output | Bounded recursive source union, exact assignment attestation, current-reader/chunk checks and global denial of unknown historical source; no automatic public backfill |
| 6. Composition | Disabled production startup, protected-only factory, mandatory recovery, atomic terminal settlement and witnessed restore quarantine/reconciliation; explicit loopback authentication/control/broker serving exists; production selection stays disabled |
| 7. Acceptance | Actual composition with synthetic dependencies, positive/negative authorization, applicable checks and independent review at a frozen local commit |

## Implemented continuation

The factory composes explicit credential workers, bounded provisioning cleanup,
the configured enrollment client, signed persisted operator acceptance and online
revocation, the broker, application, recovery, protected-only queue dispatch and
ordinary same-transaction terminal receipt settlement. Optional fresh retries
remain disabled unless explicitly configured. Production supplies nil configuration;
there is no environment flag that enables this path. Construction or a synthetic
acceptance signature does not make `Service.Current` runtime-eligible.
The mTLS enrollment issuer and client are implemented and separately tested;
the disabled factory does not construct or serve the issuer.

The compiled `cmd/protected-provider` uses the run's authenticated Unix socket to
call a trusted Responses gateway. The gateway selects an explicit user account,
allowed project, fixed endpoint/model and expiry; no owner/admin fallback, native
login, tool execution, model-selected URL or environment credential lookup exists.
The fixed request is non-streaming with `store:false`. Model source delivery uses
current-rights checks, cancellation and accepted-byte audit accounting. Synthetic
TLS fixtures are the only model services exercised.

The adapter accepts at most 32 text files/32KiB of source within 256 directory
entries, and at most 16 changed files / 32 KiB. Binary, symlink, oversized and empty
repositories are refused. Changes cannot delete files or address hidden/escaping
paths. The entrypoint builds a fixed-metadata commit/pack locally; server-held
write authority chooses the sole exact feature ref, validates quarantine and
performs compare-and-swap. A failed/ambiguous finalization cannot be converted to
successful private completion. No mutation is automatically replayed.

The concrete GitHub policy adapter proves the same account with `/user`, rejects
the current default branch, requires an existing explicitly unprotected branch,
and rejects effective repository/organization rules, pagination or unknown state.
It deliberately refuses missing branches: creating branches safely also requires
proving classic protection patterns. Gitea write-policy support remains missing.
These are software scope limits, not gaps that supplying live credentials closes.
The existing synthetic S3 bridge tests do not establish live-provider acceptance.
The contracts were checked against official
[authenticated-user](https://docs.github.com/en/rest/users/users#get-the-authenticated-user),
[effective branch rules](https://docs.github.com/en/rest/repos/rules#get-rules-for-a-branch)
and [Responses text](https://developers.openai.com/api/docs/guides/text) documentation;
no private repository, key or source was sent to those services.

Child requests derive the human and grant from the server-held parent channel and
return a new context ID, never a reusable parent credential. Every child receives
fresh prepare/claim/isolation. A failed run may receive a fresh task/context/attempt
under its original human, root, maximum attempts and expiry. Durable retry edges
allow only that failed predecessor in the new lineage; they never reactivate the
old attempt. Root revocation, cancellation, rights/key loss and uncertain or
successful root-chain mutations deny retry. A shared database advisory lock fences
retry admission against old-attempt write-intent creation.
Fresh retries may repeat failed read/model requests within the original bounds;
the uncertainty prohibition concerns Git mutations, not exactly-once model calls.

## Source and output surface inventory

The [actual surface inventory](protected-source-surfaces.md) records the router,
readerless storage/CDN, WebSocket, bus, daemon, plugin, mail/channel, analytics,
telemetry and assist LLM boundaries. Generic routes fail closed globally whenever
any protected repository, quarantine or restore anchor exists; the fixed,
content-free exact GET `/health` response remains available. Policy is installed
before legacy delivery construction. This enforces denial of unknown historical
source without pretending to classify it from current location or membership.

Restricted outputs preserve their own sealed source and every trusted input's
originating context. Provenance is bounded to eight inputs, 64 unique sources and
eight recursive levels; missing/deleted/cyclic edges, any revoked origin/ancestor,
expired execution approval or reader-key loss deny delivery. Every chunk rechecks
current authority. Public workload requests cannot choose source IDs. Assignment
text separately requires an exact fresh signed operator digest classification.

A private Linux file witness outside the database backup domain and a singleton
DB anchor detect rollback/missing or uncertain state. The lock spans durable
advance and DB commit; fresh independent verification avoids old caller snapshots
and pool starvation. Read-only finalization compares its own snapshot under that
lock; only audited pure readers may retry a stale snapshot, at most three times.
Uncertain mutation commits never retry. Reconciliation requires quiescence,
quarantines every surviving workspace/user/project, cancels active tasks, revokes
restored keys/contexts/grants, invalidates pending authentication challenges and
sessions, and invalidates old acceptance/classification/
execution approvals. Fresh per-project governance, exact human/agent/runtime
execution approval, key activation and classification are separate prerequisites.
Ordinary authority mutation in held scopes requires a witnessed transaction.

This is enforce-or-deny local software, with deliberate availability cost. It does
not backfill public historical classifications, recall already delivered/in-flight
bodies, revoke prior CDN authority or sanitize old native/MCP state. The
[local protected-control server](protected-local-serving.md) now provides
fresh OTP authentication, a fixed page, opaque short-lived sessions and separate
loopback TLS/mTLS serving. It constructs no legacy worker/delivery graph and
retains source/restore checks on every request/chunk. Production main still selects
no protected configuration; accepted deployment selection/operation remains outside
this local composition.
A quiescent transition, external key/CDN reconciliation, independent-domain restore
drill and live isolation/ACL acceptance remain rollout gates. Combined rollback
of both trust domains remains outside the boundary; production stays disabled.

## Verification

Exact frozen review, test logs, failures and baseline comparisons are recorded in
[the local review report](git-security-local-review.md). The synthetic composition
executes the actual provider/entrypoint, real Git, DB, UDS and TLS with fake engine,
custody, model and upstream Git dependencies. It covers user A success, user B denial,
revocation, forged selectors, read-only writes, ambiguous CAS, child separation,
fresh retry, shutdown cancellation and the nil production configuration.

The existing 45-second entrypoint and one-minute enrollment are deliberate finite
budgets. The first adapter must fit them; increasing or renewing them requires a
separate explicit policy/protocol change and revalidation. A timeout never resumes
a native session or repeats a possibly committed Git mutation.

Local software evidence does not accept a VM, namespace, UID mapping, seccomp,
AppArmor, cgroup, network policy, live custody/enrollment, real coding provider or
restored production data. Those require the separate operator acceptance in
[the entrypoint contract](protected-entrypoint-acceptance.md). Incomplete stages
must be reported; this disabled local composition does not complete S0–S6 rollout acceptance.
