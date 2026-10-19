# Protected source boundaries and restore recovery

The [current source candidate](protected-local-candidate.md) records exact local
verification and deployment prerequisites.

This continuation implements a disabled, local enforcement composition. Unknown
historical source is denied; current membership or moving an object does not
classify its prior contents. Team remains the existing Workspace. Explicit
cross-workspace project grants and the original human identity remain the
protected Git authority; administrative agent ownership supplies neither.

| Application surface | Enforced boundary |
| --- | --- |
| Issue/project bodies, comments, task history, chat/session history, drafts, inbox, search and search-index exports | Global source middleware denies generic routes while any protected repository, quarantine or restore anchor exists. New routes inherit denial. The fixed, content-free `/health` liveness response remains available during policy/DB failure. |
| Login/profile/onboarding, share-link previews, ordinary session/bootstrap API | Same pre-authentication denial; stored narratives/names cannot bypass the authenticated route groups. |
| Signed downloads, user/legacy storage keys, local uploads, avatar and plugin surfaces | Readerless capabilities denied. A caller header is not a current Git reader. |
| Restricted Git identity/run/output routes | Exact route/method allowlist; existing session/task authentication, sealed scope and current rights still required. Project titles omitted from profile options and their ordering. |
| CDN session renewal/refresh | Broad CloudFront capability issuance suppressed by the current source policy, including on allowed Git controls. Previously issued CDN authority requires separate operator invalidation. |
| WebSocket delivery | Current global source policy in actual writer membership checks, including captured frames on existing connections. |
| Legacy daemon claims/RPC and internal public task details | Production TaskService uses source authority; existing RPC claims fail closed. Protected tasks retain the earlier sealed-task refusal checks. |
| New event-bus deliveries | Global source guard runs before all listeners, including unrelated workspace events with unknown provenance. |
| Queued plugin hooks | Actual HTTP attempt, redirect and retry guard; enqueue-time checks alone are insufficient. |
| Telegram/Lark/DingTalk/Slack channel text/media/fallback sends | Current guard at HTTP transport, including default and supplied clients and Slack SDK factories. Detached direct replies also check. |
| WeCom Redis replay/queued socket frames | Current guard at actual socket writer; media HTTP requests also guarded. |
| Invitation mail | Method entry, SMTP DATA boundary and Resend HTTP transport guard. |
| Queued analytics/telemetry and server assist LLM | Actual network attempt guard; telemetry also guards durable pending-body delivery. This assist LLM is separate from the selected protected provider. |
| Restricted output and trusted derived-output composition | Immutable originating context plus union of every declared trusted input; recursive current-origin/current-reader checks on every delivery chunk. Missing/deleted/cyclic provenance is denied. Public workload requests cannot select source IDs. |
| Issue assignment supplied to selected workload | Signed trusted classification of exact title/description digest, project/provider/repository and expiry. No automatic historical relabelling from current project location. |

The production `main` installs policy before legacy relay/analytics/worker
construction and refuses the legacy worker graph when protection evidence or an
invalid expected witness exists. It still supplies no protected deployment
configuration. The [explicit local server](protected-local-serving.md) now serves
fresh protected
login and a fixed control page on separate loopback TLS/mTLS listeners, without
constructing the legacy graph. Production main still selects no protected config;
there is no deployed or automatically enabled protected listener. Generic UI and
ordinary login remain unavailable under a source hold.

A hold is an intentional availability restriction. It does not recall bytes
already delivered, CDN credentials already minted, an HTTP/SMTP/socket body
already in flight, or source already held by an old native agent/MCP/provider.
Transitioning an ordinary process into protection requires quiescing legacy work
and reviewing external authority. Hot transition and existing ambient work are
unsupported acceptance gates. No local fake proves host isolation or revocation
of an independent external provider.

Restore detection uses a private Linux witness outside the database/credential
backup domain. Startup never creates or resets it. DB/witness mismatch, missing
expected witness, missing or ambiguous DB anchor and unavailable verification
fail closed. A dedicated fresh read-only pool avoids old caller snapshots and
caller-pool starvation. Read-only authorization finalization also compares its
snapshot checkpoint under the same lock; only five audited pure DB reads may
retry a stale snapshot, at most three times. A real mismatch stays closed.
The file lock spans durable advance through DB commit;
a bounded cancellation-independent finalization prevents caller cancellation
from abandoning an already advanced ordinary write. Crash/commit failure after
external advance remains closed and requires explicit reconciliation. Combined
rollback of both trust domains remains outside this boundary.

Reconciliation is trusted service tooling, with no HTTP recovery endpoint. It
requires a quiescent instance and quarantines every surviving workspace/user/
project, including scopes whose post-backup provenance was lost. It invalidates
pending protected authentication challenges and sessions, cancels active task rows,
revokes all
restored keys, contexts and grants, queues key cleanup and invalidates runtime
acceptance, assignment attestations and execution approvals. Cleanup of external
keys absent from the restored DB still requires external inventory/reconciliation.
Fresh signed per-project governance approval creates explicit managers without
workspace-admin promotion. Fresh exact human/workspace/agent/runtime/project
execution approval, current rights, consent/key activation, assignment
classification and runtime acceptance are separate prerequisites. Expired
execution approval also denies historical/nested derived output. Ordinary
membership, offboarding, invocation/binding and task lineage/status mutations in
held scopes require a witnessed transaction or are denied by the DB guard.

The selected compiled provider is the bounded JSON/text Responses implementation
in `cmd/protected-provider` with the per-user `ResponsesGateway`; it is direct
HTTP through the protected broker. It does not select a native Codex/Claude CLI,
resume native sessions, forward generic MCP or use the server assist SDK.
Supported repository/edit/provider-policy limits from the completion matrix
still apply. Dedicated VM/image/kernel/network acceptance, real provider ACL/
policy checks, live custody/enrollment, CDN invalidation and independent-domain
restore drills remain unperformed. Fixtures use deterministic synthetic keys and
local HTTP/Git/database processes; production stays disabled.
