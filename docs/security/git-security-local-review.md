# Local Git security implementation and review

Date: 2026-10-16 UTC. References: [PR92](https://github.com/r2d-ai/multica/pull/92), S0–S6 [#85](https://github.com/r2d-ai/multica/issues/85)–[#91](https://github.com/r2d-ai/multica/issues/91).
Branch: `feat/git-security-local`. All commits remain local. The development
executor is usable. Protected execution is blocked on the missing production
software and separate operator acceptance described in the final continuation below.
Full backend checks retain the failures detailed below.

**Protected execution remains disabled.** The local software includes durable
human admission, per-user key management, pinned SSH read/write transport, an
unmounted push-only smart HTTP bridge, bounded full-history pack validation and
restricted output storage/delivery, plus a Docker supervisor/channel and protected application lifecycle
verified with a fake engine, synthetic enrollment and a test-created helper. This is an executable synthetic checkpoint, not
completed S0–S6 rollout acceptance.

Current local source/test checkpoint: `dafa551b94a272d7f62cad54c082d850a71bd270`.
The [current candidate](protected-local-candidate.md) records the finite supported
contract and focused failure resolution. The latest local authentication/serving,
S5/restore and model/edit composition and remaining gates
are in [the completion matrix](protected-completion-matrix.md), which supersedes
the earlier read-only status and implementation tables below. The continuation
verification record is appended at the end of this report.
Previous source/test checkpoint: `875d0152a26e1825807656e6064280b161f90a56`.
The final finite entrypoint acceptance boundary and remaining software/deployment
gaps are in [the acceptance contract](protected-entrypoint-acceptance.md).
Previous application checkpoint: `c42ec73ca948a42ac04833028a1bc8a384d2f54d`.
The application and final entrypoint continuations are detailed at the end of this report.
Previous Docker supervisor/channel checkpoint: `3058202e3f725b8c1e183d066e0f4b0147f07bb5`. Previous lifecycle/output
checkpoint: `63e7fcd4fd9e13eb50a04a737f3a1c6d6c128ae2`. Previous broker write checkpoint:
`900cf51e8ccd13ee868187177868889f41e427c3`. Previous source checkpoint:
`721c984be342525c310d49d1e039b30a91a17aa6`.
Additional test-only real database lock regression:
`77babacf38e20eb6fa643819ad1ff95182b99f5f` (production source unchanged).
Recovered and verified prior checkpoint: `eb6446912c659cc3bdfbf917e421cd922ea29b50`
with documentation HEAD `d7b588acff4e7e256a8cdf31b4acf46c0eb1c2d1`.
Transport/output feature: `26360041aa95a01142dcc775ca90b8e14ff5405a`.
Claim fixture follow-ups: `2c0336818b619a1a239675e49dc0988b410eab4c` and
`fead134dea40816f79070444e15d474c09146c9d`.
Previous reviewed source: `8e172012c6a747b7e658f6d45e40c4a74c3475f4`;
resumed from documentation HEAD `410d624ee8fc53ca5961cd8c6cff104c89bc54ef`.
Original production-code baseline: `231dedb55287ab6e40fd103634a024e4d9d1baeb`.
Planning PR head: `207cf4cae5f79f0556df9e2490383449ab665af4`.

## Authorization and existing project semantics

The historical ACL cursor `d14b6f579587ff94e347657d20a1b6ce735f53c3`
is not an ancestor of current main. Historical `r2dauth` and migration900000
are absent. Ordinary project APIs remain workspace-bound. The new narrow
`r2d_git_project_policy` and explicit user/workspace grants do not restore the
historical ACL stack or change ordinary project discovery.

**Team = Workspace.** A direct project grant may authorize a human from another
workspace without resource-workspace membership. A workspace project grant
follows current membership. Workspace governance can manage the policy; agent
ownership, global-observer status and membership alone confer no protected Git
access. Admission separately checks execution-workspace membership, agent
invocation, resource issue/project binding and project contribute rights.
Agent/squad inventory remains workspace-private.

All schema changes use R2D side tables, no upstream columns or foreign keys.
Provisional local migration allocation is 900100–900129; see
[allocation and rollback notes](git-security-migrations.md). No tracker or
production allocation was changed.

## Implemented software and remaining gates

| Slice | Local behavior implemented | Still incomplete |
| --- | --- | --- |
| S0 | Verified human-session context retains original authentication time; immutable human/root/parent/attempt and separate execution/resource scope; narrow current-rights adapter; atomic admission/audit; server and daemon fail closed | Complete agent/provider policy limits, operator-certified runtime and all-path acceptance |
| S1 | Owner-only profile API/shared web/desktop UI; public key/fingerprint only; durable fenced provisioning, consent, reconciliation, tombstone/retry cleanup, account continuity and monotonic rotation; pinned GitHub/Gitea SSH account verification; TLS KV signer adapter | Real provider/custody configuration, enrollment and backup/restore acceptance |
| S2 | Distinct direct-human runs; exact task-token-bound children preserve originator and narrow grants; full current lineage revalidation and root revocation | Broker wire capability/introspection, protected retry/recovery, cancellation supervisor |
| S3 | Same-user/key live proof, short operation/channel leases, pinned SSH reads and single-ref CAS pushes, full reachable-history quarantine, unmounted push-only smart HTTP v0 adapter, stable wire mutation IDs, durable intent and read-only reconciliation, active write cancellation | Certified workload channel/token adapter, production provider protected-ref policy verifier, general fetch wire protocol and integrated runtime acceptance; broader history/large-repository support |
| S4 | Local Docker supervisor, UDS/mTLS channels, signed exact-run registration interfaces, application prepare/read/private checkout/output acknowledgement/clean-exit completion, admission and engine recovery, fresh state and spent identities; synthetic application integration | Production composition/dispatch/enrollment and native provider/write/child orchestration, actual Linux/VM containment, custody/provider and rollout acceptance |
| S5 | Immutable server-classified output store; exact task writer; reader's own live provider proof; current originator/all-ancestor checks; audit intent/deny/prepared; deadline-bound HTTP1/2 restricted downloads; generic task-token/daemon fences; allowlisted task history and singleton responses; service-level dispatch, progress, completion/failure and pending recovery boundaries | Complete legacy/historical classification across every API/WS/search/export/MCP/download; native pointer/session isolation; process/WS/other-stream revocation bounds; full external ACL-change acceptance |
| S6 | Synthetic A/B local SSH/TLS/real Git packs, real local DB/router tests, authorization negatives, resource/deadline tests, migration round-trip and independent review | Actual isolated runtime/provider acceptance, restore drill and measured workload/other-stream cancellation; router→fake engine→real socket/TLS→synthetic provider→restricted-output software fixture now exists |

## Execution and key boundary

Recent verified human login is required for account mutations and direct admission;
original `auth_time` survives CLI exchange/renewal. PAT/task-token exchange cannot
manufacture human consent. Existing cookie CSRF and desktop bearer contracts
remain. Public input takes structured provider/resource IDs and never keys,
secret paths, human overrides or header-supplied grants.

`POST /api/me/git-runs` creates queue/context/grant/audit atomically. The shared
agent owner supplies neither identity nor connected-app token.
`POST /api/git-runs/{contextId}/children` binds the authenticated parent task,
agent and execution workspace; sealed lineage supplies the human. Current rights,
policy/key locks, narrow grants and cancellation checks apply to descendants.

Admission returns `execution_available:false`. Production construction supplies
no key generator/custody/verifier/output-prover dependencies. Management reports
unavailable and protected execution cannot obtain certified runtime rights. The
server detects protected project references, stored contexts and bounded
parent/retry/delegation/rerun lineage at response construction, token commit and
both start paths. Missing policy/errors deny. Unknown daemon versions deny.
Arbitrary shell text is not repository classification; network/filesystem
execution isolation remains an essential S4 gate.

The explicit Ed25519 generator and OpenBao KV-v2 CAS0/hard-destroy adapter exist,
but only deterministic synthetic keys and local fake TLS services were used.
The signer callback checks the stored public fingerprint before SSH authentication.
Pending verification after identity revoke may verify a new matching generation;
verification does not reactivate it. Explicit activation is required. Private
material never enters public response types, key files, agent sockets, subprocess
arguments or transport diagnostics. Clearing buffers is best effort; KV encryption
is not hardware non-exportability.

Workspace deletion revokes affected chains transactionally, removes owned
policies/repositories and deleted-workspace grants, and invalidates foreign
project policy epochs. Human keys, jobs, immutable run/output history and audit
records are retained; current authorization denies later delivery.

## Concrete local transport

The worker accepts catalog IDs, a safe owner/repository pair and operator-supplied
IP prefixes. Every resolved address must be allowed; it dials the checked literal
IP and pins the SSH host key. It uses only the bound Ed25519 identity, user `git`,
fixed upload-pack/receive-pack commands and no ambient SSH config/agent/forwarding/password.
SSH, custody and validator work receive bounded contexts. Host/identity/generation
substitution, unlisted destinations, malformed advertisements and invalid packs
deny. Reads support HEAD/SHA-1; the write slice supports a single explicitly granted
task ref. Empty/default-branch-unknown and unsupported repositories deny. Client
URLs, argv, arbitrary refs and general Git protocol are not supported.

GitHub verification requires the pinned account banner and exit1. Gitea requires
the account-key banner and exit0; deploy-key and principal banners deny. The Gitea
grammar follows [official serv.go](https://github.com/go-gitea/gitea/blob/main/cmd/serv.go).
Synthetic fixtures establish parser/transport behavior; supported deployed Gitea
versions and provider account-continuity behavior remain acceptance gates.

The Linux pack subprocess has a new temporary object DB, sanitized environment,
empty templates/hooks disabled, no network protocol, a five-second wall deadline,
process-group kill, CPU/address-space/file-size/fd/core limits and explicit
single-thread Git parsing. Per-run PID limits require the S4 boundary. Strict
index/pack checks, pack checksum/framing, object count/expanded-size limits and
closed-graph fsck precede return. Every reachable commit tree (at most 256) rejects
gitlinks, `.gitmodules`, `.lfsconfig` and `.gitattributes`; no checkout occurs. The
process uses the same host UID and lacks namespace/seccomp/filesystem isolation;
it is **not** the S4 workload sandbox and must not enable execution.

The SQL journal rejects replay after restart and preserves operation identity.
Pending/indeterminate writes can be observed by the same authorized identity
without changing the original record or retrying a mutation. The push-only wire
adapter remains unmounted; production has no certified runner channel.

## Restricted output behavior

`POST /api/git-runs/{contextId}/outputs` accepts only exact task-session writers
and four content kinds. Classification derives from sealed grants, never the
payload. The initial slice supports one repository grant; unsupported unions
deny. Immutable output rows produce no generic comments, search rows, narrative
WebSocket events, notifications or public URLs. The receipt schema strips unknown
fields before diagnostic parsing. The HTTP JSON input limit is 16 KiB; the internal
store additionally enforces 1 MiB maximum content.

`GET /api/me/git-outputs/{outputId}` requires a verified human session. Each read
checks current project rights and the reader's own active, consented, ready key;
a progress-only viewer receives no source. It makes a live repository proof,
rechecks current policy/provider/key facts, records durable audit and rechecks
again before returning a no-store binary attachment. It validates every sealed
ancestor's live binding, originator membership/invocation/contribute rights,
active original generation and non-revoked grant. Completed history is readable
only while these current checks continue to pass. Rotation/revoke/offboarding,
ancestor project/runtime/invocation changes, root cancellation, audit failure and
rights changes during proof or audit deny source to both A and B.

Protected task tokens can reach only their child and output endpoints. Legacy
source-bearing daemon reports, session pinning, supplements, plugin hook/MCP
credential actions and task-message readers are fenced before persistence or
fanout. Ordinary-task positive controls still work. This does not retrofit every
pre-existing source row/search/export surface. Active process, WS and every other
stream/export path remain enabling blockers together with S4.

The restricted download uses 16 KiB chunks with a fresh consistent authorization
snapshot before each write, including all original ancestor and reader-key facts.
Checks, socket writes and delivery audit each have a one-second deadline. Each
chunk flushes through an error-returning controller; unsupported/unknown response
adapters deny before source. Known non-buffering Chi status/metrics wrappers
preserve write accounting while the trusted underlying FlushError preserves
transport errors. Tests use the production RequestLogger/Metrics/Recoverer stack,
not just an unwrapped fixture router. A partial failure aborts the HTTP response
or HTTP2 stream; it never appends a free-form JSON error to source content.

A slow download refreshes its own reader-key provider proof after 30s, bounded by
one second and followed by another local check. Synthetic clock tests prove this
branch denies after external proof failure; real external-ACL detection acceptance
and long-lived source sessions remain open. There is no background worker or
unbounded writer that outlives the request.

Real local Linux TCP backpressure tests commit root cancellation, key revoke,
key rotation or originator offboarding during an active HTTP1 download, then
require cutoff within 5s. A separate TCP case injects policy-read unavailability
through a test transaction adapter; it is not a real database shutdown. A raw TLS/HTTP2 Framer advertises a
1024-byte stream window, sends no WINDOW_UPDATE, revokes the root after source
begins and requires a reset within 5s. Normal authorized HTTP1 and HTTP2 downloads
are positive controls. These are server write/reset bounds for this endpoint;
bytes already queued in a socket or accepted by the client cannot be recalled.
No bound for sandboxes, WS, legacy downloads or every supported provider is implied.

Migration900123 adds structured metadata to the R2D audit table: delivery ID,
reader operation/identity/generation/fingerprint, original human/root/task/attempt,
agent, accepted-byte count and a bounded outcome reason. No source, secret ref,
private key or token is recorded. Durable intent precedes source. Completed means accepted
and flushed by the server, not a reader receipt; accepted_bytes counts the HTTP
writer's acceptance and can exceed bytes observed at a stalled client. If terminal
audit fails after writes, the durable intent has no confirmed terminal outcome and the
outcome is uncertain (a lost acknowledgement can also hide a committed terminal
record). Tests explicitly preserve that distinction rather than
claiming that already accepted bytes were denied.

## Recovered checkpoint verification (eb6446912)

Checks use pinned Go 1.26.9 and pnpm 10.28.2, the repo-managed local database and
`scripts/go-test-with-agent-cli-guard.sh`. No real coding-agent CLI or account was
used. Handler processes run serially because TestMain shares fixed fixtures.
The API is stopped; no production, provider or credential settings were changed.

The executor recovered after a transport disconnect. HEAD and dirty files were
reconciled; the interrupted fixture follow-up had not executed. Saved frontend
logs showed successful completion. These checks are confirmed, not inferred from
an empty log:

| Check | Actual result |
| --- | --- |
| Independent security-package race | All 27 top-level tests passed at `eb6446912` (6.602s), including deterministic A/B SSH/real packs, fake TLS KV signer, parser limits/deadlines and 80-thread caller regression |
| Independent managed handler race | Selected 126 top-level cases (`TestR2DGit` + `TestClaimTask`) passed at `fead134de` (48.209s); handler/auth unchanged by bounds fix |
| Full managed handler race | Passed within first broad run at `fead134de` (147.417s), including all five repaired claims and final output/audit negatives |
| Full service / middleware race | Passed at `fead134de` (60.809s /2.424s) |
| Baseline production + matching claim test patch | `TestClaimTask -race -count=1` passed 50.859s; test-only changes then removed, baseline worktree clean |
| Core Git schemas | Independent5/5 passed at feature26360041; no frontend change afterward |
| Full frontend tests | All 6 packages /9,295 tests passed, including 2,252 core and 6,027 views; one Turbo task, two Vitest workers,15s timeout |
| `pnpm typecheck` / `pnpm lint` | Passed 10/10 and 7/7 tasks; existing warnings remain |
| Scoped Go vet | Changed security/middleware/handler/service/migrator packages passed after recovery; bounds follow-up vet passed |
| sqlc | Official prebuilt 1.31.1 regenerated successfully with no generated-code diff; source-build proxy issue from earlier checkpoint remains unrelated |
| First recovered `make test` | Failed at `fead134de`: 7 baseline-reproduced failures, 3 additional daemon failures including a race not reproduced in baseline comparison, and new SSH pack test failure corrected below |
| Guarded agent half | Failed 27 top-level tests, all within prior untouched baseline's 28; no current-only failure. Unchanged agent package source |
| Full backend after bounds fix | Failed only 6 baseline-reproduced cases at `eb6446912`: 3 Cursor MCP, processtree cancellation, repocache cancellation and storage mode. Fresh security-package race passed 7.466s; daemon passed 28.650s; handler/service/middleware passed from cache. The earlier 3 additional daemon failures did not recur, but remain unresolved recorded failures. |
| Migration round-trip | All 23 provisional migrations up/down/up in disposable schema, covered by both handler passes; regular managed migration runner passed |
| Whitespace | `git diff --check` passed |
| Playwright / real provider / real-agent smoke | Not run: no running app/provider/sandbox acceptance environment and no live credential/model authorization |

Frontend verification command:
`pnpm exec turbo test --filter='!@multica/mobile' --concurrency=1 -- --maxWorkers=2 --testTimeout=15000`.
This scheduling/timeout command is distinct from an unmodified default-suite run.
Frontend source is unchanged after 26360041.

The first broad run exposed the new pack test returning `indeterminate` after
transport failure. A controlled regression with 80 locked caller threads failed
under the old 64-thread UID limit and passed after the correction. Linux
[RLIMIT_NPROC counts the real UID's threads](https://man7.org/linux/man-pages/man2/getrlimit.2.html),
so it cannot provide a per-worker process budget. The code removes that
host-coupled limit, explicitly bounds Git parser threads, and retains its other
resource/deadline controls. The earlier failure's exact subprocess stderr was
not captured; the link to this demonstrated mechanism is an inference. Per-run
PID/cgroup isolation remains an enabling gate, not a newly claimed guarantee.

Evidence logs: `/tmp/gitsec-recovered-{full-go,baseline-claims-fixed,baseline-nondb,agent,vet}.log`,
`/tmp/gitsec-bounds-full-go.log`, `/tmp/gitsec-quarantine-thread-{before,after}.log`,
`/tmp/gitsec-independent-{bounds-r2dgit,resume-handler,resume-schema}.log`,
and `/tmp/gitsec-resume-{frontend,typecheck,lint}.log`.

## Download continuation checks

Frozen production source: `721c984be342525c310d49d1e039b30a91a17aa6`.
Final test checkpoint: `77babacf38e20eb6fa643819ad1ff95182b99f5f`.

| Check | Confirmed result |
| --- | --- |
| Independent managed handler race | All 24 top-level Git-security tests passed at 77babacf3, no skips, 16.905s; earlier source 721c984be pass 16.450s |
| Independent security-package race | All 27 top-level tests passed at 721c984be, 8.693s; unchanged by test-only 77babacf3 |
| Full managed `make test` | Full handler race passed 201.209s; fresh security package passed 6.988s; service/middleware passed from cache. Overall failed the same 7 cases reproduced by the fresh baseline comparison; no new failure |
| HTTP1 blocked socket cutoff | Root cancel 975.286343ms; key revoke 962.237803ms; key rotate 966.967978ms; offboard 972.513329ms; simulated policy outage 1.013800463s after the local transition (database commit for revocations/offboard; atomic fixture toggle for outage) |
| HTTP2 flow-controlled cutoff | Root-cancel stream reset 997.677368ms; 1024 source bytes received before reset; no window replenishment |
| Actual protocol positives | Complete authorized 1 MiB HTTP1 and HTTP2 downloads, no-store, own-reader key/generation/fingerprint audit |
| Failure controls | Unsupported deadline/flush adapters deny before source; production middleware preserves partial flush errors; in-progress simulated DB outage and real PostgreSQL table-lock timeout, refreshed provider denial and reader rotation stop subsequent chunks; terminal audit failure preserves outcome uncertainty |
| Migration checks | All 24 migrations up/down/up; normal managed migration runner applied 900123; no upstream-table or index additions |
| Scoped Go vet / sqlc | Security/handler/middleware/metrics/migrator vet passed; sqlc regeneration produced no diff |
| Guarded agent half | Failed 27 top-level cases in 116.656s, all also present in the previously recorded untouched baseline's 28; no current-only failure |
| Frontend | Unchanged since 26360041; confirmed earlier 9,295 tests, typecheck 10/10 and lint 7/7 remain applicable; no frontend rerun for Go-only continuation |
| Real runtime/provider/restore acceptance | Not performed; still gated, no production enablement |

The final test-only follow-up holds an actual PostgreSQL ACCESS EXCLUSIVE table
lock after the first authorized chunk. The next read hits the driver's one-second
query deadline and sends no second chunk. Its five-subcase group passed 4.258s;
the real-lock subcase passed 1.16s. This complements the simulated outage with an
actual driver/transaction deadline check. Independent validation at 77babacf3
passed all 24 Git cases (16.905s), including the real-lock subcase (1.15s).
The full backend result above is at 721c984be; the only subsequent source-tree
change is this additional test case.

The first HTTP1 iteration asserted audit immediately when the socket closed;
four cases saw the terminal audit still in progress. A request-handler completion
barrier now separates the measured socket cutoff from audit completion. This
corrects the fixture synchronization instead of weakening the audit assertion.
Independent review also caught errorless Chi Flush wrappers and missing flush
preflight: the adapter now preserves the native FlushError behind only known
pass-through wrappers. The forced partial-flush negative runs through the production
logging/metrics/recovery stack. The missing-flush negative uses a dedicated
unsupported response writer on the fixture router.

Evidence: `/tmp/gitsec-delivery-{full-go,agent,handler-first,handler-second,handler-middleware,http2,vet-frozen,migrate}.log`,
`/tmp/gitsec-independent-delivery-handler.log` and
`/tmp/gitsec-independent-delivery-r2dgit.log`, `/tmp/gitsec-delivery-real-lock.log`
and `/tmp/gitsec-independent-final-handler.log`.

There is no executor-access blocker. Remaining implementation/acceptance work
includes the runner-facing broker gateway and writes, complete history policy,
Linux workload isolation, process/WS/legacy-surface revocation, integrated S6
adversarial/restore gates, and separately authorized live provider/runtime setup.
None of these is represented as finished by a successful profile, pack read or
single-endpoint cancellation test.

## Baseline comparison and claim investigation

At previous source8e172012, full `make test` failed seven non-handler tests that
were reproduced against untouched baseline231dedb: DSH cancellation, three Cursor
MCP cases, processtree cancellation, repocache cancellation and storage file mode.
Its guarded agent half had27 failures, all within the baseline's 28. These are
prior recorded comparisons, not an assertion that new runs must fail identically.

The previous broad run also had five ordinary claim tests return200 with no task.
Later isolated and full-handler runs passed, so those five were never classified
as baseline-reproduced failures. Investigation found that all five selected an
arbitrary workspace agent/runtime with `LIMIT1`, borrowing unrelated capacity and
freshness. The new controlled regression owns both agent/runtime fixtures, proves the
first eligible before saturation, occupies its capacity and observes the empty
claim, then obtains the intended task with the independent fixture. The five
fixtures now own their capacity/runtime. This proves a fixture failure mechanism,
not the exact historical cause of every transient failure.

The first test-isolation follow-up accidentally reused a fixture agent name;
the controlled baseline run caught its unique-constraint failure. The helper now
assigns distinct names, and the matching baseline claim selection passes50.859s.
This is a corrected test defect, not a baseline production failure. Baseline test
patches were removed afterward. Current full-handler and independent 126-case
runs both pass with the corrected fixture.

The fresh baseline non-DB comparison reproduced these seven failures:
`TestProvisionDshMulticaProfile_CancellationKillsTheWholeTree`,
`TestPrepareCursorMcpConfigManagedEmptySet`,
`TestPrepareCursorMcpConfigSeedsExplicitAuthSource`,
`TestPrepareCursorMcpConfigWritesProjectConfigAndApprovals`,
`TestCombinedOutputKillsDescendantsHoldingOutput`,
`TestCreateWorktreeContextCancelsRunningGitProcessTree`, and
`TestLocalStorageUploadsAreWorldReadable`.

The first recovered broad run additionally failed
`TestExecuteAndDrain_BackgroundToolWatchdog`,
`TestReadTaskWakeupMessagesAcceptsLargeRPCResponse` and
`TestReadTaskWakeupMessagesExtendsReadDeadlineOnPeerTraffic` (including a detected
race between a leftover reader and changed test timing globals). Those files are
unchanged from baseline; the fresh baseline package run did not reproduce these
three. They remain recorded current-run failures without a reproduced baseline
attribution or source correction. A later pass does not erase that evidence.

## Independent review and delivery limits

A separate read-only reviewer inspected 26360041, both claim-fixture follow-ups
the frozen bounds correction at eb6446912 and the final download continuation
at 721c984be, plus test-only 77babacf3. Review found and
prompted fixes for SSH deadline propagation, unbounded validator work, additional
daemon/plugin sinks, historical originator key/membership checks, all-ancestor
binding checks, read audit, and revoked-identity reconnection. Independent tests
and results are recorded above. No unresolved finding in the disabled local slice
is being treated as completion of the remaining system gates.

No source was uploaded; no push, PR, merge, deployment, live key generation or
enrollment, real OpenBao setup, paid API call, production or security-setting
change occurred. All new services and credentials in tests are local/synthetic.

## Broker write continuation — local S3 sub-slice

Base `b9294a891b5cf22ca5c330a69ba882ca69f43b59`; implementation
`28b607a8fe3ecc40e0a3228bd1c85d234b2cdf8f`, HTTP body-deadline correction
`cd0ef75430aea4be9445c625df84b6ed71178a50`, and Git capability-spacing correction
`900cf51e8ccd13ee868187177868889f41e427c3`. No migration was added; the existing
immutable operation JSON stores the additional mutation metadata.

`PushHandler` implements an **unmounted**, push-only smart HTTP v0 bridge to the
pinned SSH worker. The URL selects neither repository nor identity. A trusted
`WorkloadChannel` supplies the server-held lease; fixture authentication uses
verified synthetic mTLS peers, and user/channel headers cannot replace it. No
production channel adapter, token issuance or route is installed. Fixed service
paths deny fetch/dumb/protocol-v2 requests. Only one exact granted task ref,
SHA-1 object format, report-status and bounded pack data are accepted. Deletes,
tags/default refs, multiple commands, force updates, push options, certificates,
shallow/missing graphs, malformed framing and unsupported capabilities deny.

The key worker requires a separate `ProviderWritePolicy` proof; the production
`Service` deliberately does **not** implement it. App `write_refs` approval is
not provider branch-protection metadata. The synthetic adapter denies protected
refs; the worker additionally reads the same key's live upload-pack HEAD symref
and rejects that default branch, including a default branch inside `task/*`.
Unknown default metadata denies. The receive-pack advertisement proves current
write-service access with that user's exact key generation. Provider hooks and
old-object comparison remain effective. Production provider-policy adapters,
including authorized read access to protection metadata, are an open gate.

For updates, a same-key upload-pack session obtains the exact authenticated base
ref. An isolated temporary object DB imports base and incoming packs (including
incremental thin packs), checks framing/checksum, strict object/connectivity
validation, exact commit types, and old-to-new ancestry. It checks every reachable
commit tree and repacks only reachable objects, dropping unrelated incoming
objects. The parser limits are 16MiB per input/output pack, 32,768 objects total,
8MiB per expanded object,64MiB aggregate expanded bytes,256 reachable commits,
1MiB metadata per subprocess, a five-second quarantine wall limit, and the prior
Linux process resource controls. Base and incoming share the aggregate limits.
The host UID/process/filesystem isolation limitations above still apply. A new,
previously absent granted task ref may start a closed orphan history; it cannot
rewrite an existing ref. Larger/unsupported repositories fail closed.

Before sending a reconstructed receive-pack update, the broker persists the
actor/context/root/task/attempt/grant, policy/grant epochs, provider/repository,
identity/generation, exact ref, old/new IDs and canonical-pack SHA-256 digest.
The digest is checked again in the key worker. A fresh same-key receive-pack
advertisement checks the old ID; current authorization and provider policy are
checked again before the canonical command. No caller command/capability bytes,
URL or `.git` config is forwarded to SSH. Provider private keys and SSH agent
sockets never enter quarantine Git subprocesses; the signer remains inside
custody's callback. Synthetic mTLS fixture files authenticate only the test HTTP
client and are not provider credentials or a certified sandbox channel. HTTP mutation IDs derive from the sealed
operation and old/new IDs; changing pack encoding or reconstructing the handler
cannot create a fresh ID for the same uncertain mutation.

Writes use a 250ms online-authorization watchdog with one-second lookup deadlines
and a 30-second operation budget; cancellation closes the actual SSH connection.
This is an active write-transport bound, not sandbox/process/other-stream
revocation acceptance. A command already sent may commit remotely. Disconnect,
post-send cancellation or missing durable outcome remains **indeterminate**;
there is no automatic retry. If the provider confirmed and the success audit
persisted before authorization changed during return, `ErrCommitted` distinguishes
that known mutation from uncertainty. Read-only reconciliation rechecks the same
current principal/generation/lease and records a separate observation of
`matches_old`, `matches_new` or `diverged`. The original record is retained;
matching an object does not prove who wrote it or that an uncertain update never
happened. Confirmed operations remain inspectable too.

The wire implementation follows the primary
[Git pack protocol](https://git-scm.com/docs/pack-protocol) and
[smart HTTP protocol](https://git-scm.com/docs/http-protocol), with the deliberately
narrow supported subset above. These tests certify neither general Git/provider
compatibility nor workload isolation.

### Continuation verification

Root full `r2dgit` race run at 900cf51 passed13.745s:
`/tmp/gitsec-push-corrected-package.log`. Real local Git create and incremental
pushes pass through synthetic mTLS HTTP, broker/quarantine and pinned SSH to a
real receive-pack process. Tests cover provider identity separation, exact-ref
and current-rights/epoch/key negatives, non-fast-forward and concurrent-ref
movement, deleted submodule metadata hidden in history, unreachable-object
removal, malformed request/provider packets, read-only reconciliation and audit
outage after an actual remote commit. HTTP2 valid provider work longer than one
second succeeds. A repeated uncertain HTTP push through reconstructed handlers
sends exactly one mutation. A provider-default task ref, protected task ref and
missing policy adapter all deny.

Two first-run negative fixtures were corrected: identical synthetic root commits
made the intended unrelated-history case a valid fast-forward, and a shell-looking
ref with no control characters was valid Git syntax (it is still subject to the
exact grant). After the first independent frozen review, an over-strict capability
spacing check rejected Git's valid leading ASCII separator space, failing the
real-client positive and retry controls. The correction at 900cf51 retains strict
control-character/capability rejection and adds a spacing positive. Failed run:
`/tmp/gitsec-independent-write-r2dgit.log` at 28b607,12.190s. This was a corrected
implementation regression, not a baseline failure.

Independent handler race run at cd0ef7543 passed all 26 top-level `TestR2DGit`
cases, no skips,16.241s: `/tmp/gitsec-independent-write-handler.log`. These
handler/SQL sources are identical at 900cf51. The new real-DB cases prove current
catalog write/ref/user/generation/consent checks and immutable old/new/digest/epoch
intent lookup and replay denial after journal reconstruction; the prior output,
revocation, authorization and migration round-trip cases also pass.

The guarded `pkg/agent` half launched at 28b607 failed 28 cases in 119.686s:
`/tmp/gitsec-push-agent.log`. This package and its production dependencies were
not changed by the subsequent HTTP-only fixes.26 failures match the previous
baseline failure set; two names were absent from that baseline run:
`TestClaudeCancellationTerminatesProcessGroupGraceful` and
`TestCodexExecuteSemanticInactivityAllowsContinuousDeltaProgress`. A focused
fresh run of those two at unchanged baseline231dedb passed1.412s:
`/tmp/gitsec-push-baseline-agent-new.log`. They remain unresolved current full-suite
failures without a reproduced baseline attribution. The earlier seven regular
baseline failures and three unresolved first-recovery daemon timing/race failures
remain documented above; no later pass erases them.

No frontend, sqlc query input or migration changed in this continuation. The
previous full frontend/typecheck/lint and migration evidence remains the applicable
unchanged-source evidence; those frontend commands were not rerun for this Go
slice. No Playwright/live provider, real agent/model, OpenBao, restore or protected
workload acceptance ran. S4 isolation, certified workload wire authentication,
production provider policy, complete S5 delivery/bypass coverage and integrated
S6 acceptance continue to block protected execution. No infrastructure blocker
or new design approval is required to retain this disabled local checkpoint.

Independent final `r2dgit` race run at 900cf51 passed all 41 top-level tests, no
skips,15.590s: `/tmp/gitsec-independent-write-final-r2dgit.log`. Observed active
SSH cutoffs were241.807503ms before advertisement,151.550738ms after the remote
committed (indeterminate audit retained), and1.2448769s for policy outage. These
are synthetic local write-transport measurements, not provider-wide or runtime
cancellation certification. Independent source review found no remaining blocker
within this disabled local slice, after the HTTP deadline/idempotency and capability
spacing fixes. Scoped Go vet at 900cf51 passed:
`/tmp/gitsec-push-final-vet.log`.

Managed full `make test` at 900cf51 finished with nine failing regular tests:
`/tmp/gitsec-push-full-go.log`. The fresh broker package passed14.706s;
middleware/service passed cached checks. Seven failures match the previously
reproduced baseline set listed above. Two additional failures are unresolved:

- `TestPrepareIsolated_PermanentFIFOBlockThenImmediateRetry`: the helper had not
  created its task directory before the 250ms fixture timeout (full case0.26s).
- `TestCommentSourceContextLifecycle`: the delete-intent sweep returned1 when
  the test expected at least3 (full handler package failed130.553s).

Neither test/source changed in this continuation. Fresh guarded baseline runs
passed the FIFO case1.334s and comment lifecycle case2.010s:
`/tmp/gitsec-push-baseline-fifo.log`, `/tmp/gitsec-push-baseline-comment.log`.
A focused current900cf51 repeat also passed both (execenv1.587s, handler2.099s):
`/tmp/gitsec-push-current-new-regular.log`. These passes do not establish the
cause of the full-run failures or erase them. They are not classified as
baseline-reproduced failures, and the full handler suite is not reported green.
The separate agent-half failures above also remain part of the final check result;
`make test` stopped after its regular half. No unrelated test/source was changed
to conceal these results. The baseline comparison checkout remains clean.

`git diff --check` passed. All implementation changes are local commits; the
final report/handoff update changes documentation only. No source upload, remote
push, PR/issue/comment write, merge, deployment, real credential generation or
enrollment, paid call, OpenBao setup or host/security-setting change occurred.


## Lifecycle/output continuation — local S4/S5/S6 work

Production change `ff3032e134c4a47c939c4a40a333546dfd8ad573`; test-only vet
correction `980d53b68a30eb5c9da082a6cbb148be3e58f21f`; terminal-replay fixture
correction and frozen source/test checkpoint
`63e7fcd4fd9e13eb50a04a737f3a1c6d6c128ae2`. This continuation uses no new
migrations. The existing Team=Workspace and cross-workspace direct project grant
semantics are unchanged.

### Integrated boundaries

Task-history lists and singleton task responses now apply one bounded batch
classification after hydration. Protected and missing rows receive newly
constructed allowlisted progress records: structured IDs/status/attempts/times
remain; result/error/narrative, trigger/handoff, session/workdir/branch/config
fields do not. Ordinary task detail remains available. A policy-query failure
returns503 without source; responses use `Cache-Control: no-store`. Recursive
classification keeps batch roots independent and retains bounded fail-closed
lineage handling. The existing client schema accepts these progress records;
malformed optional and required input coverage was added without a response
shape change.

The boundary also lives in the service: real claim dispatch does not merge
protected/unknown task Context into public events. Structured lifecycle events
discard caller-provided extras when protection is present or unknown; direct
progress reporting denies. Direct protected completion and preparation extension
deny before writes. Protected failure records a fixed runtime-ineligible failure
and settles the task without generic comments, narrative events, outbound
recovery, source-bearing caller metadata or generic retries. New caller-provided
session/workdir/branch pointers are rejected; **historical stored pointers are
preserved** by the underlying fail update. This is not pointer erasure or native
resume/cache isolation. Dedicated cancellation remains available; the chat
cancellation draft route is fenced before it can return a rich draft.

Delegated failure recovery checks both worker and coordinator task policy before
creating comments or dispatching a pending recovery outbox. Previously persisted
pending outbox rows are covered, not only new writes. Denied rows stay pending;
they are not silently acknowledged. Generic failed-task sweeps and retries do
not reintroduce protected narratives or unsealed execution.

Synthetic real-DB/router/bus tests exercise historical source markers across
agent history/snapshot and issue history/active responses, independent ordinary
positive controls, missing tasks and one-second per-caller query outages, actual
claim dispatch, post-failure event/retry handling and direct completion/failure.
Pending recovery tests cover ordinary delivery, protected worker, protected
coordinator and query failure. Query outages use a per-caller DB wrapper; they
do not lock global tables or simulate a whole PostgreSQL shutdown.

Independent review identified the reachable dispatch Context and persisted
recovery paths; both were fixed and independently retested. The first outage
fixture cancelled its entire request before reaching claim dispatch; it was
corrected to fail only the policy query. Scoped vet then identified two test
fixtures copying TaskService's lock-containing value. The test-only correction
constructs isolated services through the existing constructor. Neither failure
is attributed to baseline. Logs: `/tmp/gitsec-s456-combined.log`,
`/tmp/gitsec-s456-vet.log`.

### Precise S4 prerequisite

The accepted plan §7.1 specifies a dedicated Linux worker VM with a hardened
per-run container: non-root, user/mount/PID/network isolation, dropped
capabilities, no-new-privileges, seccomp/AppArmor, resource/time limits and a
read-only base. It excludes engine sockets, broker/control-plane credentials,
host HOME and SSH sockets from workloads and requires operator certification.
The plan selects neither a concrete container engine nor a workload channel
identity/PKI backend. The broker requires a trusted authenticated workload
channel; handing a signing credential to an untrusted sandbox would not supply
that boundary.

Read-only inspection found Docker28.4.0 with builtin seccomp and cgroupns
SecurityOptions. Two disposable synthetic runs used only the cached pgvector
image `sha256:151aa1c2e849e7828ed8aef2183ae15f692cbe887d2f28921d8b44b26e154d7e`,
`--pull=never`, no network, no source mounts, uid65534, dropped capabilities,
read-only root and bounded tmpfs/pids/CPU/memory. They observed CapEff0,
NoNewPrivs1, Seccomp2, pids32, memory67108864 and CPU50000/100000; root writes
failed and neither the engine socket nor `/workspace` was present. These are
partial local probes, not a certified lifecycle or containment test.

The UID map was identity `0 0 4294967295`. A separate unshare user/mount/PID/net
probe failed opening `/proc/self/uid_map` with a read-only filesystem error.
`/proc/self/attr/current` returned raw `kernel` followed by NUL; Docker reported
no AppArmor option. This establishes **no approved/reported AppArmor profile
evidence**, not proof of an unconfined or absent profile. Probe log:
`/tmp/gitsec-s456-runtime-probe.log`. Docker's official
[user namespace documentation](https://docs.docker.com/engine/security/userns-remap/)
and [AppArmor documentation](https://docs.docker.com/engine/security/apparmor/)
describe operator configuration; this task does not authorize modifying the
host daemon, UID mappings, kernel policy or security profiles.

The remaining prerequisite is operator selection/provisioning and certification
of the dedicated backend plus an outside-workload trusted channel identity
backend. No unused container driver or self-advertised capability was added.
Production runtime eligibility remains false and daemon protected-version
refusal remains in place. Complete preparation/checkout/execute/resume/finalize/
cleanup, cache/native-session isolation, egress, cancellation and integrated
router→workload→provider→restricted-output acceptance cannot be established in
this environment. Real custody/provider enrollment and restore acceptance also
remain open. These are S4/S5/S6 rollout blockers, not permission to enable a
partial protected path.

### Broad failure investigation

Independent baseline checkout remained clean at
`231dedb55287ab6e40fd103634a024e4d9d1baeb`. A fresh guarded selected regular run
reproduced all seven previously identified failures: DSH cancellation, three
Cursor MCP cases, process-tree cancellation, repo-cache cancellation and local
storage mode (`/tmp/gitsec-independent-s456-baseline-regular.log`).

A fresh full guarded baseline agent run failed27 cases in102.891s
(`/tmp/gitsec-independent-s456-baseline-agent.log`).25 of the prior current-run
28 failures reproduce in that fresh run; two others reproduce in the earlier
baseline full-run artifact. Thus27/28 have baseline reproductions across runs,
not an identical failure set in one run. In particular Claude graceful
cancellation now has a fresh baseline reproduction. The unmatched current
failure is `TestCodexExecuteSemanticInactivityAllowsContinuousDeltaProgress`;
fresh baseline passed0.22s and the prior focused baseline passed. Its prior
full-suite failure remains unresolved; unchanged source alone does not establish
a cause.

The FIFO case passed three repetitions in both fresh baseline1.902s and
current3.047s (`/tmp/gitsec-independent-s456-{baseline,current}-fifo.log`),
without explaining the prior full-run250ms startup failure. Comment source
context code/query/test are identical to baseline. A historical baseline artifact
contains the same count1 failure, but its SHA provenance was not independently
re-established here; it is not upgraded to a fresh baseline attribution. Fresh
isolated baseline/current passes remain recorded above. Its global limited
sweep may interact with unrelated due intents; that is a hypothesis, not a
proven original cause.

Specific descendant PIDs from the cancellation failures were later observed as
zombies under PID1. The test helper treats successful kill(pid,0) as alive.
These observations are consistent with that helper reporting an existing PID
and establish no running descendant at inspection time. They do not establish
its state at the original assertion or explain every timing/process failure.
No init/process or host security settings were changed, and no unrelated tests
were weakened. Earlier unresolved recovery daemon failures remain recorded.

### Final verification

At frozen source/test `980d53b68a30eb5c9da082a6cbb148be3e58f21f`, independent
guarded handler race passed31 top-level `TestR2DGit` cases without skips,
27.830s (`/tmp/gitsec-independent-s5-final-handler.log`). Independent full
r2dgit race passed41 cases16.348s and service recovery passed its four-subcase
matrix2.885s at `ff3032e134c4a47c939c4a40a333546dfd8ad573`, whose production,
r2dgit and service sources are identical to the frozen checkpoint
(`/tmp/gitsec-independent-s5-{r2dgit,handler-service}.log`). Independent review
found no remaining blocker within the disabled local slice, with the historical
pointer, complete output-surface and runtime caveats above. Reviewer requested
the later-zombie causal wording correction; it is included.

Scoped Go vet passed after the test-only lock-copy correction
(`/tmp/gitsec-s456-vet-final.log`). Frontend typecheck passed10/10 tasks in
4m58.957s; lint passed7/7 tasks in46.668s with existing core warnings and no
errors (`/tmp/gitsec-s456-{typecheck,lint}.log`). Their frontend source is
unchanged by the test-only correction. The focused new client projection tests
also passed3/3 (`/tmp/gitsec-s456-core-projection.log`).

The final separate guarded agent race at the frozen checkpoint failed25 cases
in129.583s (`/tmp/gitsec-s456-final-agent.log`).23 reproduce in the fresh full
baseline run and the remaining two have prior full baseline reproductions:
all25 have baseline evidence, without claiming one identical baseline failure
set. The prior unmatched semantic-delta timing case passed in this final run;
that does not erase its historical unresolved failure or prove its cause.

The first full managed run at980d53b68 passed the complete handler race suite
191.162s and r2dgit21.954s. It failed the seven baseline regular cases plus two
introduced test-fixture compatibility failures:
`TestCompleteTask_AlreadyFinalized` and `TestFailTask_AlreadyFinalized`
(`/tmp/gitsec-s456-final-go.log`). Their minimal mocks did not implement the new
policy reads: Query always returned ErrNoRows and QueryRow ignored the boolean
scanner. Unknown policy correctly denied; it was not a demonstrated production
no-op regression. The final test-only correction explicitly models an ordinary
task using the same policy-row and typed-row helpers already used by service
tests. No production check was relaxed and all terminal no-op assertions remain.
These introduced fixture failures are corrected separately from baseline results.
The FIFO and comment lifecycle cases both passed that full run; earlier failures
remain recorded without a proven cause.

Corrected full managed `make test` at frozen
`63e7fcd4fd9e13eb50a04a737f3a1c6d6c128ae2` completed with exactly the seven
baseline-reproduced regular failures and no additional failures
(`/tmp/gitsec-s456-corrected-full-go.log`). Full service race passed46.710s;
r2dgit race passed24.625s. Full handler passed from its identical-source cache
(the preceding fresh full run191.162s). The regular-half failure stops make
before its agent half; the separately executed agent results above remain the
applicable unchanged-source check. Scoped vet also passed at this final commit
(`/tmp/gitsec-s456-corrected-vet.log`). The two introduced mock failures are
therefore corrected, not relabelled as baseline. No full backend green status
is claimed.

Independent guarded replay-fixture race at the exact final commit passed both
`TestCompleteTask_AlreadyFinalized` and `TestFailTask_AlreadyFinalized`, all six
completed/cancelled/failed subcases, without skips,1.120s
(`/tmp/gitsec-independent-s5-final-replay.log`). Independent review confirms
the explicit ordinary policy fixtures preserve the assertions and do not alter
production authorization.

Full frontend verification passed all6 package tasks /9,298 tests in18m17.1s:
core2,255; views6,027; docs16; UI Lab46; desktop675; web279. Command:
`pnpm exec turbo test --filter='!@multica/mobile' --concurrency=1 -- --maxWorkers=2 --testTimeout=15000`.
One task was cached; frontend source is identical across the production and two
test-only correction commits. Log: `/tmp/gitsec-s456-frontend.log`.

`git diff --check` and local report/handoff link checks passed. No mobile source
changed. No Playwright/protected end-to-end, real provider/model, real custody,
backup/restore or production acceptance ran. Protected execution remains
unavailable. All tests/probes used synthetic/local fixtures and guarded agent
CLIs. No source upload, remote push, PR/issue/comment write, merge, deployment,
real key generation/enrollment, OpenBao setup, paid call or host/security-setting
change occurred. The final report/handoff commit changes documentation only.


## Docker supervisor/channel continuation — disabled local S4 slice

Base documentation HEAD `e92a3e7dc3e9d8fd2c34475befd5d21298ff40a9`;
source/test checkpoint `3058202e3f725b8c1e183d066e0f4b0147f07bb5`. No migrations,
public API routes, frontend code, production construction or daemon capabilities
changed. Team=Workspace and cross-workspace project policy are unchanged.

### Implemented component path

`WorkloadSupervisor` is Linux-only. Its concrete `DockerEngine` uses a fixed
[Engine API v1.47 subset](https://docs.docker.com/reference/api/engine/version/v1.47/)
through an explicitly supplied HTTP transport, with no Docker executable,
ambient DOCKER_HOST or default client fallback. Engine requests have one-second
bounds, reject redirects and malformed/oversized results, and distinguish
confirmed synchronous deletion from errors or asynchronous acceptance.

Launch consumes sealed `RunSecurityContext`/`RepositoryGrant`, an independently
authorized runtime/channel and a trusted outside-workload TLS key pair.
`IssueLease` and `Authorizer` perform the existing immutable/current-rights checks.
This slice supports the existing receive-pack channel only: unsupported read
leases deny admission. Ref/operation/TTL cannot grow; the grant expiry clamps
the lease. Docker inspection never supplies OperatorApproved or Isolated facts.
Production `Service.Current.Runtime` remains empty and all daemon protected
versions still refuse. No local caller or configuration turns this gate on.

The supervisor writes/fsyncs a launch intent before engine creation. Intent
contains run/task/attempt and partition identifiers, not credentials. A private
root lock excludes simultaneous ownership; runtime plus root hash scopes exact
engine labels. Removal checks reserved name/labels, then uses the inspected
canonical immutable container ID. Startup recovery removes exactly owned orphans
and refuses adoption/resume. Cert/channel/session tombstones survive normal
restart: fresh TLS credentials cannot re-execute a spent attempt, and retry
requires a freshly derived context/attempt/session. Recovery retains foreign
resources. Root/tombstone rollback or loss is not solved by filesystem fsync;
restore acceptance remains an S6 gate.

A per-run Unix socket is the only workload bind mount. Its outside-workload
proxy holds the TLS private key in memory and calls a fixed HTTPS broker origin.
`WorkloadChannels` maps the TLS-verified leaf to a server-held lease and rechecks
current authorization. Workload headers, bearer values, URL/query parameters and
certificate subject names cannot select identity. The proxy strips untrusted
identity headers and permits only the bounded receive-pack routes. TLS,
connection and request failures deny; unexpected proxy exit cancels the run.
Connections/in-flight requests and active run counts are bounded. Provider work
has a30s operation budget, independently of1s online policy/engine budgets;
a valid >1s provider operation is covered by a positive regression.

Typed engine configuration fixes a digest-pinned image and entrypoint, numeric
non-root identity, read-only root, dropped capabilities, no-new-privileges,
seccomp/AppArmor, private IPC/cgroup namespaces, default non-host PID/UTS
namespaces and no network. User namespace remapping inherits the Docker daemon
configuration and still requires operator configuration/acceptance. Work/home/tmp use fresh
bounded tmpfs with explicit ownership; no host cache, native history, alternate
object store, credentials or engine socket is mounted. Retry can retain the
same authorization-domain cache key but gets fresh storage and session state.
The engine log driver is disabled to avoid an ordinary stdout/source sink.
Inspection mismatches deny before execution. These checks verify requested/API
configuration, **not effective kernel enforcement**.

Revocation cancels/refuses channel traffic before engine cleanup. A per-run
watcher rechecks rights/epochs/generation/lease and engine state. One launch's
I/O cannot hold another run's revoke behind a global lock. Supervisor shutdown
cancels the shared lifetime before draining admission. Failed removal retains
intent, does not close the cleanup receipt and blocks further launches. A create
that times out and later succeeds remains recoverable; a404 alone never erases
an uncertain creating intent. An uncertain create that remains absent requires
operator reconciliation rather than automatic forgetting. Tombstone garbage
collection is intentionally absent; preserve and size this durable state.

### Synthetic evidence and review

The fake HTTP engine implements the adapter's real create/inspect/start/delete/
list requests and starts a test-created fake CLI process. That process connects
through the actual per-run Unix socket and mTLS proxy to the existing
`PushHandler`/broker authorization/audit path. All TLS/Git identities are
synthetic; no Docker daemon, VM, live provider or real agent CLI participates.
This demonstrates component integration and process cancellation/reaping, not
namespace, network, filesystem or kernel containment.

Tests cover concurrent A/B originators of the same shared agent, forged identity
headers, unregistered certificates, live TLS connection refusal after revoke,
foreign refs/grants/runtime/channel, TTL bounds and expiry during creation,
unsafe inspection, epoch/key/offboarding/lease changes, one-second policy outage,
in-flight broker cancellation before a failed removal, independent-run revoke
while another create is blocked, shutdown during admission, slow valid provider
work, proxy loss before/after start, fresh retry state, spent attempt/cert/channel
replay across restart, foreign-owner preservation and malformed container IDs.
Late create and crash fixtures verify orphan+intent exist before recovery.

Independent review found and prompted corrections for global-lock revocation,
pre-start lease expiry, shutdown cancellation ordering, certificate/channel/
attempt reuse, owner scoping, a too-short proxy response-header timeout, ignored
proxy exit and a crash-fixture lock. The first test run also exposed two fake
engine defects: ID lookup shadowed the requested ID, and the fake write-reference
callback did not record/observe its operation. Those fixture defects were fixed;
the failed log is `/tmp/gitsec-s4-first-tests.log`. Expanded guarded race tests
passed5.778s before the final crash-helper-only lock correction
(`/tmp/gitsec-s4-combined-tests.log`). No failed result is relabelled as baseline.

### Operator deployment prerequisites and remaining integration

1. For the proposed Docker/Proxmox pilot, provision a dedicated Linux KVM worker
   VM and its disposable storage/network. The accepted plan requires a dedicated
   Linux worker VM but leaves hypervisor selection open; Proxmox/KVM is the
   recommendation for the user's stack. The local backend choice here is Docker,
   without Kubernetes.
   Container engine control is privileged inside that worker VM only; workloads
   must never receive engine or Proxmox API credentials.
2. Approve guest administrator changes for Docker/user namespace mapping,
   subordinate UID/GID ranges, enforced seccomp/AppArmor, resource controls and
   network policy. Verify actual mappings/profile enforcement and cgroup limits
   with positive/negative containment tests. The earlier partial host probes are
   not acceptance for this implementation.
3. Supply a reviewed digest-pinned fake-agent image containing the fixed
   `/opt/multica/agent` entrypoint, tested profile JSON/AppArmor profile, matching
   container and remapped socket owner IDs, and a durable private supervisor root
   owned by its service identity. Size/quota/monitor root and tombstone storage.
   The current no-network, bounded-tmpfs policy does not support arbitrary native
   providers, package networking or persistent resume.
4. Implement the production supervisor service/entrypoint and trusted runtime
   registry/registration/enrollment adapter. The local components share an
   in-process trusted registry in tests; a remote control plane needs an
   authenticated registration protocol and certificate expiry/revocation policy.
   Supply broker trust roots and per-attempt proxy certificates outside the
   container, with no CA signing key or Git key in the workload. This turn did
   not provision any identity or credential.
5. Integrate protected read/prepare, checkout, execution, finalize, restricted
   output collection and cleanup across actual daemon/provider paths. Production
   custody/provider policy adapters and acceptance remain separate gates. Run the
   integrated A/B/egress/revoke/crash/restore suite and independently review its
   measured properties before enabling any runtime capability. Treat "certified"
   as this recorded operator approval of versioned configuration and passing
   properties, not an external certificate or a self-advertised Boolean.

S5 still needs full legacy/history/API/WS/search/export/MCP/attachment coverage,
provider-aware egress and all-stream/process revocation acceptance. The new engine
stdout policy avoids one sink but is not a restricted-output collector. S6 still
needs the full router→isolated workload→provider→restricted-output path, actual
containment/cleanup measurements, restore/rollback and authorized provider/native
CLI acceptance. Protected execution stays disabled.

### Frozen-checkpoint verification

At exact source/test `3058202e3f725b8c1e183d066e0f4b0147f07bb5`, independent
guarded full r2dgit race passed26.316s with no failures/skips:
`/tmp/gitsec-independent-s4-r2dgit.log`. It has61 top-level entries:41 existing,
17 functional Workload cases, one fake-CLI subprocess helper that returns in the
parent, and two Docker protocol cases. Independent scoped Go vet passed
(`/tmp/gitsec-independent-s4-vet.log`). Source review found no remaining blocking
finding in this disabled component scope after the fixes above. The final
crash-helper-only correction releases the global map mutex before joining its
watchdogs and preserves the orphan/intent assertions.

Root guarded full r2dgit race also passed26.185s
(`/tmp/gitsec-s4-final-r2dgit.log`). In the managed full `make test`, the fresh
handler suite passed130.316s, r2dgit passed19.402s and service passed from cache.
Overall make failed only the seven previously baseline-reproduced regular cases:
DSH cancellation, three Cursor MCP cases, process-tree cancellation, repo-cache
cancellation and local storage mode (`/tmp/gitsec-s4-final-go.log`). The regular
failure stops make before its agent half; no full backend green status is claimed.

The separate guarded agent race failed28 cases in130.316s
(`/tmp/gitsec-s4-final-agent.log`):25 reproduce in the fresh full baseline run,
two more in the earlier full baseline artifact. The unmatched case is
`TestCaptureCursorBackgroundLateDescendant`, which reported its background process
group still active after1s. A fresh three-repeat run at clean baseline
`231dedb55287ab6e40fd103634a024e4d9d1baeb` passed4.291s
(`/tmp/gitsec-s4-baseline-cursor-late.log`). This unmatched full-suite failure
remains unresolved and is not relabelled as baseline. Agent/protocol/test-script
sources are unchanged by this S4 commit, and `go list -deps ./pkg/agent` excludes
r2dgit (`/tmp/gitsec-s4-agent-deps.log`); that evidence does not establish the
cause of a timing failure. The earlier unresolved failures remain recorded.

A three-repeat focused run at this exact current commit also passed3.796s
(`/tmp/gitsec-s4-current-cursor-late.log`). Neither isolated pass explains or
erases the full-run failure. No unrelated test/source was weakened to hide it.

No frontend source changed in this Go-only continuation; the preceding9,298-test,
typecheck and lint results remain applicable unchanged-source evidence and were
not rerun. No migration/sqlc change required regeneration. No mobile, Playwright,
real Docker/VM/containment, live provider/custody/enrollment, real-agent/model or
restore acceptance ran. Tests used fake HTTP engine requests, synthetic TLS/Git
identities, explicit test-created CLI helper processes and local temporary files.
No Docker/security/network settings changed; no VM or credentials were provisioned,
and no source upload, publication/push/PR/merge/deploy or paid call occurred.
The final report/handoff commit is documentation only.

Final `git diff --check` and local report/handoff link checks passed.

## Application prepare/read/output continuation — disabled local S4/S5 slice

Base: `18bd61c89513dcae7035c047945e98ba46c2b8f0` (source checkpoint
`3058202e3f725b8c1e183d066e0f4b0147f07bb5`). New local implementation:
`c42ec73ca948a42ac04833028a1bc8a384d2f54d`. No migrations, generated SQL inputs,
frontend, agent/protocol or test-script sources changed.

### Implemented boundary

`WorkloadApplication` is an explicit dependency-injected, unmounted construction
interface. It reloads the sealed context/grant from the application DB instead of
accepting a caller's run identity. An operator signature binds the whole context,
grant, channel, actual validated supervisor-policy digest, certificate digest,
expiry and acceptance reference under a fixed signature domain. Serialization
errors, substituted fields/certificates, absent issuers and default construction
deny. Signed mutable grant data is copied. The registered authority adds only
exact runtime evidence after `Service.Current` succeeds; the ordinary production
authority stays ineligible and human admission still says
`execution_available:false`. No live issuer or public registration endpoint exists.

Read-scoped channels accept only fixed snapshot, result and receipt-acknowledgement
operations. The workload cannot select user/task/context/repository/ref/audience,
and cannot reach the existing write bridge. Existing write channels retain their
previous route restriction. `SSHWorker.ReadSnapshot` returns the validated pack
and HEAD from the same authenticated pinned advertisement, through the broker's
existing own-key live proof, current-rights and durable audit pipeline. Read HTTP
delivery reauthenticates the exact live channel between 16KiB chunks, bounds policy
checks and writes to1s, and bounds the whole request to25s. It audits intent,
accepted bytes and completion/abort, including partial writes and flush failures.
The request budget also bounds the initial provider proof's lifetime.

The in-workload helper receives only its socket and trusted entrypoint paths. It
checks out the authenticated HEAD into new private state using explicit Git,
strict quarantine, sanitized environment, disabled hooks/templates/protocols and
bounded subprocesses. This helper is not a host sandbox. Source/result content
never enters engine stdout logging or ordinary task result/session fields.
The result's classification and writer binding come from the sealed channel.
Completion requires a stored restricted result, explicit acknowledgement of that
exact receipt, canonical inspected exit zero, successful exact-resource cleanup
and current-rights private completion. It invokes the application's required
same-transaction terminal receipt settlement adapter; no generic task narrative,
comment, notification or retry pipeline is called. Historical reads use the
existing current-reader-own-key and all-ancestor checks.

An application journal is fsynced before queued→running. Restart refuses adoption,
cleans owned engine state, privately fails the exact immutable attempt and settles
its dependent receipts/audit before deleting that journal. A DB/settlement outage
rolls back terminal writes, retains evidence and refuses prepare. Ambiguous output
responses are not replayed; interrupted runs recover to private failure. Completed
queue status, rather than a context lock upgrade, closes execution and preserves
already-issued children of normally completed ancestors.

### Independent review and synthetic evidence

Independent review found and drove fixes for missing terminal receipt settlement,
the pre-engine crash window, completion/child-admission lock ordering, partial-byte
audit accounting and malformed-body drain deadlines. Serialization/policy binding
and client acknowledgement were strengthened during review. No further blocking
finding remained in this disabled integration scope.

The independent guarded full r2dgit race suite passed64 top-level tests with no
failures/skips in19.124s (`/tmp/gitsec-independent-app-r2dgit.log`). Scoped Go vet
passed (`/tmp/gitsec-independent-app-vet.log`). Independently recomputed sorted
source-tree SHA256 was identical before/after testing:
`171f10420baf140698449379c04c7541029e5b8a1da3e3a79716af6ee1470f09`, covering39 Go
files in r2dgit plus the new handler integration test, matching the committed source.

Independent guarded handler race testing at the exact commit also passed all36
`TestR2DGit` top-level cases, no failures/skips, in23.664s
(`/tmp/gitsec-independent-app-handler.log`). This includes all five new
application integration cases and their positive/negative matrices. Source was
unchanged; only this report and the handoff were edited afterward.

The root guarded application race suite passed7.660s before the source-only commit
(`/tmp/gitsec-app-integration-sixth.log`). It covers human-router admission,
cross-workspace project rights, two humans using the same admin-owned agent,
synthetic signed enrollment, fake Engine HTTP, real UDS/mTLS, real private Git
checkout, restricted storage and the actual current-reader HTTP endpoint. It also
executes a test-created helper subprocess using the real client and observes/reaps
its actual success/nonzero/no-receipt exits before settling. The new application's
provider is synthetic; pinned real local SSH/pack behavior is covered separately
by the full r2dgit suite, not claimed as this fixture's provider transport.

Negatives include signature/attempt/policy/channel/expiry/certificate substitution,
revocation during enrollment and stalled reads, terminal replay, provider outage,
forged scope fields/headers, read-channel pushes, early/cross-context result input,
missing result/acknowledgement, nonzero exit and reader ACL/provider denial. Restart
fixtures cover before-claim and running-owned-orphan crashes, forged attempt data,
receipt settlement and outage rollback/evidence retention. A real DB concurrency
test holds context SHARE locks, observes child admission waiting on completion's
queue lock, then verifies completion and child rejection without deadlock while
an already-issued child stays current. Byte-accounting/chunk-revocation and stalled
malformed-body tests cover the new delivery/parser boundaries.

### Full-check results at the frozen commit

The managed guarded `make test` failed eight regular tests
(`/tmp/gitsec-app-final-go.log`). R2D Git passed23.142s and service passed from
cache. Handler failed135.021s solely at `TestCommentSourceContextLifecycle`
(`cleanup target delete intents = 1`), the previously recorded source-context
cleanup case. A fresh serial guarded race run at clean baseline
`231dedb55287ab6e40fd103634a024e4d9d1baeb` reproduced that exact assertion in all
three repetitions (package0.664s, `/tmp/gitsec-app-baseline-source-context.log`).
This confirms the current cleanup failure also occurs on the baseline; it does
not explain earlier isolated passes or fix its cause. The seven other established
baseline failures also recur: DSH
process-tree cancellation, three Cursor MCP config cases, combined-output process
tree cancellation, worktree Git cancellation and local storage world-readability.
The regular failure stops make before the agent half. No full backend green result
is claimed, and unrelated assertions/source were not changed.

The separately guarded agent race failed26 tests in127.095s
(`/tmp/gitsec-app-final-agent.log`). Twenty-five names overlap the saved clean
baseline artifacts. `TestCodexExecuteCleansUpWhenScannerOverflowsOnResume` is
unmatched in those artifacts: cleanup took6.592s against its5s assertion. Fresh
three-repeat guarded race runs passed at the exact clean baseline
`231dedb55287ab6e40fd103634a024e4d9d1baeb` in5.439s
(`/tmp/gitsec-app-baseline-scanner-cleanup.log`) and current frozen commit in4.861s
(`/tmp/gitsec-app-current-scanner-cleanup.log`). These isolated passes do not
explain the full-run failure, which remains unresolved. The previously unmatched
`TestCaptureCursorBackgroundLateDescendant` did not fail this run; its earlier
failure is still unresolved. Agent/protocol/test-script sources remain unchanged;
that is evidence about patch scope, not a demonstrated cause of timing failures.

No frontend source changed; the prior9,298-test/typecheck/lint results remain
unchanged-source evidence and were not rerun. No sqlc query input/schema changed.
No mobile, Playwright, real runtime/native CLI/provider/custody/enrollment, restore
or containment acceptance ran. Final documentation links and `git diff --check`
are checked locally; the final handoff commit changes documentation only.

### Remaining gates

The exact next infrastructure action is to provision and accept the dedicated
Linux worker VM, mapped identities, enforced seccomp/AppArmor and cgroups/network
policy, then supply the fixed digest-pinned entrypoint image and reviewed live
enrollment/broker trust material. No such action is authorized in this local turn.
No production factory, daemon/provider-native entrypoint, live operator enrollment,
provider policy/custody setup, VM/containment acceptance or capability enablement
was performed. A synthetic signature and correct Engine Inspect configuration do
not certify containment. Production execution remains disabled.

S1 live custody/provider continuity, S2 protected retry/recovery issuance, S3 broader
Git/provider policy acceptance, S4 real runtime/native CLI integration, S5 all
historical/API/WS/search/export/MCP/attachment sinks and all-stream revocation, and
S6 real containment/restore/rollout gates remain open. This commit completes the
bounded local application lifecycle slice; it does not complete S0–S6 rollout.

No source upload, push/PR/merge/deploy, live key creation/enrollment, real agent/model
call, paid call, host security/network change or privileged Docker/VM operation ran.

## Final entrypoint closure and finite local acceptance

Starting from source `c42ec73ca948a42ac04833028a1bc8a384d2f54d` and handoff
`a01d88d74540c4922f1a386b97f3b74a6d6c410a`, local entrypoint implementation
`6314fb4f154a7cc4cec3fa7a4c4726fcf1a48015` and final reaper closure
`875d0152a26e1825807656e6064280b161f90a56` complete the finite **read-only v1**
software workflow. [The acceptance contract](protected-entrypoint-acceptance.md)
is the canonical end-to-end boundary, image/provider protocol and exact list of
missing production software versus deployment/live-validation prerequisites.
No further helper/interface slices are planned in this local task.

The actual Linux command obtains a bounded prepare-time issue assignment over its
channel, checks out an authenticated private snapshot, executes one fixed image
provider through bounded stdin/stdout JSON, stores restricted output and explicitly
acknowledges its receipt before exit. Issue ID and assignment digest are signed;
same-project issue swaps are rejected by current registration and private lifecycle
checks. Config/executable/argv/roots are image-owned, with private empty HOME/tmp,
minimal environment and no ambient credential, native session or generic result/log
fallback. Provider failures, malformed/overflow output and timeouts deny.

Review identified the final standalone-command reaping gap. The command now sets
its own child-subreaper flag before spawning, leaves each direct `Cmd.Wait` as its
sole reaper, then drains adopted children under a1s bound. It streams128-entry
`/proc` batches, caps scanned/owned processes, checks deadlines throughout, validates
PPID before/after `pidfd_open`, signals only through stable pidfds and waits for
`ECHILD`. Continuous exits/EINTR cannot bypass the deadline. Uncertain cleanup
forces nonzero exit and prevents private successful completion. This changes only
the command's process state, not host security settings or the shared server's
reaping behavior. Whole-container removal and actual PID1/containment acceptance
remain mandatory.

The first reaper attempt failed closed because this executor lacks optional
`/proc/self/task/<tid>/children`; the isolated adoption probe reproduced it. Those
failures are preserved in `/tmp/gitsec-entry-reaper-targeted.log` and
`/tmp/gitsec-reaper-probe.log`. The final implementation uses bounded process-stat
enumeration, without weakening pidfd signaling or changing the host. Failed-test
detached groups were stopped by their verified test-owned identities. The corrected
actual-command acceptance passed15.882s, including detached descendants disappearing
on revocation and successful provider exit (`/tmp/gitsec-entry-reaper-fixed.log`).
The final streamed command adoption/deadline tests passed2.487s
(`/tmp/gitsec-entry-reaper-stream.log`). These are new-command fixes, not fixes for
the unrelated pkg/agent process/timing failures.

### Final independent verification

At exact `875d0152a26e1825807656e6064280b161f90a56`, independent guarded handler
race testing passed all38 `TestR2DGit` top-level cases with no failures/skips,
53.776s (`/tmp/gitsec-independent-entry-handler-final.log`). This includes the
compiled command, two humans/same admin-owned agent/different projects and repos,
verbatim assignment data, private state, restricted output and actual reader HTTP,
plus all earlier current-rights/recovery/delegation/streaming matrices. Final
entrypoint acceptance took13.38s, including malformed command/config, provider
nonzero/overflow/malformed/timeout, and detached revocation/success with strict PID
disappearance. Assignment snapshot/swap/oversize cases passed1.15s.

Independent command race tests passed both top-level cases,3.101s
(`/tmp/gitsec-independent-entry-command-final.log`), and scoped vet for r2dgit,
command and handler passed (`/tmp/gitsec-independent-entry-vet-final.log`). All45
reviewed Go files matched the committed source before/after checks, SHA256:
`6002e7d42903a321cc360ebe416d845eddc0e52c9fde7d330a0d692d11ac31f3`.
No remaining blocking source finding remained within this disabled boundary.

The independently guarded full r2dgit race suite passed64 top-level tests with no
failures/skips in40.666s at exact6314
(`/tmp/gitsec-independent-entry-r2dgit-frozen.log`); the r2dgit package source is
byte-identical at875. The final closure changes only standalone command code/tests
and the corresponding handler entrypoint test. No migration, generated SQL input,
frontend, pkg/agent/protocol or test-script source changed.

### Broad checks and baseline comparison

The managed full `make test` at6314 passed the entire handler suite182.907s,
r2dgit25.269s and service from cache, but failed six regular tests
(`/tmp/gitsec-entry-6314-go.log`): three Cursor MCP config cases,
`TestCombinedOutputKillsDescendantsHoldingOutput`,
`TestCreateWorktreeContextCancelsRunningGitProcessTree` and
`TestLocalStorageUploadsAreWorldReadable`. All six have prior untouched-baseline
reproductions recorded above. DSH cancellation and the comment-source cleanup case
did not fail this run; earlier failures/reproductions remain recorded. This broad
run preceded the command-only reaper closure; final changed-path race/vet checks
are the independent exact875 results above. A full backend green result is not
claimed. Repeating unchanged legacy packages after the command-only closure was
not necessary to validate that closure.

A new complete guarded agent race run at untouched clean baseline
`231dedb55287ab6e40fd103634a024e4d9d1baeb` failed29 top-level cases in147.188s
(`/tmp/gitsec-entry-baseline-agent-full.log`). It now reproduces the exact formerly
unmatched `TestCaptureCursorBackgroundLateDescendant` assertion (group still active
after1s), as well as other process/semantic failures. Its earlier focused passes
and this reproduction do not explain or resolve the timing/process cause.

The final current-source guarded full agent race run at exact875 failed23
top-level cases in113.013s (`/tmp/gitsec-entry-final-agent.log`). Twenty-one also
failed in that fresh baseline run. The remaining two have matching failure
assertions in the earlier untouched-baseline artifact
`/tmp/multica-gitsec-baseline-agent-tests.log`:
`TestCodexExecuteRetryAfterCatalogFailureStartsFreshThreadForResume` (retry's80ms
no-progress timeout) and `TestOpencodeCancellationEscalatesToSIGKILL` (descendant
still alive after cancellation). Thus all23 have baseline reproductions across
runs; this does not claim an identical failure set or explain the failures.
Neither the earlier scanner-cleanup nor Cursor late-descendant case failed this
current full run. The scanner full-run failure remains without a reproduced
baseline assertion; its focused baseline/current passes do not resolve it. The
Cursor baseline reproduction likewise does not establish a cause or fix. All
earlier failed results remain recorded; no unrelated code/assertion was changed.

Frontend source remains unchanged; the prior9,298-test/typecheck/lint results are
unchanged-source evidence, not new runs. No sqlc input/schema changed. Mobile,
Playwright, real native/provider/custody/enrollment, actual containment and restore
acceptance were not run. Local documentation links and `git diff --check` pass;
the closing handoff commit changes documentation only.

Production remains disabled. Remaining **software** includes protected production
composition/dispatch, authenticated enrollment transport, native/model provider and
egress adapters, write/finalize integration, child/retry workload orchestration,
complete S5 historical/multi-source/all-surface coverage and operational rollout
composition. Separately, dedicated VM/image/kernel/profile/cgroup/network acceptance,
live custody/provider/enrollment, real native-provider/ACL-change and restore testing
are **deployment and real validation** prerequisites. Supplying credentials alone
does not close the missing software. Nothing was published, provisioned or enabled.

## Disabled model/edit/finalize continuation — 2026-10-16

Starting checkpoint: `b0bd80b20f954cbcb84a06dda2c87f7653c86bed`.
Scope matrix: `769085a9e`. Frozen source/test commit:
`ec8ff664e075400389ee84ad099ad173225e8184` (36 Go files, 2901 insertions/64 deletions).
All commits are local on `feat/git-security-local`. Existing project semantics
remain: Team = Workspace, with explicit cross-workspace direct project grants.

The [completion matrix](protected-completion-matrix.md) is the current supported
contract and surface inventory. The continuation adds bounded credential worker
composition/maintenance, mTLS enrollment issuer/client, persisted signed runtime
acceptance with online revocation, a compiled Responses provider and per-user
project gateway, constrained edits/exact-ref CAS finalization, isolated child
admission, durable fresh retries and protected-only scheduling/recovery/shutdown.
Service composition supplies real same-transaction terminal receipt settlement.
Production invokes the nil factory only; no serving route/capability was enabled.

Fixtures use synthetic accounts/keys/certificates, fake TLS custody/model/GitHub,
fake Engine, real local DB/Git and compiled provider/entrypoint over UDS/mTLS.
No real OpenBao, live key generation/enrollment, real model/provider or paid call,
container/VM provisioning, host-policy/network change, source upload/external push, PR,
merge or deployment occurred. Official public API docs were consulted without
source upload. No Codex Security scan was performed; the independent assessment
below is manual source review and local tests.

### Frozen independent review

The reviewer examined all 36 changed Go files against the frozen commit, including
retry/write-intent fencing, current authorization, provider policy, accepted-byte
delivery audit, live acceptance revocation, TLS validation and shutdown cancellation.
No remaining blocking source finding was identified within the supported disabled
scope. Before/after content matched the frozen commit; review manifest SHA256:
`a65d0947ca18be27ee0e12baa6e07b33bf96712c342271614121079996d41e1d`.

| Frozen check | Result | Evidence log |
| --- | --- | --- |
| Guarded handler race `-run TestR2DGit -count=1 -timeout=150s` | 45 top-level cases passed, zero failures/skips, 59.567s | `/tmp/gitsec-independent-completion-handler.log` |
| Full r2dgit race | 70 cases passed, zero failures/skips, 19.282s | `/tmp/gitsec-independent-completion-packages.log` |
| protected-agent command race | 2 cases passed, zero failures/skips, 2.679s | Same package log |
| protected-provider command | Compiles; no own tests; actual binary exercised by handler integration | Same package log |
| Vet r2dgit/handler/service/protected-agent/protected-provider/server | PASS | `/tmp/gitsec-independent-completion-vet.log` |
| Root serial command race `-count=3` | Both cases passed all three repeats, 5.462s | `/tmp/gitsec-completion-command-frozen.log` |
| Managed full `make test` | Regular portion failed 8 cases; full handler passed 288.896s, r2dgit 21.469s, service 36.243s; protected-agent 2.869s | `/tmp/gitsec-completion-frozen-make-test.log` |
| Darwin/arm64 non-CGO build of r2dgit and cmd/server | PASS | `/tmp/gitsec-completion-darwin-build.log` |
| Guarded full agent race `--only agent` | Failed 25 top-level cases, 112.437s; matching baseline assertions as detailed below | `/tmp/gitsec-completion-frozen-agent.log` |

The handler matrix includes signed acceptance/revocation/replay/wrong-peer,
gateway user/project/account selection, actual provider success and revocation,
forged selectors, read-only write denial, successful CAS and ambiguous-finalize
refusal, independently prepared children, fresh retry/current rights/old-attempt
denial, automatic fresh retry, atomic settlement and shutdown during stalled
credential cleanup. User A can read their restricted result; user B sharing the
same admin-owned agent cannot. GitHub fixtures reject wrong account, default,
protected, rules-covered or missing branches, redirect and missing account.
Existing unprotected feature branches are the selected concrete write policy;
new-branch/Gitea policy support and live-provider acceptance are incomplete.

### Failed intermediate checks and unresolved observations

All failures remain evidence; later passes do not erase them:

- Initial enrollment positive/replay fixtures failed because fractional lease
  expiry exceeded second-precision X509 expiry. Supervisor TTL now clamps to
  certificate expiry with one captured time. All enrollment cases subsequently
  pass (`/tmp/gitsec-completion-enrollment{,-fixed,-clamped}.log`).
- A model-cancellation fake server waited without consuming its POST body and
  prevented shutdown. The exact owned test process was stopped after command-line
  verification. The fixture now drains the body before waiting; gateway cases
  pass (`/tmp/gitsec-completion-model-unit-fixed.log`). One unused-import compile
  failure was corrected before frozen verification.
- The first handler suite rejected the journal-restart test's invented IDs after
  intents gained immutable-context validation. That fixture now uses a real sealed
  running run and additionally rejects a forged attempt. Restart/indeterminate
  assertions remain (`/tmp/gitsec-completion-handler-first.log`).
- The second handler suite timed out in the new deployment fixture's synthetic
  `DestroyAll` setup, waiting on an unbounded background context during revoke
  before the shutdown assertion. Setup revoke now has a 500ms bound; the actual
  blocked-Tick/Close cancellation assertion remains. The composed workflow had
  succeeded. Go cleanup did not run, leaving fixture rows. Read-only inspection
  identified exact synthetic users/workspaces; a guarded transaction removed only
  that verified pair and dependencies. The third attempt's fixture-owner FK error
  and timeout remain in `/tmp/gitsec-completion-handler-{second,third}.log`.
  No production/unrelated data was removed. The fourth handler run passed all 45
  in 56.586s; the independent frozen run also passed.
- A parallel package run failed `TestStandaloneReaperAdoptsChild` with
  `child_cleanup_unconfirmed` in 1.12s
  (`/tmp/gitsec-completion-core-second.log`). Command source/tests are byte
  unchanged from b0. Frozen current commands pass three isolated repeats;
  untouched clean b0 passes five isolated repeats in 8.119s
  (`/tmp/gitsec-completion-b0-reaper.log`). **The failed assertion has not been
  reproduced at baseline and its cause remains unresolved.** Load/contention is
  not an established cause. Cleanup uncertainty fails closed at runtime.

Earlier scanner-cleanup and agent/process failures and baseline comparisons remain
recorded above. No unrelated assertion was weakened.

The frozen managed full `make test` first verified the existing migrations were
applied, then failed its regular portion. Seven cases have prior untouched-baseline
reproductions: DSH cancellation, three Cursor MCP configuration cases, combined
output descendant cancellation, worktree Git cancellation and local storage
world-readability. The eighth was a newly observed
`TestHTTPClient_DownloadMessageResourceUsesResourceTimeout` timeout obtaining its
local synthetic tenant token. A fresh five-repeat race run at clean untouched
`231dedb55287ab6e40fd103634a024e4d9d1baeb` reproduces the exact assertion once,
with four passes (`/tmp/gitsec-completion-baseline-lark.log`, 0.430s). The frozen current five-repeat check passed in 1.464s
(`/tmp/gitsec-completion-current-lark.log`). Lark source is byte unchanged. This establishes baseline reproduction, not its cause or a fix.
The full handler, r2dgit, service and command passes do not make the overall
backend check green. The regular failure prevents make from entering its agent
half; that suite was run separately.

The frozen guarded agent suite failed 25 top-level cases in 112.437s. Twenty-four
have matching failure assertions in the clean untouched baseline full-run log
`/tmp/gitsec-entry-baseline-agent-full.log`; the remaining
`TestCodexExecuteRetryAfterCatalogFailureStartsFreshThreadForResume` has the same
retry 80ms no-progress timeout assertion in
`/tmp/multica-gitsec-baseline-agent-tests.log`. Comparison includes assertion
messages (apart from PIDs/durations), not test names alone. All 25 therefore have
baseline reproductions across those runs, without claiming identical failure
sets or a cause/fix. The earlier scanner-cleanup and unmatched reaper failures
remain unresolved even though they did not recur in this final run.

No frontend, mobile, SQL/schema/sqlc input, pkg/agent/protocol or test-script source
changed in this continuation. Frontend, mobile and Playwright checks were not
rerun; prior results above remain unchanged-source evidence only. Non-Linux build,
independent changed-path race/vet, all four modified documents' local links and
`git diff --check` pass. The final handoff commit changes documentation only.

### Remaining work

Stage 5 is partial: complete historical classification/backfill, full source-union
provenance and every API/WS/search/export/MCP/attachment/native-memory reader and
stream cancellation remain software work. Stage 6 has disabled composition and
startup recovery, but external anti-rollback tombstone/epoch restore reconciliation
and accepted production serving/configuration integration remain incomplete.
Additional provider/policy/large-repository support needs software work. Operator
VM/image/namespace/profile/cgroup/network acceptance, live custody/enrollment,
provider/ACL-change tests and restore drills remain unperformed. Synthetic
signatures and fake engines certify none of these. This is a local continuation,
not completed PR92/S0–S6 rollout acceptance.


## Historical source union and restore reconciliation — 2026-10-16

Frozen source/test commit: **`8b6be5bcd611c6cc6eb8590a1726eb980f5cd3ce`**.
Starting documentation checkpoint: `480a89e0f81edaa32efc9058762d88e0c381c88f`,
with underlying prior source `ec8ff664e075400389ee84ad099ad173225e8184`.
Implementation commits are `7503eee6784ba0127cc2b2da4dc8a63cd5f7f7f9`,
`0bffcc7d95018e33af83aa6f72a4ac5b0be722ad` and the frozen commit above.
The final handoff commit changes documentation only. All remain local.

### Delivered boundary

The [application inventory](protected-source-surfaces.md) identifies the actual
router and delivery seams. A global pre-authentication source hold denies generic
API, login/bootstrap, search/export/history, readerless storage/download and public
plugin/media routes whenever any protected repository, quarantine or restore
checkpoint exists. Exact restricted Git control/output routes retain their normal
session/task authentication and current authority. The fixed content-free exact
GET `/health` liveness response is available even during policy failure. CORS
preflight retains its existing contract before content authorization. A nil-pool
route-only constructor cannot replace the process's installed delivery policy.

Actual WebSocket writer checks include captured frames on existing connections;
the bus checks before listeners; daemon RPC/task details and claims are fenced.
Queued plugins, mail, channels, telemetry/analytics and server assist LLM check at
the actual outbound transport/writer seam, including redirects, retries and supplied
clients. Slack, assist LLM and Resend defaults retain their SDK transport/timeout/
normalization behavior. Broad CDN refresh/renewal is suppressed even on allowed
control routes. Profile options disclose no stored project title or title order.
Production installs policy before legacy background construction and refuses the
legacy worker graph under a hold. Production still supplies nil protected config.

Trusted derived-output storage retains its own sealed source plus every input's
origin context, with bounded input/source/recursive graph limits and persisted
edges. Missing provenance, duplicate inputs, cycles, any origin/ancestor rights
loss or the reader's own key loss deny. Delivery checks each 16KiB chunk. Public
workload requests cannot nominate source IDs. Issue assignment separately requires
fresh signed exact title/description, project/provider/repository classification;
current object location alone never labels old source public. Team remains the
existing Workspace; explicit cross-workspace project grants and the immutable
originating human remain authoritative, with no admin-agent fallback.

A private Linux witness outside the DB/credential backup domain uses exclusive
creation, private ownership/mode, bounded parsing, fsync and flock. Startup never
creates or resets it. Every held transaction compares the singleton DB anchor
with the external nonce. The lock spans durable advance through DB commit, with
bounded cancellation-independent commit finalization. A fresh independent reader
pool avoids caller-pool starvation and old-snapshot false mismatches. Read-only
finalization also checks the caller's snapshot under the same lock. Only four
audited pure DB readers retry a stale snapshot, at most three times; writes and
uncertain commits never retry. Crash/commit uncertainty remains closed.

Trusted service reconciliation, without an HTTP recovery route, requires
quiescence. It quarantines every surviving workspace/user/project, cancels active
tasks, revokes restored keys/contexts/grants and invalidates old runtime acceptance,
assignment attestations and execution approvals. Fresh signed governance assigns
explicit project managers and demotes stale workspace owners/admins rather than
promoting managers to workspace admin. Exact human/workspace/agent/runtime/project
execution approval, current rights, key activation, classification and runtime
acceptance are separate prerequisites. Approval expiry denies historical derived
output too. DB triggers deny ordinary authority/lineage/status changes in held
scopes unless the transaction is witnessed. A surviving anchor also denies direct
unwitnessed service writes. New retained tables preserve source tombstones,
instance checkpoint and derivation history across workspace deletion.

Migrations `900124`–`900129` add side tables, separately concurrent indexes,
authority guards and execution holds, without upstream columns or foreign keys.
Each new index is in interrupted-build cleanup; the retention manifest accounts
for all three tables. The standalone side-table round trip covers all 30 local
side-table migrations, including conditional upstream-trigger installation.

The selected actual adapter is compiled `cmd/protected-provider`, a fixed bounded
JSON/text direct HTTP Responses implementation through the per-user protected
`ResponsesGateway`. It is separate from the server assist SDK and native Codex/
Claude CLIs. The earlier limits remain: small text repositories, existing
unprotected GitHub feature refs, no generic tools/MCP/native resume, no Gitea
writes/new-branch policy/PR API/LFS/submodules/signing. This continuation adds no
provider call or credential lookup.

The main review entrypoints are the
[application source boundary](../../server/internal/handler/r2d_git_source_boundary.go),
[immutable output union](../../server/internal/r2dgit/output.go),
[restore coordinator](../../server/internal/r2dgit/restore.go),
[file witness](../../server/internal/r2dgit/restore_witness_linux.go),
[governance approval](../../server/internal/r2dgit/restore_approval.go) and
[execution approval](../../server/internal/r2dgit/restore_execution.go).
The [source-authority startup](../../server/cmd/server/source_authority.go) keeps
this implementation disabled in ordinary production composition.

### Independent review and checks

The independent reviewer confirmed clean frozen commit
`8b6be5bcd611c6cc6eb8590a1726eb980f5cd3ce`, reviewed the source/restore boundary
and follow-up SDK/CORS/index/retention delta, and reported no blocking finding in
the disabled local scope. Root exclusively owned the DB test slot; final review
was static, performed no edits or DB tests, and did not certify live isolation,
restore operation or a green full backend. Earlier findings led to fresh witness
verification, snapshot serialization, cancellation finalization and retained
retention/default contracts before freezing.

| Frozen-source check | Result | Local evidence |
| --- | --- | --- |
| Full managed handler race suite, with 53 R2DGit cases defined and the 30-migration round trip | PASS, 180.266s | `/tmp/gitsec-s5-8b6-full-go.log` |
| Migration command full race package | PASS, 41.743s | Same full log |
| Server command full race package, actual router/WS/plugin boundaries | PASS, 27.246s | Same full log |
| r2dgit/sourceguard/events and guarded SDK/mail packages | PASS: r2dgit 21.290s, service 35.957s, LLM 1.080s; other unchanged checks cached | Same full log |
| Managed full `make test`, serialized DB packages | FAIL 7 regular top-level cases with prior baseline reproductions; regular failure prevents automatic agent half | Same full log |
| Separate guarded full agent race suite | FAIL 26 top-level cases, 134.225s; all 26 assertion blocks have baseline matches | `/tmp/gitsec-s5-8b6-agent.log`, `/tmp/gitsec-s5-8b6-agent-baseline-comparison.log` |
| Scoped vet: r2dgit/handler/service/sourceguard/commands | PASS | `/tmp/gitsec-s5-8b6-vet.log` |
| Darwin/arm64 non-CGO r2dgit and server build | PASS | `/tmp/gitsec-s5-8b6-darwin.log` |
| sqlc v1.31.1 regeneration | PASS; generated code unchanged | `/tmp/gitsec-s5-8b6-sqlc.log` |

The regular invocation uses the Go test cache for unchanged packages where valid,
including the protected-agent command; that is not a new uncached reaper repeat.

Positive/negative fixtures cover authorized cross-workspace A, same-agent B denial,
union readers needing both repositories, origin revocation after the first chunk,
missing/deleted/cyclic provenance, exact assignment changes/wrong signer/expiry,
all-surface/default denial and readerless storage. Restore fixtures exercise
revoked DB backup restoration against a newer external witness, missing/corrupt/
symlink/unsafe witness refusal, explicit quarantine reconciliation, fresh key and
runtime/assignment/execution approval, separate A/P1 and B/P2 governance,
restored active task cancellation, caller cancellation/pool exhaustion and a
deterministic read-vs-offboarding snapshot barrier. Existing actual compiled
entrypoint/provider, broker, child, retry and current-reader suites remain in the
full handler matrix.

### Failure evidence and diagnosis limits

Failed checks remain evidence; later passes do not erase them:

- Before the final default-preservation follow-up, full managed `make test` at
  `0bffcc7d9` failed 15 top-level cases in its regular portion
  (`/tmp/gitsec-s5-final-full-go.log`). Seven integration regressions were CORS,
  diagnostics route behavior, two plugin retry fixtures, missing index cleanup
  registration and missing workspace retention entries. All seven have targeted
  passing regressions in `/tmp/gitsec-s5-preserve-boundaries.log`. A first new
  assist SDK test lacked the fixture JSON content type; corrected fixture and
  custom-client/default tests pass in `/tmp/gitsec-s5-sdk-defaults2.log`.
- Seven regular failures already have untouched-baseline reproductions recorded
  above: DSH cancellation, three Cursor MCP config tests, combined-output descendant
  cancellation, worktree Git cancellation and local-storage world readability.
  The newly observed source-context cleanup-budget assertion also reproduces
  three out of three at clean `231dedb55287ab6e40fd103634a024e4d9d1baeb`:
  delete attempts=1, expected batch size=2
  (`/tmp/gitsec-s5-baseline-cleanup-budget.log`). This does not establish its cause.
- The standalone reaper failed nine of ten concurrent repeats at `7503eee67`
  (`/tmp/gitsec-s5-frozen-reaper10.log`) and once in that core run
  (`/tmp/gitsec-s5-frozen-core.log`). The executor exposed 13,076 process entries;
  an idle stat scan took about 163ms. Load is plausible but **not an established
  cause**, and no particular failed phase was established by those old errors.
  An attempted own-task `children` enumeration was rejected and fully reverted:
  this executor lacks that optional proc file, so it falsely observed no children.
  No host setting or compatibility shim was introduced. The correct final code
  keeps a nonblocking final ECHILD observation after deadline and adds internal
  `reap`/`signal_scan` phase diagnostics; external stderr remains fixed unavailable.
  Bounded live-child, exit/EINTR/continuous-status controls pass. Ten isolated
  phased repeats pass in 17.576s (`/tmp/gitsec-s5-reaper-final-phase.log`), and the
  regular command package later passes. These passes **do not explain or fix the
  earlier uncertainty**. Real PID1/whole-container cleanup acceptance stays open.
- Before final source, full guarded agent race failed 27 cases at `7503eee67`
  (`/tmp/gitsec-s5-frozen-agent.log`) and 29 at `0bffcc7d9`
  (`/tmp/gitsec-s5-final-agent.log`). Twenty-eight of the latter have matching
  baseline names across earlier logs; name matches alone do not prove assertions.
  The unmatched `TestCaptureCursorBackgroundProcessReapsLeaderExitedGroup` reports
  a group still active after one second. Three isolated clean-baseline repeats
  pass (`/tmp/gitsec-s5-baseline-new-agent.log`), and a fresh clean-baseline full
  run fails 27 other cases while this case passes
  (`/tmp/gitsec-s5-baseline-agent-full.log`). Its baseline reproduction and cause
  therefore remain unproven. `pkg/agent` source/test bytes are unchanged from
  `231dedb5`; that does not resolve the failure. Earlier scanner cleanup uncertainty
  also remains recorded, with no fix claim.

At the frozen final source, the separate guarded agent race suite fails **26**
top-level cases in 134.225s (`/tmp/gitsec-s5-8b6-agent.log`). All 26 assertion
blocks match untouched-baseline full-run evidence after normalizing only varying
PIDs/durations (source line locations are unchanged); the comparison is recorded
in `/tmp/gitsec-s5-8b6-agent-baseline-comparison.log`. Most match the fresh baseline
full run; Cursor late-descendant matches `/tmp/gitsec-entry-baseline-agent-full.log`,
and graceful OpenCode cancellation matches
`/tmp/multica-gitsec-baseline-agent-tests.log`. The Codex retry 80ms assertion matches
the fresh baseline full run. This is assertion comparison, not test-name matching,
and establishes neither a cause nor a fix. The previously unmatched Cursor
leader-exited-group and scanner/reaper observations remain open even though they
did not recur in this final agent invocation.

At the frozen final source, full managed `make test` completes its regular half
and fails **seven** top-level cases: DSH process-tree cancellation, three Cursor
MCP configuration tests, combined-output descendant cancellation, worktree Git
cancellation and local-storage world readability. These are the seven prior
baseline-reproduced assertions listed above. The full handler, service, server,
migration and core security packages pass; no new source/restore test fails.
`TestCleanupSourceContextObjectIntentsBoundsAttemptsNotSuccesses` passes in this
final full run. Its earlier three baseline failures remain uncertainty evidence,
not a diagnosed/fixed cause. The regular failure prevents make from automatically
entering its agent half, which was run separately as recorded above.

The managed DB suites were serialized (root-only DB slot and `GOFLAGS=-p=1`) so
restore fixtures cannot overlap other packages' transactions. Guarded agent tests
run separately with only test-created fake/missing CLIs. No real agent/model smoke
was authorized or run. sqlc uses locally cached v1.31.1 after `make sqlc` dependency
fetch failed with HTTP403; generated DB code is unchanged. Frontend/mobile and
Playwright were not rerun because no UI/TypeScript/mobile code changed. Temporary
logs are local supporting evidence, not uploaded artifacts. Document links and
`git diff --check` are checked before the final documentation commit.

### Remaining gates

The local historical/source-union and restore reconciliation slice is implemented
as enforce-or-deny software. It does not claim public historical backfill or
production serving. Protected-control login/UI and reviewed production operator
composition/configuration remain software work. A transition must quiesce legacy
work; guards cannot recall already delivered/in-flight HTTP/SMTP/socket bodies,
prior CDN credentials or old native/MCP/provider state. Unknown external keys lost
from a restored DB require external inventory. Combined rollback of both witness
and DB is outside the trust boundary. Additional provider/policy support remains
separate software work.

Dedicated VM/image/user namespace/UID/seccomp/AppArmor/cgroup/network acceptance,
actual provider rights/policy and revocation, live custody/key enrollment, external
key/CDN invalidation and an independent-domain restore drill remain unperformed.
Unresolved full-check and cleanup/reaper failures remain gates. Production stays
disabled, with no capability, security setting, live key, OpenBao, deployment or
host-network change. No source upload, push, PR, merge, publication or paid call
was performed. This is not completed PR92/S0–S6 rollout acceptance.


## Explicit local authentication and serving — 2026-10-16

Frozen source/test: **`141ab40970847e8cba27b9491fb048d503c6bb0a`**.
Starting checkpoint: `8b80cca6faf0869b548348b91470c41ad584f8a0`.
Local implementation commits: `58a63cf87` (observed reaper fixture), `43953389f`
(authentication/serving), `6f87cd106` (session-generation UI fix) and `141ab4097`
(native form fallback). The final handoff commit is documentation only.

The user explicitly authorized completing local authentication/serving and testing,
with production disabled, synthetic fixtures and no real keys/providers, host
security changes or publication. No exact previously denied tool action was
available in this execution history to retry, and no retry/approval-review success
is claimed. Direct authorized local edits and checks proceeded. A real browser
launch, detailed below, remains blocked by the unchanged executor sandbox.

### Completed local integration

[The local serving contract](protected-local-serving.md) records the actual API,
configuration and ownership. This is a concrete two-listener TLS server and a fixed
control page, composed with fresh human authentication and the protected worker;
it is not only interface declarations. The main integration test opens actual
loopback TLS listeners and drives fresh login through HTTP cookies to durable
human admission, the actual compiled entrypoint/provider, mTLS broker and restricted
result. User A succeeds; user B sharing the same admin-owned agent is denied.
The execution workspace and resource workspace remain distinct. Team remains
Workspace and explicit cross-workspace project grants remain authoritative.

The server refuses wildcard/non-loopback endpoints, mismatched control origin/
broker URL, weak/unverified TLS, dynamic TLS callbacks, malformed or mismatched
server key material and missing broker client verification before worker
construction. Certificate hostname/validity and key pairing are checked. Session
tickets are disabled. Only fixed controls, current Git identity/run/output/policy
APIs, session operations and content-free liveness are mounted. Generic routes,
legacy login/CLI exchanges, broad profile narratives, CDN signing, uploads/search/
WS/MCP, ambient native sessions and legacy background construction stay absent.
No environment switch selects this server. Production main remains nil/disabled.

Fresh authentication is existing-account only: random three-minute six-digit
codes, browser-bound challenge cookie, bounded attempts/rates/registry, consumed
proof before uncertain writes, witnessed single-use event CAS and current exact
email/user checks. No dev verification override, signup or JWT/PAT/task/CLI
promotion is accepted. Sessions are opaque, stored by hash in an ephemeral
registry, use their own Secure/HttpOnly/SameSite=Strict host cookie and expire in
15 minutes without sliding original auth time. Mutations require exact Origin
and session CSRF. Headers cannot select the human. Pending challenge and session
events are explicitly invalidated by restore reconciliation; DB events cannot
reconstruct registry secrets after restart.

The concrete SMTP authentication sender has explicit, prevalidated configuration,
verified implicit TLS1.3 and bounded cancellation. Its only payload is a fixed
sign-in message, a validated mailbox and six server-generated digits. It cannot
accept a narrative/subject/template/attachment and does not release ordinary mail
from its historical-source guard. Its live network test is a local synthetic TLS
SMTP peer, without real enrollment or accounts.

A fifth audited pure DB reader validates current control-session events/email with
the existing repeatable-read/witness finalization. Ordinary authenticated GETs do
not advance the global checkpoint. Registry state is checked before and after DB
validation; actual response writes/flushes recheck within each 16KiB chunk. The
source's own origin/ancestor/key/provider checks remain independent. A deterministic
snapshot-vs-committed-logout regression and captured-response closure test pass.

The page supports login/logout, public Git identity lifecycle and consent, read-run
admission/status/revoke, restricted output and project grants. It renders source
as text, uses no persistent browser source/credential storage, clears content on
logout/expiry and reports unconfirmed server logout. Authentication mutations are
single-flight; a local session generation checks late headers, parsed bodies,
errors and immediate DOM updates. Native form fallback is POST and fails closed
if the script is unavailable, rather than putting email/code in a GET URL.

### Independent findings and fixes

Independent review identified and verified these fixes before acceptance:

- Per-request session validation originally used a mutation transaction. It now
  uses the fifth pure read-only fence, avoiding checkpoint churn and preserving
  current-snapshot finalization. A regression asserts GETs do not advance witness.
- TLS shape checks alone allowed dynamic callbacks to replace broker settings.
  Dynamic callbacks and mismatched/malformed key pairs are refused. Negative cases
  use otherwise valid Source/Worker config and assert no credential composition.
- A delayed A response body could repopulate cleared DOM after logout/B login.
  The independent `/tmp/gitsec-independent-control-ui-race.cjs` reproduced it at
  `43953389f`; the existing 3 cases passed and the added case failed. The generation
  fix checks after body consumption and immediately before rendering, drops stale
  errors/initial metadata, and serializes auth cookie changes. The original 4-case
  harness now passes, and repository regressions cover both output and identity
  data across B login. Earlier accepted bytes are not claimed to be recalled.
- UI logout now clears content immediately and reports network/revocation
  uncertainty rather than silently implying success. Native POST fallback closes
  the script-load credential-URL edge case.

The independent reviewer accepted the corrected delta at `6f87cd106`, then
confirmed exact final `141ab40970847e8cba27b9491fb048d503c6bb0a`, all eight native
POST forms, seven passing repository UI cases with no skips, and no additional
blocking finding in this local scope. Review performed no DB tests or repository
edits on the authentication/server work. The reviewer authored the stricter reaper
fixture; root independently reviewed that test-only diff before committing it.
Root exclusively owned the serialized DB test slot.

### Verification and retained failures

All final commands used frozen source 141, the repository-managed environment,
local caches and guarded fake/missing agent CLIs. DB packages ran only in root's
serialized slot (`GOFLAGS=-p=1`). No package source changed during these checks.

| Check at 141 | Result and evidence |
| --- | --- |
| `GOFLAGS=-p=1 make env-exec ARGS='-- make test'` | Completed with **9 top-level failures in 6 packages**, 65 package passes and 16 no-test packages; regular failure prevents automatic agent half. `/tmp/gitsec-control-141-full-go.log` |
| Handler/core/auth/middleware | Handler PASS 150.473s (including real TLS composition, authorization/restore and Node UI cases); r2dgit PASS 20.241s; middleware PASS 1.589s; auth PASS cached in the full command |
| Command/migration/service packages | Server, migration command/tests and protected-agent PASS cached. Service FAIL 72.720s on the already baseline-reproduced cleanup-budget assertion below |
| Separate `make env-exec ARGS='-- bash scripts/test-go.sh --race --only agent'` | Completed FAIL: 28 top-level cases, 129.743s. 27 recorded baseline assertion matches; Codex continuous-message timeout remains unmatched. `/tmp/gitsec-control-141-agent.log` |
| Scoped `go vet` | PASS, exit 0. `/tmp/gitsec-control-141-vet.log` |
| `GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build` for core/middleware/handler/server | PASS, exit 0. `/tmp/gitsec-control-141-darwin.log` |
| JavaScript syntax and repository Node UI logic | PASS, 7 tests, 0 failures/skips; `/tmp/gitsec-control-ui-native-post.log`. Independent 4-case race harness also PASS |
| Documentation targets/whitespace | 40 local Markdown targets resolve; `git diff --check` PASS before the documentation commit |

Eight regular failures have recorded untouched-baseline assertions: DSH process-tree
cancellation, three Cursor MCP config cases, combined-output descendant cancellation,
worktree Git cancellation, local-storage world readability and cleanup-budget
attempt accounting. The latter recurred as `delete attempts = 1`, expected 2,
`source_context_cleanup_budget_test.go:134`; the earlier clean 231 baseline log
`/tmp/gitsec-s5-baseline-cleanup-budget.log` records the same assertion on all three
repeats. It passed at 8b6 but its cause was not fixed or explained. The ninth regular
failure, Pi upstream cancellation, has no established baseline reproduction.

Focused pre-freeze evidence remains useful, with exact limitations:

- Auth initial 4 top-level cases plus 4 subcases PASS 2.447s
  (`/tmp/gitsec-control-auth-first.log`). Expanded 5 top-level cases plus 6 subcases,
  including stream closure and deterministic logout race, PASS 2.126s
  (`/tmp/gitsec-control-auth-second.log`).
- Actual two-listener fresh-login/compiled workflow plus invalid-config controls
  PASS 9.131s (`/tmp/gitsec-control-server-second.log`). The first attempt had a
  test compile error using the wrong ContextSpec field
  (`/tmp/gitsec-control-server-first.log`); the fixture now checks immutable
  `Binding.OriginatorUserID` and keeps the substantive identity assertion.
- Concrete SMTP fixed-body/verified-TLS/header rejection and stalled-handshake
  cancellation PASS 1.087s (`/tmp/gitsec-control-smtp-first.log`).
- Seven UI logic/native POST cases pass
  (`/tmp/gitsec-control-ui-native-post.log`); the independent original 4-case
  race harness passes (`/tmp/gitsec-control-independent-ui-recheck.log`).
- Scoped vet and Darwin/arm64 build passed at 439 before the UI-only followups;
  final checks are listed above. One initial unmanaged handler compile invocation
  reached its TestMain and failed on the wrong DB schema/workspace table; it is
  retained in `/tmp/gitsec-control-server-compile.log`, not treated as a managed
  package pass. Subsequent DB runs use the repository environment.
- Broad 439 and 6f87 attempts were intentionally stopped after review/native-form
  corrections, before the handler DB suite. Root inspected exact process-group
  ownership before SIGINT; no unrelated process was targeted. Partial logs
  `/tmp/gitsec-control-{439,6f87}-full-go.log` are intermediate evidence only.
  Final verification runs at 141. No running DB fixture was abandoned.

The final guarded agent half failed **28 top-level tests** in 129.743s
(`/tmp/gitsec-control-141-agent.log`). A comparison of assertion bodies, with only
PIDs/durations normalized, matched 26 to prior untouched-baseline full logs
(`/tmp/gitsec-control-141-agent-baseline-comparison.log`). The initial comparison
missed the verbose baseline's assertion-before-FAIL format: Claude graceful
cancellation also matches `claude_cancel_unix_test.go:72` in the earlier independent
clean 231dedb baseline log, lines 206–207
(`/tmp/gitsec-independent-s456-baseline-agent.log`; baseline provenance is recorded
in the earlier independent review). Thus 27 have recorded baseline assertion
matches; this does not make cancellation/cleanup acceptable or prove their cause.

The remaining agent failure is
`TestCodexExecuteSemanticInactivityAllowsContinuousMessages`: expected completion,
received a 90ms semantic-inactivity timeout after `tool-result:exec_command`.
The final regular run also failed
`TestExecuteAndDrain_PiWithoutTurnErrorKeepsUpstreamCancellation`: expected upstream
cancellation, received `aborted`/`execution cancelled`. **Neither new assertion
has a matching baseline failure established.** On clean untouched
`231dedb55287ab6e40fd103634a024e4d9d1baeb`, guarded race repeats of Codex continuous
messages and Claude graceful cancellation all passed (three each, six total,
zero skips, 2.046s; `/tmp/gitsec-control-baseline-agent-focus.log`). The independent
reviewer's guarded Pi baseline repeats also all passed (three, zero skips, 1.093s;
`/tmp/gitsec-independent-control-baseline-pi.log`). Passing targeted repeats do not
explain a broad-suite failure. Provider/fixture source is unchanged; the existing
Pi result-vs-context select suggests a possible race but no cause/fix is claimed.
No runtime or test expectation was weakened to turn these checks green.

The earlier 439 and 6f87 agent runs also failed 28 cases, with a different unmatched
Cursor leader-exit cleanup assertion retained in their logs. The earlier cleanup,
process-tree and reaper uncertainty is not closed by this continuation. Final
full-suite status is failed; the two unmatched final assertions and actual host
containment remain review blockers outside the completed local control delta.

### Reaper and browser diagnosis boundaries

The standalone production reaper algorithm is unchanged in this continuation.
The stricter fixture observes a live adopted PID, its exact parent and stable
pidfd in both helper and parent before releasing the start barrier. The measured
drain keeps the exact 1s budget; success additionally requires independent ECHILD
and PID absence. Failure cleanup uses already-opened stable handles, not raw PID
or group signaling. Test-only post-failure process observations have a separate
100ms bound and are labelled as observations, not historical failed-scan telemetry.

The reviewer's guarded race run executed three top-level cases ten times:
30 passes, no failures/skips, with measured successful drains 300–532ms
(`/tmp/gitsec-independent-reaper-handshake-{first,repeat}.log`); scoped vet and
whitespace checks passed. That improves future evidence but does not establish a
cause/fix for the earlier 9/10 failed repeats, unmatched cleanup observations or
actual container/PID1 behavior. Final full-package results remain above.

A sandbox-enabled Chromium/Playwright launch aborted before rendering:
`/usr/lib/chromium/chrome-sandbox` was found but not correctly configured for the
SUID sandbox; crashpad also reported its missing database configuration
(`/tmp/gitsec-control-browser-sandbox.log`). No `--no-sandbox`, chmod/chown,
user-namespace, kernel, container or security-policy workaround was attempted.
This is a real-browser environment blocker, not an automatic-approval rejection.
HTTP/TLS behavior and isolated browser logic pass; rendered browser acceptance is
not claimed. No frontend shared/mobile/TypeScript code changed, so unrelated
frontend/mobile suites were not rerun. New JavaScript syntax and behavior are
checked directly and through the Go handler package. Schema/sqlc inputs are
unchanged; this slice adds no migration or generated query change.

### Remaining scope

The finite local authentication/serving integration is implemented. Production
main still does not select it; there is no deployed ingress, live account/key or
host acceptance. The local page intentionally provides a narrow ID-scoped control
surface, not the generic historical product UI or every provider/policy feature.
A reviewed production selection/configuration and quiescent transition still need
operator acceptance; the dedicated VM/image/UID/namespace/seccomp/AppArmor/cgroup/
network boundary, real custody/enrollment/provider ACL changes, external key/CDN
reconciliation and independent-domain restore drill remain unperformed. Guards
cannot recall legacy delivered/in-flight source or previously minted CDN/native
state. Combined rollback of DB and witness remains outside the trust boundary.

Full-check and historical cleanup/reaper uncertainty are still reported; local
software completion does not mean PR92/S0–S6 production rollout acceptance. All
changes remain local commits. No source upload, push, PR, merge, deployment, real
key enrollment, OpenBao setup, host security change, model or paid call occurred.

## Focused cancellation and cleanup resolution — 2026-10-16

Source candidate: **`dafa551b94a272d7f62cad54c082d850a71bd270`**, starting from
`e32c17ec544b6c47cf9711172e14763926bf1f37`. The [candidate guide](protected-local-candidate.md)
records the usable supported contract and explicit deployment prerequisites.
Production remains disabled. The user explicitly requested resolving the Pi,
Codex and process-cleanup observations through focused reproduction, recoverable
local fixes and independent review. No host, security policy or live service was
changed. This section supersedes the previous unresolved-candidate status.

### Matched evidence and fixes

- Original Pi cancellation fixture: **100/100 passes on each tree**, current and
  clean pristine `231dedb55287ab6e40fd103634a024e4d9d1baeb`, identical guarded
  `-race -count=100 -parallel=2 -timeout=90s` conditions. Original Codex continuous
  messages: **30/30 passes on each tree** under matching guarded conditions.
  Logs: `/tmp/gitsec-resolve-{pi,codex}-{current,baseline}-before.log`. These passes
  did not retroactively reproduce or explain the old broad-run failures.
- Pi's unchanged baseline selected differently when both a cancellation-generated
  Result and upstream Done were ready. The new deterministic both-ready regression
  fails on current and pristine source, with the same `aborted`/`execution cancelled`
  assertion; a Go overlay adds identical test bytes without editing the pristine
  tree (`/tmp/gitsec-resolve-pi-regression-{current,baseline}-before.log`). The fix
  captures upstream cancellation before transcript drain in the Result branch and
  applies the same classification as Done, preserving authoritative provider
  outcomes and watchdog priority. Twenty focused top-level cases repeated ten
  times pass in 13.061s (`/tmp/gitsec-resolve-pi-after.log`).
- Cursor's original pristine fixture freshly reproduced the exact late-descendant
  group-still-active assertion once in three repeats; five other matching cases
  passed (`/tmp/gitsec-independent-cleanup-baseline.log`). Current matched six
  passed. An algorithm-preserving extraction then demonstrates the stale
  pre-SIGKILL snapshot defect deterministically; the surviving-group deadline
  control remains a failure. The fix signals the identity-verified retained group
  before observing liveness, preserving the one-second deadline and Linux pidfd/
  Darwin birth-identity signalling. Deterministic controls pass 20/20; real capture,
  late-child, leader-exit and foreign/changed-identity controls pass 12/12 in 8.209s.
  Logs: `/tmp/gitsec-independent-cursor-{regression-red,regression-green,real-green}.log`.
  The old failed scan's exact phase remains unavailable; this is a demonstrated
  defect and regression fix, not a claim of recovered historical telemetry.
- The old Codex log records 119ms since tool-result progress against 90ms inactivity,
  then records completion after timeout. Production Codex source is unchanged.
  The positive fixture's 50ms sleeps did not bound scheduler wall time. Progress
  gaps and inactivity windows are scaled together by ten; total work still exceeds
  a window. The test additionally requires observed running-to-finished span above
  the window, text and tool-result events, completion and expected output.
  Negative timeout tests retain their original bounds. An intermediate frozen
  focus at 6d764df3 also hit the adjacent legacy fixture's 80ms first-progress limit
  after 92ms; that failed run remains in `/tmp/gitsec-resolve-final-focus.log`.
  Legacy and delta positive fixtures received the same ratio-preserving scaling.
  Final paired verification of the same fixture bytes on current and pristine
  production source (test-only Go overlay) passes 35/35 each, no skips, 19.914s and
  19.828s (`/tmp/gitsec-resolve-final-codex-{current,baseline}.log`).
- Proper adoption is part of a PID-absence fixture's environment. Three unchanged
  Claude/Codex cancellation cases repeated three times passed on both current and
  pristine trees under a local adopting parent, with final ECHILD and no forced
  cleanup: 9/9 each, 2.221s/2.187s
  (`/tmp/gitsec-resolve-adopting-{current,baseline}.log`). No PID-absence assertion
  was relaxed to accept a zombie. The optional committed helper scopes subreaping
  to its command, revalidates parents before stable-pidfd signalling and bounds
  command/cleanup lifetimes. Its five controls cover orphan reaping while the test
  still runs, detached live-leak failure, foreign-process protection, interruption,
  timeout/nonzero status and delayed final ECHILD. An initial positive fixture
  incorrectly kept its child's parent alive; it was corrected to a three-generation
  adoption model. Initial evidence remains, final controls pass 3.928s
  (`/tmp/gitsec-resolve-final-helper.log`). The helper reports and fails any forced
  post-test cleanup; it does not certify production isolation.
- A warranted full agent run at 949cc9f3 reduced 28 failures to five previously
  baseline-recorded Pi home-directory fixture errors; all cancellation/cleanup and
  Codex progress cases passed (`/tmp/gitsec-resolve-949-agent-full.log`). Four Pi
  stream tests and the cold resume-refusal case had requested the real home default.
  An unexported per-backend allocator now lets those fixtures choose a private
  temporary cold-session file, without changing HOME, global permissions or an
  empty ResumeSessionID. Production nil allocation keeps the original default;
  explicit resumed paths still bypass allocation and retain file locking. The
  five targets repeated ten times pass 1.290s, no skips, final ECHILD and no forced
  cleanup (`/tmp/gitsec-resolve-pi-storage-focused.log`).

### Final candidate verification

All final runtime source is frozen at `dafa551b94a272d7f62cad54c082d850a71bd270`.
Final commits are `8a661e497` (daemon cancellation), `f85ee887a` (Cursor ordering),
`cf69f6fcc`/`949cc9f32` (measured positive progress fixtures), `6d764df39` (optional
bounded test adopter) and `dafa551b9` (private cold Pi fixtures). The final handoff
commit changes documentation/instructions only.

| Final check | Result and local evidence |
| --- | --- |
| `GOFLAGS=-p=1 make env-exec ARGS='-- python3 scripts/test-process-reaper.py --timeout 300 -- bash scripts/test-go.sh --race --only agent'` | Complete agent package PASS 48.438s. Adopter reaped 83 descendants, final ECHILD, `cleanup_after_test=none`. `/tmp/gitsec-resolve-final-agent-full.log` |
| `GOFLAGS=-p=1 make env-exec ARGS='-- python3 scripts/test-process-reaper.py --timeout 1200 -- make test'` | Completed regular half: 69 package passes, 16 no-test packages, four top-level failures in two packages. Adopter reaped 630 descendants, final ECHILD, no forced cleanup. Regular failures prevent automatic agent half; its separate complete PASS is above. `/tmp/gitsec-resolve-final-full-go.log` |
| Changed/relevant backend paths | Handler PASS 159.309s, r2dgit PASS 18.796s, service PASS 30.967s, daemon PASS 15.654s, process-tree PASS 1.675s, repocache PASS 8.272s, server PASS 10.988s; auth, middleware, migrations and protected-agent PASS cached |
| Final scoped vet | PASS via guarded `go vet ./internal/daemon ./pkg/agent ./cmd/protected-agent`. `/tmp/gitsec-resolve-dafa-vet.log` |
| Final Darwin/arm64 build | PASS with `GOOS=darwin GOARCH=arm64 CGO_ENABLED=0` for daemon, agent, handler and server. `/tmp/gitsec-resolve-dafa-darwin.log` |
| UI and helper controls | JavaScript syntax PASS; seven UI cases PASS, zero skips (`/tmp/gitsec-resolve-final-ui.log`). Five adopting-parent controls PASS 3.928s (`/tmp/gitsec-resolve-final-helper.log`). These source bytes are unchanged in the final candidate |
| Focused immutable-source controls | At 6d764df3: 100 daemon top-level passes, 54 agent passes/one legacy timing failure and 15 command passes, no skips. Final revised Codex fixtures pass 35/35 on each production-source tree. Private Pi fixtures pass 50/50 plus 20 subcases. Earlier focused failure is retained, not erased by later passes |
| Documentation/instructions | 55 local Markdown targets resolve; `git diff --check` PASS before the final documentation commit |

The four remaining regular assertions are the three
`TestPrepareCursorMcpConfig{ManagedEmptySet,SeedsExplicitAuthSource,WritesProjectConfigAndApprovals}`
fixtures (`managed cursor mcp_config would overwrite existing .cursor/mcp.json`)
and `TestLocalStorageUploadsAreWorldReadable` (`buffered mode = 600, want 0644`).
All four assertion bodies exactly match the recorded pristine-baseline evidence
in `/tmp/gitsec-independent-s456-baseline-regular.log` and
`/tmp/gitsec-recovered-baseline-nondb.log`; comparison is recorded in
`/tmp/gitsec-resolve-final-baseline-assertions.log`. They are existing ordinary
MCP/public-file checks outside the selected protected contract; they were not
weakened or repaired by changing permissions. Full repository `make test` is still
nonzero. There is no unmatched changed-path test failure in the final candidate.
The prior source-context object cleanup-budget assertion passes in this final
service suite; its earlier baseline failures remain historical evidence and its
cause is not claimed fixed.

The final serialized DB slot remained root-only. All source stayed frozen during
final broad checks; only documentation was edited. Temporary logs are local
supporting evidence. No real CLI/model/provider, credentials, enrollment, OpenBao,
source upload, push, PR, merge, deployment or host setting change occurred.

### Review and operational boundary

The independent reviewer accepted Pi classification, measured Codex fixtures,
private Pi cold-session allocation and the optional adopter after an ECHILD-order
correction with a deterministic regression. Root independently reviewed the
reviewer's Cursor implementation and retained identity/foreign-process controls.
Scoped vet and Darwin compilation also cover the Cursor change. No review finding
remains open within this corrected local delta.

The standalone production reaper algorithm is unchanged. At6d764df3 the actual
observed-adoption fixture and bounded nonblocking reap controls pass 15/15, no skips;
measured one-second drains include 352–473ms, final ECHILD and PID absence. Earlier
9/10 failures lack sufficient phase telemetry to assert a historical cause.
The executor observation of 15,987 visible PIDs, including 15,959 zombies, also
places the 16,384-entry scan limit in a concrete environment context, without
proving it caused an old failure. The dedicated runtime must supply a private,
bounded visible PID namespace and verified whole-container cleanup.

The exact browser launch abort, sandbox boundary and seven safe non-browser UI
controls are recorded in the [candidate guide](protected-local-candidate.md#browser-boundary).
There was no automatic-approval rejection to retry. The accepted next operational
steps are concrete: fixed image/VM and effective isolation acceptance, explicit
serving configuration and trusted channel selection, live per-user custody/provider
proofs, independent-domain restore/transition drills and a working sandboxed
browser environment. The selected local software contract is implemented; no
production enablement is implied by synthetic acceptance.
