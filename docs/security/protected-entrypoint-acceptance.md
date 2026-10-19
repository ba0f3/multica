# Protected workload: finite local acceptance boundary

The latest disabled software boundary is source/test
`dafa551b94a272d7f62cad54c082d850a71bd270`, described in
[the completion matrix](protected-completion-matrix.md) and
[application surface inventory](protected-source-surfaces.md). It includes bounded
Responses model/edit/finalize, child/retry orchestration, historical default-deny,
source union, witnessed restore quarantine/reconciliation and explicit
[local authentication/serving](protected-local-serving.md). Ordinary production
startup passes nil configuration and refuses protected legacy startup. This is
local software evidence, not completed S0–S6 or permission to enable production.

## Complete synthetic workflow

The canonical application tests drive this entire sequence:

1. A recent authenticated human admits a task through the real HTTP router.
   Current execution-workspace membership, invocation rights and the explicit
   project grant are checked. Team remains Workspace; resource-workspace membership
   is not required for an explicit cross-workspace project grant.
2. The trusted application reloads sealed context/grant/attempt identity from DB,
   requires a fresh signed classification of the exact issue/project/repository and
   title/description digest, snapshots that text at prepare time, and obtains synthetic
   signed enrollment. The signature binds issue ID and assignment digest as well
   as policy, channel, certificate, context, grant and expiry. Changed issue/project
   binding, epoch, identity, grant or current rights denies execution.
3. Durable admission and engine journals bracket private claim and launch. A fake
   HTTP Engine implements the actual Engine adapter seam; no container is created.
   The supervisor starts the compiled `cmd/protected-agent` executable as a real
   subprocess. Per-run socket paths and fresh workspace/HOME/tmp are distinct.
4. The executable obtains its bounded assignment over the real UDS/mTLS bridge,
   requests an authenticated HEAD/pack snapshot, validates and checks it out with
   explicit Git into private state, then starts the fixed image-provider executable.
   The application provider transport is synthetic; pinned real local SSH/pack
   transport is independently covered by the broker package tests.
5. The image provider receives only v1 JSON on stdin: assignment, private directory
   and authenticated HEAD. The argv is fixed. The environment contains private
   HOME/tmp and minimal Git/process settings, with no ambient API keys, proxies,
   SSH socket, provider login, control-plane token or reusable native session.
   A real test-created provider subprocess reads its own checkout and returns one
   bounded v1 JSON result. Malformed/extra-scope fields, overflow, nonzero exit and
   timeout deny; stderr is discarded with a bound, never logged as source.
6. The executable stores the result through the exact channel, receives a durable
   restricted-output ID and explicitly acknowledges that receipt. Source audience
   comes from the sealed grant; trusted derived-output composition additionally
   retains all input origins. Provider output cannot choose sources. There is no
   generic result/comment/notification/log fallback or ambiguous-response retry.
7. The standalone command adopts descendants before spawning children and performs
   a bounded final child drain after direct process waits finish. Detached-session
   descendants must disappear on success and revocation; cleanup uncertainty forces
   nonzero exit. The supervisor observes canonical exit zero and removes its exact
   fake engine resource/socket state. Private completion rechecks current rights
   and atomically settles existing task receipts and audit. Otherwise the run fails
   privately. Restart refuses adoption and retains evidence on DB uncertainty.
8. Actual restricted-output HTTP reads require the reader's own current key/provider
   proof and all existing source/originator/ancestor rights. A/B users share the same
   admin-owned agent but receive different assignments, repositories, state and
   results; cross-project reads are denied.

Existing integration matrices additionally cover forged identities/URLs/headers,
read-channel pushes, output/acknowledgement ambiguity, revocation/outage, root and
lineage checks, cleanup/recovery, current-reader revocation, HTTP1/2 deadlines and
concurrent child admission. Assignment delivery is audited with accepted-byte
accounting; title/description edits after prepare do not change its snapshot.

These tests validate software composition and actual local subprocesses. They do
not prove namespaces, UID mappings, egress restrictions, kernel isolation, cgroup
limits, PID1 behavior inside an actual container, or production identities.

## Image entrypoint contract

Build the Linux command from `server/` with the managed Go toolchain:

```sh
CGO_ENABLED=0 go build -trimpath -o agent ./cmd/protected-agent
```

The accepted image must install it as `/opt/multica/agent`, install a reviewed v1
provider adapter at `/opt/multica/provider`, and include Git and `/usr/bin/prlimit`.
Copy [the example config](../../server/cmd/protected-agent/runtime.example.json)
to `/opt/multica/runtime.json` in the immutable image. Paths are image/operator
configuration; they are never accepted from a task. The command also accepts an
explicit `--config` path for operator tooling and synthetic tests. That flag grants
no additional broker authority and is not supplied by the task/supervisor.

Workspace, HOME and tmp must start empty, owned by the workload UID, mode0700,
and distinct/non-nested. Runtime state is never resumed. The45s maximum entrypoint
budget is additionally shortened by earlier grant/channel expiry and current-rights
cancellation. Provider process groups are cancelled on timeout/signal. Only the
standalone command enables the per-process child-subreaper flag; the shared
application does not change its reaping behavior. Final cleanup streams bounded
`/proc` batches, checks parent IDs before and after opening pidfds, signals only
through those stable handles, and reaps until `ECHILD` or a1s deadline. Continuous
exit/EINTR streams cannot bypass that deadline. Whole-container cleanup remains
mandatory; no machine setting or weaker PID-signal compatibility path is used.
Failures print only `protected_workload_unavailable` to stderr, with nonzero exit.
The engine's logging policy remains `none`.

The selected compiled `cmd/protected-provider` is the bounded JSON/text Responses
adapter through the per-user gateway, using direct HTTP. It is separate from the
server assist SDK and does not invoke native Codex/Claude CLIs or resume sessions.
The repository does not ship an approved deployment image. The example is a
packaging contract, not a runnable production deployment.

## Missing production software

These are code/integration gaps, not credentials waiting to be entered:

| Gap | Current boundary |
| --- | --- |
| Deployment selection and operational acceptance | The explicit loopback-only server now composes fresh human OTP proof, opaque sessions, fixed controls, TLS/mTLS listeners and the protected-only worker, with restore-aware request/chunk checks and owned shutdown. Main still supplies nil configuration and refuses protected legacy startup. Deployment selection/configuration, live acceptance and generic UI remain outside this finite local surface. |
| Additional provider/policy support | The selected direct Responses adapter, per-user gateway, constrained writes, isolated children and fresh retries are implemented synthetically. Native sessions/tools/MCP, large/binary repositories, Gitea write policy, new GitHub branch policy, PR/API, LFS, submodules and signing remain unsupported. |
| Historical transition and external authority | Generic API/WS/export/attachment and delivery sinks enforce denial; trusted output union and exact assignment classification exist. A quiescent transition and external key/CDN inventory are required. Guards cannot recall already delivered/in-flight bodies or old native/MCP state; automatic historical public backfill and hot transition are unsupported. |
| Restore/rollout operation | Independent-domain witness, rollback refusal, all-scope quarantine and fresh governance/execution/key/classification approval exist as trusted service tooling, with no HTTP recovery endpoint. Accepted production operation, independent-domain restore drill and S6 rollout evidence remain missing. Combined rollback of DB and witness is outside the trust boundary. |

Process cleanup uncertainty still denies execution. The standalone reaper and agent
suite have failed in recorded full/parallel runs. Passing isolated repeats do not
establish a cause or certify a fix. The [review report](git-security-local-review.md)
retains exact failure and baseline evidence; the full backend is not green.

## Deployment and real validation prerequisites

Separately from the software gaps, an operator must provision and accept the
dedicated Linux worker VM; user namespace mappings; enforced seccomp/AppArmor;
read-only image and bounded disposable mounts; cgroups; and network/egress policy.
Engine, broker, secret-store and enrollment credentials must remain outside the
workload. Supply the reviewed digest-pinned image, TLS trust material, per-attempt
proxy certificates, actual encrypted custody/provider catalog and live enrollment.

The accepted kernel/profile must permit `PR_SET_CHILD_SUBREAPER`, `wait4`,
`pidfd_open`, `pidfd_send_signal` and read-only process-stat enumeration. The
software uses `/proc/<pid>/stat`; it does not require the optional task `children`
file, which is absent in the local executor. Unsupported/uncertain cleanup denies.

Then perform real positive/negative containment, PID1/reaping, resource, egress,
cleanup, external ACL-change, native provider, restore and rollout acceptance.
Successful fake Engine Inspect or an operator signature from synthetic keys is
not that evidence. No host/security/network changes, privileged container run,
VM provisioning, live enrollment, real model call, publication or deployment is
authorized or performed in this local checkpoint.

Exact commits, independent review and broad-suite failure evidence are recorded
in [the local review report](git-security-local-review.md).
