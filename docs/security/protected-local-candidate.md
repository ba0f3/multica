# Protected local source candidate

Candidate: `dafa551b94a272d7f62cad54c082d850a71bd270` on
`feat/git-security-local`. All commits are local. Ordinary production main still
passes nil protected configuration. There is no environment enablement switch.

## Supported contract

The explicit [local server](protected-local-serving.md) composes fresh human OTP
authentication, opaque short-lived sessions, fixed account/project/run controls,
separate loopback TLS and mTLS listeners and the protected worker lifecycle.
Its integration fixture drives actual HTTP/TLS login, durable admission, the
compiled entrypoint/provider, broker and restricted output with synthetic external
dependencies. A succeeds; B sharing A's admin-owned agent is denied. Team remains
Workspace; explicit cross-workspace project grants remain authoritative.

The selected execution contract supports bounded text repositories, a direct
Responses adapter through the per-user gateway, pinned Git reads, existing
unprotected GitHub feature-ref writes, isolated children/fresh attempts and
current-reader restricted output. Unsupported native tools/MCP/resume, large or
binary repositories, LFS/submodules, signing, PR/API operations, new/protected
GitHub refs and Gitea write policy fail closed. These are explicit feature limits.

This continuation fixes daemon cancellation/result selection and Cursor cleanup
ordering. Codex production timeout code is unchanged. Positive progress fixtures
retain their timing ratios with a larger subprocess scheduling margin; the
continuous-message fixture also asserts observed progress over more than one
inactivity window. Negative timeout tests remain active. The [review report](git-security-local-review.md) retains the old
failed runs and matched-baseline evidence.

## Reproduce locally

Use the repository-managed environment and synthetic fixtures. Serialize DB
packages because restore fixtures invalidate the synthetic instance. On Linux
executors whose PID1 does not reap orphaned test processes, the optional adopting
parent gives fixtures an owned reaper without changing the host:

```sh
python3 scripts/test-process-reaper_test.py -v
GOFLAGS=-p=1 make env-exec ARGS='-- python3 scripts/test-process-reaper.py -- make test'
make env-exec ARGS='-- python3 scripts/test-process-reaper.py -- bash scripts/test-go.sh --race --only agent'
```

The helper requires Linux, Python pidfd support and per-process subreaper support.
It waits only for its command and adopted descendants. It bounds command lifetime
and cleanup, revalidates ownership before signalling stable pidfds, and reports
final ECHILD. A surviving descendant requiring post-test cleanup makes the command
fail even if its tests returned zero. Existing strict PID-absence assertions are
preserved. Foreign-process, detached-child, interruption, deadline and final-ECHILD
controls are included. This helper supplies a test parent, not runtime isolation.

At the frozen candidate:

| Check | Result |
| --- | --- |
| Complete guarded agent race suite | PASS 48.438s; 83 adopted descendants reaped, final ECHILD, no forced cleanup |
| Serialized backend race check | 69 package passes; handler 159.309s, core 18.796s, service 30.967s, daemon 15.654s, process-tree 1.675s and Git worktree 8.272s PASS |
| Repository-wide residual checks | Four failures in two packages: three ordinary Cursor MCP configuration fixtures and local-storage public-file mode. Their assertion bodies match recorded pristine-baseline logs; full `make test` remains nonzero |
| Focused regressions and review | Both-ready Pi regression fails old/current and pristine source before the fix; corrected cancellation/provider/watchdog controls pass. Cursor ownership/deadline controls, measured Codex progress/negative timeout controls and private cold-session fixtures pass. Independent review accepted the delta |
| Static/UI/helper checks | Scoped vet and Darwin/arm64 build PASS; seven Node UI cases and five Linux adopter fault controls PASS |

The complete agent run and backend wrapper both finish at ECHILD without forced
post-test cleanup (83 and 630 adopted descendants respectively). The four repository
baseline failures are separate from the selected protected execution contract;
no unmatched changed-path test failure remains. This is a reviewable source
candidate with explicit feature limits, not a claim that the repository-wide
check is wholly green. Exact commands, source checkpoints, logs and assertion
comparisons are in the latest [review evidence](git-security-local-review.md).

## Browser boundary

The blocked action was Playwright `browserType.launch` of `/usr/bin/chromium`
with the Chromium sandbox enabled. The browser aborted with SIGABRT before a page
rendered: its `/usr/lib/chromium/chrome-sandbox` SUID helper was not correctly
configured. Crashpad also reported a missing database argument. This was the
browser's sandbox boundary, not an automatic approval-review rejection. The full
launch/error log is `/tmp/gitsec-control-browser-sandbox.log`.

No sandbox-disable flag, chmod/chown, user-namespace, kernel or host-policy change
was attempted. Seven isolated Node UI cases cover source-as-text, in-memory CSRF,
login ordering/retry/expiry, uncertain logout, late A responses after B login,
stale session metadata and native POST fallback. Actual TLS integration verifies
server-side cookies and authorization. Real rendering, browser-enforced cookie/CSP
behavior, layout and accessibility still need an accepted browser environment.

## Deployment prerequisites for this contract

| Prerequisite | Concrete acceptance needed |
| --- | --- |
| Trusted worker boundary | Accept the dedicated worker VM and fixed digest-pinned entrypoint image; accepted nonroot container UID/GID and verified host/user-namespace ownership, private filesystem/cache, PID namespace, cgroup limits, capabilities, seccomp/AppArmor and network allowlist. Verify effective settings and whole-container removal. |
| Child cleanup | Run a genuine adopting/reaping supervisor and prove observed adoption, bounded termination, final ECHILD and PID absence. Keep the visible PID namespace within the software's 16,384-entry scan and 1,024-owned-child limits. Current synthetic tests do not certify host PID1 or the old failed scan phase. |
| Explicit serving selection | A reviewed application entrypoint must supply the explicit constructor configuration: two owned loopback listeners, matching control origin/broker URL, fixed valid TLS identity, broker client CA and owned shutdown. Accept the trusted ingress/workload channel path without forwarded identity or legacy authentication fallbacks. Ordinary main remains disabled. |
| Live identity and custody | Supply per-user custody/signing and provider enrollment, verified current account/key/ACL proofs, explicit SMTP authentication delivery and reviewed execution approvals. Perform real ACL-change and key rotation/revocation checks. No live material was created locally. |
| Restore and transition | Place the witness in an independent backup/trust domain; accept rollback refusal, quarantine and a restore/reconciliation drill. Quiesce historical paths and reconcile prior provider keys, CDN authority and native/MCP state. Existing guards cannot recall delivered bytes. |
| Browser and operational review | Repeat rendered-browser acceptance in a working sandbox, accept configuration/telemetry and review rollout/rollback procedures before any production enablement. |

The constructor and selected software paths are implemented. Production selection,
live credentials/providers, image/host acceptance and operational drills require a
separate authorized deployment step. No source upload, push, PR, merge, deployment,
live enrollment, OpenBao setup, host change, model or paid call occurred.
