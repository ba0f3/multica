# Local protected authentication and serving

Source/test checkpoint: `dafa551b94a272d7f62cad54c082d850a71bd270`.
This implements a concrete loopback-only server, with synthetic end-to-end
verification. Ordinary production main still supplies no protected configuration;
there is no environment enablement switch or deployed listener.

## Composition and ownership

[NewLocalProtectedServer](../../server/internal/handler/protected_server_linux.go)
accepts an explicit source service, independent restore guard, protected deployment
config, authentication delivery and two already-opened loopback TCP listeners.
The control origin and broker URL must exactly match their respective listener
addresses. TLS1.3, fixed server certificate/key/hostname/validity and broker
`RequireAndVerifyClientCert` with explicit client CAs are required. Dynamic TLS
configuration/certificate callbacks are refused; serving disables session tickets.
Invalid configuration closes both listeners before constructing a worker. Nil
configuration remains disabled and touches no listeners, credentials or engine.

The constructor installs the historical-source policy before protected recovery or
credential maintenance, then composes the existing protected-only worker. It
constructs a minimal handler directly, without the legacy router, background
relays, mail service, ordinary task scheduler, native sessions, analytics or CDN
signer. `Serve(ctx)` owns the two TLS servers and protected scheduler; first error
or cancellation closes authentication, request contexts, listeners and worker,
with a bounded join. Close is idempotent and a closed server cannot restart.
The supplied source DB/restore verifier and explicit external dependencies remain
the caller's resources. Closing the server never reopens generic historical source.

This is application software, not a placeholder interface: the test drives the
actual listeners, HTTP/TLS cookie exchanges, mTLS broker, durable human admission,
compiled entrypoint/provider and restricted output. The Engine, custody, email,
model and Git upstream dependencies remain synthetic. No production main or CLI
selects the constructor automatically. Operator image/identity/host/network/live
provider acceptance and reviewed deployment selection remain outside local scope.

## Fresh human authentication

[ProtectedControlAuth](../../server/internal/middleware/protected_control_auth.go)
mounts only these authentication operations:

| Method and path | Behavior |
| --- | --- |
| POST `/auth/code` | Bounded existing-account email challenge; generic 202 receipt for known and unknown accounts |
| POST `/auth/session` | Consume browser-bound six-digit proof and issue an opaque protected cookie |
| GET `/auth/session` | Current user ID, original authentication time, expiry and CSRF value only |
| DELETE `/auth/session` | Erase the local credential before witnessed logout; expire its cookie |

Authentication requires actual TLS, the exact configured Host and exact Origin on
mutations; forwarded identity/proxy headers supply no authority. The browser binds
a challenge with a separate Secure/HttpOnly/SameSite=Strict host cookie. Codes
expire after three minutes, allow five attempts, and are consumed before an
uncertain transaction can be retried. A witnessed event CAS supplies durable
single-use consumption. Existing user ID and exact current email are checked again;
there is no signup, dev-code override, PAT/task/CLI/JWT exchange or owner fallback.

Challenges and session credentials exist only in a bounded per-process registry.
Only hashes and necessary identity/time state reside there; DB events contain
non-secret UUIDs and actions. The registry allows 1000 pending challenges and 1000
sessions, with 10 requests/IP, 3/email and 1000 globally per 15-minute window and a
bounded rate map. Process restart forgets all credentials; DB events cannot
recreate them. Sessions use a separate `__Host-multica_control` Secure/HttpOnly/
SameSite=Strict cookie, expire after 15 minutes, and never slide original auth time.
Business writes retain the existing recent-human requirement. The UI keeps CSRF
only in memory and never stores bearer credentials or source in browser storage.

[SMTPCodeDelivery](../../server/internal/auth/code_delivery.go) is the concrete,
explicitly configured authentication-only sender. It validates configuration
without a network operation, requires verified implicit TLS1.3, bounds cancellation
and sends a fixed sign-in message containing only a validated mailbox and six
server-generated digits. It cannot take a caller's narrative, subject, template,
attachment or arbitrary source body. This narrow code channel does not release the
historical-source hold on the ordinary mail/invitation transport. No real SMTP
service was contacted; its tests use a synthetic local TLS SMTP peer.

## Current authority and restore

Every authenticated request rechecks the ephemeral registry and
[CheckControlSession](../../server/internal/r2dgit/control_session.go). This fifth
audited pure DB reader validates the current account email and active session
event with the existing repeatable-read/witness finalization fence. It does not
advance the checkpoint for ordinary GETs. Registry state is checked again after
DB validation. Actual response writes and flushes recheck the session in bounded
16KiB chunks; source delivery independently retains every origin, ancestor,
reader-key and provider-rights check.

Restore reconciliation invalidates both pending challenge and authenticated session
events. A pre-restore unused code cannot become fresh authority, and an old
registry entry cannot survive reconciliation. A new code/login after reconciliation
creates no project grant, governance, execution approval, key activation,
classification or runtime acceptance. These remain separate current prerequisites.
The authentication tests include a deterministic snapshot-vs-durable-logout race,
concurrent proof replay, email change, expiry and response closure after one chunk.

## Control surface and verification limits

The fixed page at `/` and script at `/auth/script` support login/logout, public Git
identity management and explicit consent, read-run admission/status/revocation,
restricted output reading and existing project-grant management. IDs make scope
explicit; no stored titles, profiles, histories or search data are bootstrapped.
The page uses external same-origin script under a restrictive CSP, renders source
with `textContent`, clears displayed content on logout/expiry and reports uncertain
server sign-out. A monotonic session generation rejects late headers, bodies,
errors and DOM updates from a prior session. Authentication cookie changes are
single-flight. All native form fallbacks use POST, so script-load failure cannot
put an email/code in a URL. All generic legacy APIs, uploads, search, WebSocket, login,
credential exchange and readerless capabilities are absent/default 404. Human
cookies never authenticate the separate mTLS broker listener.

The canonical integration is
[TestR2DGitLocalProtectedServingFreshLoginToCompiledOutput](../../server/internal/handler/protected_server_linux_test.go).
It verifies A success, same-agent B denial, cross-workspace admission, no legacy/CDN
credential issuance, invalid TLS refusal before worker construction, mTLS refusal
without a workload certificate and shutdown. Authentication regression fixtures are
[beside it](../../server/internal/handler/protected_control_auth_test.go). Seven
[isolated UI behavior tests](../../server/internal/handler/protected_control_ui_test.cjs)
exercise source-as-text, CSRF, startup ordering, retry, expiry, uncertain logout,
late A responses across B login, stale initial metadata and native POST fallback.
The Go package runs them when Node is available. Restore fixtures invalidate the
synthetic instance, so DB packages must run serially in the managed environment.

A sandbox-enabled Chromium smoke could not launch because this executor's SUID
sandbox helper is misconfigured. No host permission or browser-sandbox workaround
was used. HTTP/TLS composition and isolated UI logic are tested; browser-rendered
acceptance remains an environment blocker. The full backend/agent results, exact
logs, independent review and remaining process-cleanup uncertainty are recorded in
[the review report](git-security-local-review.md). Live custody/enrollment, real
provider/ACL-change, external key/CDN reconciliation, independent-domain restore
and dedicated VM/image/kernel/network acceptance remain unperformed.
