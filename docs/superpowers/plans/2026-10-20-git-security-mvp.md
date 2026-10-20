# Git Security MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every user a dedicated per-provider SSH Git key (public key only in the UI, private key in encrypted custody) and run each task attempt inside a bubblewrap sandbox whose only Git credential is a per-task SSH-agent socket bound to the human who authorized the run.

**Architecture:** The backend owns credential lifecycle in a new `server/internal/r2dgit` package backed by `r2d_*` side tables and an OpenBao KV v2 custody adapter. The daemon supervisor keeps the private key off the worker by hosting a per-attempt SSH-agent socket that forwards `List`/`Sign` to an authenticated server endpoint. Task execution moves into a hidden `multica internal-task-worker` process launched under `bwrap`, driven by a typed IPC protocol that reuses the existing `agent.Backend` interface.

**Tech Stack:** Go 1.26 (chi, pgx/sqlc), `golang.org/x/crypto/ssh` + `ssh/agent`, bubblewrap (bwrap), React 19 + TanStack Query + zod (packages/core, packages/views).

**Spec:** `docs/security/per-user-git-credentials-plan.md` (PR #95 revision, 2026-10-20) and `docs/security/git-security-agent-handoff.md`. Reuse source: PR #93 head `a0c48fb5483f2f4404a050a60c3aff2e88eadcfb` (credential code only).

## Global Constraints

- Delivery target is the fork `r2d-ai/multica`, branch `main`. Never open a PR against `multica-ai/multica`.
- New tables use the `r2d_*` prefix as side tables. **No foreign keys, no cascading deletes.** Relationships are validated in application code inside a transaction.
- Every migration-created index uses `CREATE [UNIQUE] INDEX CONCURRENTLY` and gets **its own single-statement migration file**. The runner executes migration files outside an explicit transaction.
- Migration numbers are allocated from `900000-999999`; this plan allocates `900100`–`900113`.
- New API responses pass through a zod schema and `parseWithFallback` in `packages/core/api/schema.ts`; malformed-response tests are mandatory.
- Web/desktop shared UI lives in `packages/views/`; schemas, API client and query hooks live in `packages/core/`. No store definitions in `packages/views/`. No server data in Zustand/localStorage.
- Code comments are English. UI copy follows `apps/docs/content/docs/developers/conventions.mdx`; descriptions are omitted by default.
- Go backend tests use `server/internal/testutil` fixtures. Default tests must not resolve or execute user-installed agent CLIs — pass fake or missing executable paths.
- Default tests use synthetic keys, disposable Git/SSH fixtures and fake coding CLIs. Real-agent smoke requires explicit authorization plus the `agentintegration` tag and `MULTICA_RUN_REAL_AGENT_SMOKE=1`.
- Never place a private Git key, secret-store token or host admin credential in a UI response, API DTO, task payload, worker mount, worker environment, inherited file descriptor, IPC payload or log line.
- Missing bwrap, missing namespace support or a failed mount setup **blocks** the task. There is no unsandboxed fallback for a protected run.

## Review Focus

- **A revoked key that is still cached in a signer.** Revoke must stop *new* signing requests and close live connections; removing the socket file alone does not stop an authenticated SSH session. Test: revoke while a sign request is in flight → the request fails and the connection is closed.
- **Two users, one shared agent, one runtime owner.** The key must follow the task's authenticated originator, never the runtime owner or agent owner. Test: task authored by A on an admin-owned runtime signs with A's key.
- **A forged selector in the runner.** The runner must not be able to choose the user, provider or key generation. Test: a worker that sends a different `identity_id` gets its signing request denied.
- **A worker that mutates the signer.** `ADD_IDENTITY`, `REMOVE_IDENTITY` and `LOCK` must be refused. Test: the agent socket replies failure for a mutating request and keeps serving the original key.
- **Secret leakage through a diagnostic.** Any error path that formats a key, a custody token or a signer must be checked by a test that greps the rendered error for key material.

---

## Phase 1 — MVP1 (#86) Keys and UI

### Task 1: Credential core package

**Files:**
- Create: `server/internal/r2dgit/errors.go`
- Create: `server/internal/r2dgit/identity.go`
- Create: `server/internal/r2dgit/custody.go`
- Test: `server/internal/r2dgit/identity_test.go`
- Test: `server/internal/r2dgit/custody_test.go`

**Interfaces:**
- Produces: `r2dgit.ErrUnavailable`, `ErrScope`, `ErrPrincipal`, `ErrIdentity`, `ErrConflict`, `ErrRevoked`.
- Produces: `type KeyState string` with `Provisioning`, `PendingVerification`, `Ready`, `Revoked`.
- Produces: `type PublicIdentity struct { ID, UserID, ProviderID string; Generation uint64; PublicKey, Fingerprint string; State KeyState; AccountID, Login string; VerifiedAt *time.Time; Active, CleanupPending bool; Diagnostic string; ConsentProjectIDs []string }`.
- Produces: `func GenerateKeyMaterial(random io.Reader) (KeyMaterial, error)` where `KeyMaterial` is `struct { PublicKey string; Fingerprint string; Private []byte }` and `func (k KeyMaterial) String() string` returns `"[redacted Git key material]"`.
- Produces: `type KeyCustody interface { Store(ctx context.Context, ref string, material KeyMaterial) (int, error); DestroyAll(ctx context.Context, ref string) error }`.
- Produces: `type SigningCustody interface { WithSigner(ctx context.Context, ref string, fn func(ssh.Signer) error) error }`.
- Produces: `type EncryptedCustody interface { KeyCustody; SigningCustody }`.
- Produces: `func NewBaoCustody(baseURL, mount, token string, client *http.Client) (EncryptedCustody, error)`.

- [ ] **Step 1: Write the failing test for key generation and redaction**

`server/internal/r2dgit/identity_test.go` must assert:

- `GenerateKeyMaterial(bytes.NewReader(make([]byte, 64)))` returns a public key that `ssh.ParseAuthorizedKey` accepts, a fingerprint equal to `ssh.FingerprintSHA256` of that public key, and a non-empty private PEM.
- The public key is Ed25519 (`ssh.KeyAlgoED25519`).
- `KeyMaterial.String()` and `KeyMaterial.GoString()` are exactly `"[redacted Git key material]"` — no key bytes.
- `json.Marshal(KeyMaterial)` produces `{}` (all fields are unexported or tagged `-`).

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd server && go test ./internal/r2dgit/ -run TestGenerateKeyMaterial -v`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Implement `errors.go` and `identity.go`**

`errors.go` defines the six sentinel errors with messages exactly `git_service_unavailable`, `git_scope_denied`, `git_principal_unproven`, `git_identity_unverified`, `git_identity_conflict`, `git_grant_revoked`.

`identity.go` implements `GenerateKeyMaterial` with `ed25519.GenerateKey(random)`, `ssh.NewPublicKey`, `ssh.MarshalAuthorizedKey`, `ssh.FingerprintSHA256` and `ssh.MarshalPrivateKey` + `pem.EncodeToMemory`. It clears the raw private bytes and the PEM block bytes with `clear()` after use. It must not log or format the private bytes.

- [ ] **Step 4: Implement `custody.go`**

`NewBaoCustody` validates: `baseURL` parses as `https` with a host, no userinfo, no query, no fragment, path empty or `/`; `mount` matches `^[A-Za-z0-9_-]{1,128}$`; `token` non-empty; `client` non-nil. It copies the client and forces `CheckRedirect` to `http.ErrUseLastResponse` so a custody token is never forwarded to a redirected host.

`Store` writes to `/v1/{mount}/data/{ref}` with `options.cas = 0` (never overwrite an existing generation) and base64-encodes the private key. `DestroyAll` reads `/v1/{mount}/metadata/{ref}`, collects every version that is not already destroyed, and POSTs them to `/v1/{mount}/destroy/{ref}` — hard destruction, not soft delete.

`WithSigner` GETs `/v1/{mount}/data/{ref}`, base64-decodes the private key, parses it with `ssh.ParsePrivateKey`, rejects any key type other than Ed25519, and invokes `fn(signer)` while the decoded bytes are alive.

- [ ] **Step 5: Write the failing test for the custody adapter**

`server/internal/r2dgit/custody_test.go` must use an `httptest.NewTLSServer` and assert:

- A redirect from the custody server is not followed: the request that would have carried the token never reaches the redirect target, and the call returns `ErrUnavailable`.
- `Store` sends `options.cas = 0`.
- `DestroyAll` destroys every non-destroyed version and returns `ErrUnavailable` when the metadata has no versions.
- `WithSigner` rejects a non-Ed25519 stored key with `ErrIdentity`.

- [ ] **Step 6: Run the test to verify it fails, then implement, then verify it passes**

Run: `cd server && go test ./internal/r2dgit/ -v`
Expected: FAIL then PASS.

- [ ] **Step 7: Add the dependency**

Run: `cd server && go get golang.org/x/crypto@v0.55.0`
Expected: `golang.org/x/crypto v0.55.0` added to `server/go.mod` as a direct dependency.

- [ ] **Step 8: Commit**

```bash
git add server/internal/r2dgit server/go.mod server/go.sum
git commit -m "feat(git): add credential core with encrypted custody adapter"
```

### Task 2: Schema and queries

**Files:**
- Create: `server/migrations/900100_r2d_git_provider.up.sql`, `900100_r2d_git_provider.down.sql`
- Create: `server/migrations/900101_r2d_git_identity.up.sql`, `900101_r2d_git_identity.down.sql`
- Create: `server/migrations/900102_r2d_git_key.up.sql`, `900102_r2d_git_key.down.sql`
- Create: `server/migrations/900103_r2d_git_key_job.up.sql`, `900103_r2d_git_key_job.down.sql`
- Create: `server/migrations/900104_r2d_git_provider_id_index.up.sql` (+ `.down.sql`)
- Create: `server/migrations/900105_r2d_git_identity_user_provider_index.up.sql` (+ `.down.sql`)
- Create: `server/migrations/900106_r2d_git_key_generation_index.up.sql` (+ `.down.sql`)
- Create: `server/migrations/900107_r2d_git_key_job_idempotency_index.up.sql` (+ `.down.sql`)
- Create: `server/pkg/db/queries/r2d_git.sql`
- Regenerate: `server/pkg/db/generated/`

**Interfaces:**
- Produces tables: `r2d_git_provider`, `r2d_git_identity`, `r2d_git_key`, `r2d_git_key_job` (exact columns below).
- Produces sqlc queries: `ListR2DGitProviders`, `GetR2DGitProvider`, `GetR2DGitIdentityForUser`, `ListR2DGitKeysForUser`, `GetR2DGitKey`, `CreateR2DGitIdentity`, `CreateR2DGitKey`, `UpdateR2DGitKeyState`, `CreateR2DGitKeyJob`, `GetR2DGitKeyJobByIdempotencyKey`, `UpdateR2DGitKeyJobState`, `RevokeR2DGitIdentity`.

- [ ] **Step 1: Write the migration files**

`r2d_git_provider`: `id uuid NOT NULL PRIMARY KEY`, `label text NOT NULL`, `kind text NOT NULL CHECK (kind IN ('github','gitea'))`, `host text NOT NULL`, `port integer NOT NULL DEFAULT 22 CHECK (port > 0 AND port < 65536)`, `host_pins jsonb NOT NULL DEFAULT '[]'`, `enabled boolean NOT NULL DEFAULT false`, `created_at timestamptz NOT NULL DEFAULT now()`.

`r2d_git_identity`: `id uuid NOT NULL PRIMARY KEY`, `user_id uuid NOT NULL`, `provider_id uuid NOT NULL`, `active_generation bigint NOT NULL DEFAULT 0`, `epoch bigint NOT NULL DEFAULT 1`, `revoked boolean NOT NULL DEFAULT false`, `created_at timestamptz NOT NULL DEFAULT now()`.

`r2d_git_key`: `identity_id uuid NOT NULL`, `generation bigint NOT NULL CHECK (generation > 0)`, `public_key text NOT NULL DEFAULT ''`, `fingerprint text NOT NULL DEFAULT ''`, `internal_secret_ref text NOT NULL`, `state text NOT NULL CHECK (state IN ('provisioning','pending_verification','ready','revoked'))`, `account_id text NOT NULL DEFAULT ''`, `login text NOT NULL DEFAULT ''`, `verified_at timestamptz`, `cleanup_pending boolean NOT NULL DEFAULT false`, `diagnostic text NOT NULL DEFAULT ''`, `consent_project_ids jsonb NOT NULL DEFAULT '[]'`, `created_at timestamptz NOT NULL DEFAULT now()`, `PRIMARY KEY (identity_id, generation)`.

`r2d_git_key_job`: `id uuid NOT NULL PRIMARY KEY`, `user_id uuid NOT NULL`, `identity_id uuid NOT NULL`, `generation bigint NOT NULL`, `kind text NOT NULL CHECK (kind IN ('provision','destroy'))`, `idempotency_key text NOT NULL`, `state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','done','error'))`, `last_error text NOT NULL DEFAULT ''`, `created_at timestamptz NOT NULL DEFAULT now()`, `updated_at timestamptz NOT NULL DEFAULT now()`.

No `REFERENCES` clause in any table.

Each index file contains exactly one statement:
`900104`: `CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS r2d_git_provider_id_idx ON r2d_git_provider (id);`
`900105`: `CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS r2d_git_identity_user_provider_idx ON r2d_git_identity (user_id, provider_id);`
`900106`: `CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS r2d_git_key_generation_idx ON r2d_git_key (identity_id, generation);`
`900107`: `CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS r2d_git_key_job_idempotency_idx ON r2d_git_key_job (idempotency_key);`

Each `.down.sql` drops the object it created.

- [ ] **Step 2: Verify the migration runner accepts the files**

Run: `make migrate-up` against the managed environment, then `make status`.
Expected: the four tables and four indexes exist and the migration table records the eight new versions.

- [ ] **Step 3: Write the sqlc queries**

`server/pkg/db/queries/r2d_git.sql` holds the named queries listed in Interfaces. `GetR2DGitIdentityForUser` filters on `user_id` and takes the identity id; `ListR2DGitKeysForUser` joins identity to key and orders by identity then generation descending.

- [ ] **Step 4: Regenerate sqlc**

Run: `make sqlc`
Expected: `server/pkg/db/generated/r2d_git.sql.go` and updated `models.go` appear; `git diff --stat` shows only generated files changed.

- [ ] **Step 5: Commit**

```bash
git add server/migrations server/pkg/db/queries/r2d_git.sql server/pkg/db/generated
git commit -m "feat(git): add r2d_git credential side tables and queries"
```

### Task 3: Credential service

**Files:**
- Create: `server/internal/r2dgit/service.go`
- Create: `server/internal/r2dgit/verify.go`
- Test: `server/internal/r2dgit/service_test.go`
- Test: `server/internal/r2dgit/verify_test.go`

**Interfaces:**
- Produces: `type Provider struct { ID, Label, Kind, Host string; Port int; HostPins []string }`.
- Produces: `type IdentityProfile struct { ID, UserID, ProviderID string; Generation uint64; PublicKey, Fingerprint string; State KeyState; AccountID, Login string; VerifiedAt *time.Time; Active, CleanupPending bool; Diagnostic string }`.
- Produces: `type Profile struct { Providers []Provider; Identities []IdentityProfile }`.
- Produces: `type Service struct { ... }` with `NewService(q *db.Queries, custody EncryptedCustody, verifier Verifier) *Service`.
- Produces: `func (s *Service) Profile(ctx context.Context, userID string) (Profile, error)`.
- Produces: `func (s *Service) Generate(ctx context.Context, userID, providerID, requestID string, consentProjectIDs []string) (IdentityProfile, error)`.
- Produces: `func (s *Service) Verify(ctx context.Context, userID, identityID string, generation uint64) (IdentityProfile, error)`.
- Produces: `func (s *Service) Revoke(ctx context.Context, userID, identityID string) error`.
- Produces: `type Verifier interface { Verify(ctx context.Context, provider Provider, secretRef string, generation uint64) (login string, err error) }`.

- [ ] **Step 1: Write the failing service tests**

`server/internal/r2dgit/service_test.go` uses a fake custody and a fake verifier. Assert:

- `Generate` for a user creates one identity + one key in state `pending_verification`, stores the private key in custody exactly once, and returns the public key and fingerprint. The returned profile never contains the private key.
- `Generate` with a `requestID` that already produced a job returns the existing identity instead of creating a second key.
- `Profile` for user A never returns an identity owned by user B.
- `Verify` on a `pending_verification` key moves it to `ready` and stores the returned login. `Verify` on a `revoked` key returns `ErrRevoked`.
- `Verify` with a mismatched `userID` returns `ErrScope`.
- `Revoke` marks the identity revoked, marks every generation of that identity revoked, and enqueues a destroy job. A second `Revoke` is a no-op, not an error.
- The fake custody records that `DestroyAll` was called for the revoked generation's secret ref.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd server && go test ./internal/r2dgit/ -run TestService -v`
Expected: FAIL — `Service` is undefined.

- [ ] **Step 3: Implement `service.go`**

`Generate` flow: load the enabled provider by id (404 when unknown or disabled), resolve or create the identity row for `(user_id, provider_id)`, allocate the next generation as `active_generation + 1`, generate key material, store it in custody under secret ref `r2d-git/{identityID}/{generation}`, insert the key row in state `pending_verification`, and record a `provision` job keyed by `requestID`. If custody storage fails, no key row is written.

`Verify` flow: load the identity for the user, load the key row, refuse when the identity is revoked, refuse when the generation is not the identity's active generation, call the verifier with the provider's pinned host keys, and on success set `state='ready'`, `login`, `account_id`, `verified_at`.

`Revoke` flow: in one transaction set `revoked=true` on the identity and `state='revoked'`, `cleanup_pending=true` on every key row of that identity, and insert a `destroy` job per generation. Custody cleanup runs after the transaction and is retried by the job; the local revoke takes effect even when custody is unreachable.

- [ ] **Step 4: Implement `verify.go`**

`Verify` opens an SSH connection to `provider.Host:provider.Port` with `golang.org/x/crypto/ssh`, `User: "git"`, `HostKeyCallback` restricted to the provider's `host_pins` fingerprints, and `Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}` where the signer comes from `custody.WithSigner`. It runs no command; it reads the provider's authentication banner from the session's stderr/stdout and parses it:

- GitHub: the banner matches `^Hi ([A-Za-z0-9][A-Za-z0-9-]{0,38})! You've successfully authenticated, but GitHub does not provide shell access\.$` and the SSH exit status is `1`.
- Gitea: the banner matches `^Hi there, ([A-Za-z0-9][A-Za-z0-9_.-]{0,39})! You've successfully authenticated with the SSH key named .*\.\nGitea does not provide shell access\..*$` and the SSH exit status is `0`.

A matching host pin is mandatory. A successful SSH login is **not** proof of repository permission and must not be recorded as such.

- [ ] **Step 5: Write the failing verifier tests**

`server/internal/r2dgit/verify_test.go` uses fixture banner strings for GitHub and Gitea. Assert the login is extracted, that a wrong exit status fails, that a missing banner fails, that a host pin mismatch fails, and that a Gitea banner with the GitHub wording fails.

- [ ] **Step 6: Run all package tests**

Run: `cd server && go test ./internal/r2dgit/ -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add server/internal/r2dgit
git commit -m "feat(git): add credential service with provider verification"
```

### Task 4: HTTP surface and wiring

**Files:**
- Create: `server/internal/middleware/human_session.go`
- Modify: `server/internal/middleware/auth.go` (JWT branch only)
- Create: `server/internal/handler/r2d_git.go`
- Modify: `server/cmd/server/router.go`
- Modify: `server/cmd/server/main.go`
- Modify: `server/internal/handler/handler.go` (add the `GitSecurity` field)
- Test: `server/internal/handler/r2d_git_test.go`

**Interfaces:**
- Produces: `middleware.HumanSession struct { UserID, SessionID string; AuthenticatedAt time.Time }` and `middleware.HumanSessionFromContext(ctx context.Context) (HumanSession, bool)`.
- Produces: `handler.Handler.GitSecurity *r2dgit.Service`.
- Routes: `GET /api/me/git-identities`, `POST /api/me/git-identities`, `POST /api/me/git-identities/{identityId}/{generation}/verify`, `POST /api/git-identities/{identityId}/revoke`.

- [ ] **Step 1: Write the failing handler tests**

`server/internal/handler/r2d_git_test.go` asserts:

- A request without a human session is rejected with `403` and body `git_human_session_required`.
- A request authenticated with a personal access token (no human session) is rejected with `403`.
- `GET /api/me/git-identities` returns only the caller's identities.
- `POST /api/me/git-identities` creates a key for the caller's own account and never for a `user_id` supplied in the body — the request body must not contain a `user_id` field at all, and unknown fields are rejected.
- `POST /api/git-identities/{identityId}/revoke` for an identity owned by another user returns `404` with body `git_resource_unavailable` (not `403`, so the route is not an existence oracle).
- No response body contains the string `PRIVATE KEY` or the custody token.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd server && go test ./internal/handler/ -run TestGitIdentit -v`
Expected: FAIL — handlers undefined.

- [ ] **Step 3: Add the human session to the middleware**

In `server/internal/middleware/human_session.go` define `HumanSession`, the context key, `HumanSessionFromContext`, and `humanSessionContext`.

In `server/internal/middleware/auth.go`, in the JWT branch only, read the `sid` claim and the `iat` claim from the already-verified claims and attach a `HumanSession` to the request context. Do not attach one for PAT, cloud PAT, task-token or daemon-token branches. The `iat` value is the token issue time; it is the only signal available for recent-auth, and the handler treats a session older than 15 minutes as not recent.

- [ ] **Step 4: Implement the handlers**

`server/internal/handler/r2d_git.go` defines `gitHumanSession(w, r, requireRecent bool) (string, bool)` — it requires `middleware.HumanSessionFromContext`, and when `requireRecent` is set it rejects a session whose `AuthenticatedAt` is older than 15 minutes with `403 git_recent_auth_required`.

Handlers:

- `ListGitIdentities` → `200` with `Profile`.
- `GenerateGitIdentity` → body `{provider_id, request_id, consent_project_ids}`; `201` with `IdentityProfile`.
- `VerifyGitIdentity` → `200` with `IdentityProfile`.
- `RevokeGitIdentity` → `200` with `{"locally_revoked": true}`.

Every error response uses one of the codes `git_human_session_required`, `git_recent_auth_required`, `git_resource_unavailable`, `git_identity_unverified`, `git_identity_conflict`, `git_service_unavailable`. Unknown request fields are rejected with `400`.

- [ ] **Step 5: Wire the routes and the service**

In `server/cmd/server/router.go` mount the four routes inside the existing auth group, without a workspace gate (they are account-scoped).

In `server/cmd/server/main.go` build the service from environment variables `MULTICA_GIT_CUSTODY_URL`, `MULTICA_GIT_CUSTODY_MOUNT`, `MULTICA_GIT_CUSTODY_TOKEN` and assign it to `h.GitSecurity`. When the custody variables are absent the service is constructed with a `nil` custody and every key-management endpoint answers `503 git_service_unavailable`; the server must not start without custody and pretend verification works.

- [ ] **Step 6: Run the handler tests and the backend suite**

Run: `cd server && go test ./internal/handler/ ./internal/middleware/ -v` then `make test`.
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add server/internal/middleware server/internal/handler server/cmd/server
git commit -m "feat(git): expose account-scoped Git identity API"
```

### Task 5: Frontend data layer

**Files:**
- Create: `packages/core/api/git-schemas.ts`
- Create: `packages/core/git-identities/index.ts`
- Modify: `packages/core/api/index.ts`
- Test: `packages/core/api/git-schemas.test.ts`

**Interfaces:**
- Produces: `GitProviderSchema`, `GitIdentitySchema`, `GitProfileSchema` (zod).
- Produces: `api.listGitIdentities()`, `api.generateGitIdentity(input)`, `api.verifyGitIdentity(identityId, generation)`, `api.revokeGitIdentity(identityId)`.
- Produces: `useGitIdentities()`, `useGenerateGitIdentity()`, `useVerifyGitIdentity()`, `useRevokeGitIdentity()` query hooks with the query key `["git-identities", userID]`.

- [ ] **Step 1: Write the failing schema tests**

`packages/core/api/git-schemas.test.ts` asserts:

- A response missing `fingerprint` parses to the fallback without throwing.
- A response whose `state` is an unknown server value parses and keeps the raw string.
- The parsed profile contains no `private_key`, `secret_ref` or `internal_secret_ref` field even when the server sends one — the schema strips unknown keys.
- `parseWithFallback` is used, not a cast.

- [ ] **Step 2: Run the test to verify it fails**

Run: `pnpm --filter @multica/core test -- git-schemas`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement the schemas and client**

`GitIdentitySchema` is `z.object({ id: z.string(), user_id: z.string(), provider_id: z.string(), generation: z.number(), public_key: z.string(), fingerprint: z.string(), state: z.string(), account_id: z.string().optional(), login: z.string().optional(), verified_at: z.string().nullable().optional(), active: z.boolean(), cleanup_pending: z.boolean(), diagnostic: z.string().optional(), consent_project_ids: z.array(z.string()).default([]) })`. The provider schema carries `id`, `label`, `kind`, `host`, `port`.

`packages/core/git-identities/index.ts` exposes the four API calls and the four hooks. The query key includes the signed-in user id and is cleared when the account changes.

- [ ] **Step 4: Run the test to verify it passes**

Run: `pnpm --filter @multica/core test -- git-schemas` and `pnpm --filter @multica/core typecheck`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/core
git commit -m "feat(git): add Git identity schemas and query hooks"
```

### Task 6: Git identities UI

**Files:**
- Create: `packages/views/settings/components/git-identities-section.tsx`
- Modify: `packages/views/settings/components/account-tab.tsx`
- Modify: the `settings` locale files for every supported language
- Test: `packages/views/settings/components/git-identities-section.test.tsx`

**Interfaces:**
- Produces: `export function GitIdentitiesSection()` rendered inside the account settings tab.

- [ ] **Step 1: Write the failing UI test**

`packages/views/settings/components/git-identities-section.test.tsx` asserts:

- The section lists each identity with its provider, fingerprint and state.
- Clicking **Generate key** calls the generate mutation and then shows the public key in a read-only field with a copy button.
- There is no control labelled view, download or export for a private key, and the rendered output never contains the string `PRIVATE KEY`.
- **Revoke** calls the revoke mutation and the identity is shown as revoked.
- A failed generate shows the server's error code and does not show a public key.

- [ ] **Step 2: Run the test to verify it fails**

Run: `pnpm --filter @multica/views test -- git-identities-section`
Expected: FAIL — component missing.

- [ ] **Step 3: Implement the section**

The section renders, per provider from `Profile.Providers`, a card with the provider label, the identities for that provider, their state (`pending_verification`, `ready`, `revoked`), the fingerprint and the public key, plus **Generate key**, **Copy public key** and **Revoke** actions. The public key is rendered in a read-only input so the browser never holds a private value. Copy uses the clipboard API with a fallback.

- [ ] **Step 4: Mount the section in the account tab**

Add `<GitIdentitiesSection />` as a second `SettingsSection` in `packages/views/settings/components/account-tab.tsx`, after the profile section.

- [ ] **Step 5: Add the locale strings**

Add the `git_identities` strings to every locale file under `packages/views/i18n/`, translated per the conventions pages. Use the copy rules: no description that restates the label; state the consequence of **Revoke** (it stops Multica from using the key, and the public key must be removed on the Git provider).

- [ ] **Step 6: Run the frontend checks**

Run: `pnpm --filter @multica/views test -- git-identities-section`, `pnpm typecheck`, `pnpm lint`.
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add packages/views
git commit -m "feat(git): add Git identities section to account settings"
```

## Phase 2 — MVP3 (#88) Per-task SSH agent

### Task 7: Server-side scoped signing

**Files:**
- Create: `server/internal/r2dgit/signing.go`
- Create: `server/internal/handler/r2d_git_sign.go`
- Modify: `server/cmd/server/router.go`
- Test: `server/internal/r2dgit/signing_test.go`
- Test: `server/internal/handler/r2d_git_sign_test.go`

**Interfaces:**
- Produces: `type SigningLease struct { LeaseID string; PublicKey string; Fingerprint string; ExpiresAt time.Time }`.
- Produces: `func (s *Service) OpenSigningLease(ctx context.Context, taskID string) (SigningLease, error)` — resolves the task's originator, requires a `ready` identity for that user, and binds the lease to `(task_id, user_id, identity_id, generation)`.
- Produces: `func (s *Service) Sign(ctx context.Context, leaseID string, data []byte) ([]byte, error)` — signs with the bound key and rejects any lease whose generation is revoked.
- Routes: `POST /api/daemon/tasks/{taskId}/git-signing-lease`, `POST /api/daemon/git-signatures`.

- [ ] **Step 1: Write the failing tests**

`server/internal/r2dgit/signing_test.go` asserts:

- A lease is refused when the task has no originator (`ErrPrincipal`).
- A lease is refused when the originator has no `ready` identity (`ErrIdentity`).
- `Sign` with the lease's own data returns a signature that `ssh.ParsePublicKey` of the lease's public key verifies.
- `Sign` with a different lease's data fails.
- After the identity is revoked, `Sign` fails with `ErrRevoked` and a new lease cannot be opened.
- The lease expires after its TTL and `Sign` then fails.

- [ ] **Step 2: Run the test to verify it fails, implement, then verify it passes**

Run: `cd server && go test ./internal/r2dgit/ -run TestSigning -v`
Expected: FAIL then PASS.

- [ ] **Step 3: Implement the daemon-facing endpoints**

The lease endpoint is authenticated with the daemon token and the task must belong to the calling runtime. It returns only the public key, fingerprint, lease id and expiry — never the private key or the secret ref.

The signature endpoint takes `{lease_id, data}` and returns `{signature: base64}`. `data` is base64-encoded and capped at 64 KiB.

- [ ] **Step 4: Commit**

```bash
git add server/internal/r2dgit server/internal/handler server/cmd/server
git commit -m "feat(git): add task-scoped signing lease and signature endpoint"
```

### Task 8: Daemon-side per-attempt agent socket

**Files:**
- Create: `server/internal/daemon/gitagent/socket.go`
- Test: `server/internal/daemon/gitagent/socket_test.go`

**Interfaces:**
- Produces: `type Signer interface { PublicKey() string; Sign(ctx context.Context, data []byte) ([]byte, error) }`.
- Produces: `type Options struct { SocketPath string; PublicKey string; Signer Signer; MaxRequestBytes int; OnClose func() }`.
- Produces: `func Serve(ctx context.Context, opts Options) error` — listens on a Unix socket at `opts.SocketPath`.
- Produces: `func (s *socket) Close() error`.

- [ ] **Step 1: Write the failing socket test**

`server/internal/daemon/gitagent/socket_test.go` uses `golang.org/x/crypto/ssh/agent` as the client and asserts:

- `agent.List()` returns exactly one identity whose public key equals `opts.PublicKey`.
- `agent.Sign(sshKey, data)` returns a signature the public key verifies.
- `agent.Add(...)` fails and the socket keeps serving the original identity.
- `agent.Remove(...)` fails and the identity is still listed.
- A request for an unknown public key fails to sign.
- After `Close()`, a new connection is refused and an in-flight `Sign` returns an error.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd server && go test ./internal/daemon/gitagent/ -v`
Expected: FAIL — package missing.

- [ ] **Step 3: Implement the restricted agent**

Implement `golang.org/x/crypto/ssh/agent.Agent` with:

- `List()` returning one `*agent.Key` built from the granted public key.
- `Sign(key, data)` returning a signature only when `key.Marshal()` equals the granted key's blob.
- `Add(...)` and `Remove(...)` returning an error, so `agent.ServeAgent` answers `SSH_AGENT_FAILURE` for mutating requests.

Serve with `agent.ServeAgent(restricted, conn)` on a `net.UnixConn`. The socket file lives in a per-attempt directory with mode `0700` and is removed on close. The socket is a capability: whoever can open it can sign with the granted key, so the directory must not be group- or world-accessible.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd server && go test ./internal/daemon/gitagent/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add server/internal/daemon/gitagent
git commit -m "feat(git): add per-attempt SSH agent socket restricted to list and sign"
```

### Task 9: Bind the task originator to the attempt

**Files:**
- Modify: `server/internal/handler/daemon.go` (claim response)
- Modify: `server/internal/daemon/types.go` (claim DTO)
- Modify: `server/internal/daemon/daemon.go` (attempt setup)
- Test: `server/internal/daemon/task_git_identity_test.go`

**Interfaces:**
- Produces: `daemon.Task.ExecutionUserID string` — the authenticated originator of the run, empty when the run has no provable human originator.
- Produces: `daemon.Task.GitIdentity *GitIdentityBinding` with `IdentityID string`, `Generation uint64`, `ProviderID string`, `PublicKey string`, `Fingerprint string`.

- [ ] **Step 1: Write the failing test**

`server/internal/daemon/task_git_identity_test.go` asserts:

- A task whose `originator_user_id` is set produces a claim response whose `execution_user_id` equals that originator.
- A task whose originator is null (schedule, webhook, `rule_owner`, `owner_fallback`) produces an empty `execution_user_id` and no Git identity binding.
- The runtime owner is never used as `execution_user_id`.
- The binding's generation is the identity's active generation, and a revoked identity yields no binding.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd server && go test ./internal/daemon/ -run TestTaskGitIdentity -v`
Expected: FAIL.

- [ ] **Step 3: Implement the binding**

In `server/internal/handler/daemon.go`, in the claim response builder, resolve the execution user from the task's `originator_user_id` only. Never from `runtime.OwnerID`, `agent.OwnerID` or `accountable_user_id`. When the originator is null the fields stay empty.

Resolve the identity through `r2dgit.Service` for `(originator, provider)`; return the binding only when the identity state is `ready` and the identity is not revoked.

- [ ] **Step 4: Commit**

```bash
git add server/internal/handler/daemon.go server/internal/daemon
git commit -m "feat(git): bind task attempts to the authorizing originator"
```

### Task 10: Wire the agent socket into the attempt

**Files:**
- Modify: `server/internal/daemon/daemon.go`
- Modify: `server/internal/daemon/client.go`
- Test: `server/internal/daemon/gitagent_attempt_test.go`

**Interfaces:**
- Consumes: `gitagent.Serve`, `r2dgit.SigningLease`.
- Produces: the daemon sets `SSH_AUTH_SOCK` in the agent environment to the per-attempt socket path, and `SSH_AGENT_PID` is not set.

- [ ] **Step 1: Write the failing test**

`server/internal/daemon/gitagent_attempt_test.go` asserts:

- The agent environment contains `SSH_AUTH_SOCK` pointing at a path under the attempt directory.
- The path is different for two concurrent attempts of the same user.
- A task with no Git identity binding has no `SSH_AUTH_SOCK` and the environment does not inherit the host's `SSH_AUTH_SOCK`.
- When the task ends, the socket file is removed and a new connection to the old path fails.

- [ ] **Step 2: Run the test to verify it fails, implement, then verify it passes**

Run: `cd server && go test ./internal/daemon/ -run TestGitAgentAttempt -v`
Expected: FAIL then PASS.

- [ ] **Step 3: Implement the wiring**

In `runTask`, when the task carries a Git identity binding, open a signing lease, start `gitagent.Serve` on a socket under the attempt's env root, and add `SSH_AUTH_SOCK` to the agent environment. The daemon-side signer forwards `Sign` calls to the server's signature endpoint using the daemon client and the lease id. Stop the socket and remove the file when the task finishes, is cancelled or fails.

Never copy the host `SSH_AUTH_SOCK` into the agent environment, and never mount a host `ssh-agent` socket into the sandbox.

- [ ] **Step 4: Commit**

```bash
git add server/internal/daemon
git commit -m "feat(git): expose a per-attempt SSH agent socket to tasks"
```

## Phase 3 — MVP2 (#89) Bubblewrap task worker

### Task 11: Sandbox policy and bwrap argv

**Files:**
- Create: `server/internal/daemon/sandbox/policy.go`
- Test: `server/internal/daemon/sandbox/policy_test.go`

**Interfaces:**
- Produces: `type Mount struct { Source, Target string; ReadOnly bool }`.
- Produces: `type Policy struct { TaskRoot, HomeDir, TempDir, CheckoutDir string; RuntimeRoots []string; AgentSocket, KnownHosts, PublicKeyFile string; ExtraEnv map[string]string }`.
- Produces: `func BuildArgs(p Policy, self string) ([]string, error)`.

- [ ] **Step 1: Write the failing test**

`server/internal/daemon/sandbox/policy_test.go` asserts:

- The argv contains `--unshare-user`, `--unshare-pid`, `--unshare-ipc`, `--unshare-uts`, `--unshare-net` is **not** present, `--new-session`, `--die-with-parent`, `--clearenv`, `--cap-drop ALL`, `--no-new-privileges`.
- The argv binds `/workspace/repo` read-write, `/home/agent` read-write, `/tmp` read-write, the runtime roots read-only, and the agent socket read-write.
- The argv does **not** contain `--ro-bind / /`, does not bind the host home, the workspace root, `/var/lib`, `/run` as a whole, `.repos`, `/home`, or any path under the host's home directory.
- Every `--bind` source exists on disk; a missing source is an error, not a silently skipped mount.
- `BuildArgs` errors when `TaskRoot`, `HomeDir` or `CheckoutDir` is empty or when `self` is empty.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd server && go test ./internal/daemon/sandbox/ -v`
Expected: FAIL — package missing.

- [ ] **Step 3: Implement the policy**

`BuildArgs` produces the bwrap argv in a fixed order: `--clearenv`, the namespace and privilege flags, `--proc /proc`, `--dev /dev`, the mounts, `--chdir /workspace/repo`, then `--` and the self executable plus the worker argument. It validates that no bind source is inside the host home directory or the workspace root.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd server && go test ./internal/daemon/sandbox/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add server/internal/daemon/sandbox
git commit -m "feat(sandbox): add bwrap policy and argument builder"
```

### Task 12: Worker manifest and IPC protocol

**Files:**
- Create: `server/internal/daemon/sandbox/manifest.go`
- Create: `server/internal/daemon/sandbox/ipc.go`
- Test: `server/internal/daemon/sandbox/ipc_test.go`

**Interfaces:**
- Produces: `type Manifest struct { TaskID, AttemptID, Provider, AgentID, WorkspaceID, WorkDir, HomeDir, TempDir, Prompt string; Env map[string]string; Model string; TimeoutSeconds int }`.
- Produces: `type IPCMessage struct { Type string; Message *agent.Message; Result *agent.Result; Error string }` with type values `message`, `result`, `error`.
- Produces: `func WriteManifest(w io.Writer, m Manifest) error` and `func ReadManifest(r io.Reader) (Manifest, error)`.
- Produces: `func WriteMessage(w io.Writer, msg IPCMessage) error` and `func ReadMessage(r *bufio.Reader) (IPCMessage, error)`.

- [ ] **Step 1: Write the failing test**

`server/internal/daemon/sandbox/ipc_test.go` asserts:

- A manifest round-trips through `WriteManifest`/`ReadManifest`.
- The manifest JSON contains no key whose name matches `(?i)(token|secret|password|private_key|auth)`.
- The manifest's `Env` contains only the allowlisted keys; a key outside the allowlist is dropped by `WriteManifest`.
- An `IPCMessage` carrying an `agent.Message` round-trips with every field intact.
- A malformed frame returns an error instead of a partially decoded message.

- [ ] **Step 2: Run the test to verify it fails, implement, then verify it passes**

Run: `cd server && go test ./internal/daemon/sandbox/ -v`
Expected: FAIL then PASS.

- [ ] **Step 3: Implement the manifest and IPC**

Use newline-delimited JSON. The manifest allowlist is `PATH`, `HOME`, `LANG`, `LC_ALL`, `TMPDIR`, `TERM`, `MULTICA_SERVER_URL`, `MULTICA_TOKEN`, `MULTICA_WORKSPACE_ID`, `MULTICA_AGENT_ID`, `MULTICA_TASK_ID`, `SSH_AUTH_SOCK`, `CODEX_HOME`, `CURSOR_DATA_DIR`. `MULTICA_TOKEN` is the task-scoped token; it is required by the agent and is not a Git credential.

- [ ] **Step 4: Commit**

```bash
git add server/internal/daemon/sandbox
git commit -m "feat(sandbox): add worker manifest and IPC protocol"
```

### Task 13: Hidden worker command and IPC backend

**Files:**
- Create: `server/internal/daemon/sandbox/worker.go`
- Create: `server/internal/daemon/sandbox/backend.go`
- Modify: `server/cmd/multica/main.go`
- Test: `server/internal/daemon/sandbox/backend_test.go`

**Interfaces:**
- Produces: `sandbox.WorkerArg = "__multica_internal_task_worker"`.
- Produces: `func RunWorker(ctx context.Context, manifest Manifest, out io.Writer) error` — resolves the backend, executes it, and streams messages and the result.
- Produces: `type IPCBackend struct { ... }` implementing `agent.Backend`; `func NewIPCBackend(self string, manifest Manifest) *IPCBackend`.

- [ ] **Step 1: Write the failing test**

`server/internal/daemon/sandbox/backend_test.go` asserts:

- `IPCBackend.Execute` starts the worker command, forwards the worker's `message` frames into `Session.Messages` in order, and forwards the `result` frame into `Session.Result`.
- A worker that exits non-zero without a result frame produces an error result rather than a silent hang.
- Cancelling the context terminates the worker process.
- The worker's stdout is parsed only as newline-delimited JSON; a line that is not valid JSON produces an error and does not leak raw worker output into the session.

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd server && go test ./internal/daemon/sandbox/ -v`
Expected: FAIL.

- [ ] **Step 3: Implement the worker and the backend**

`RunWorker` reads the manifest from stdin, calls `agent.ResolveBackend`, executes with the manifest's prompt and options, and writes one `IPCMessage` per agent message plus a final `result` frame.

`IPCBackend.Execute` starts `self` with the worker argument and the manifest on stdin, reads frames from stdout, and fills the session channels. It must bound the frame size and stop the worker when the context is cancelled.

In `server/cmd/multica/main.go`, add the hidden worker dispatch next to the existing `execenv.PreparationHelperArg` and `agent.CursorHookHelperArg` checks: `len(os.Args) == 2 && os.Args[1] == sandbox.WorkerArg` reads the manifest from `os.Stdin` and writes frames to `os.Stdout`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd server && go test ./internal/daemon/sandbox/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add server/internal/daemon/sandbox server/cmd/multica
git commit -m "feat(sandbox): add hidden task worker and IPC backend"
```

### Task 14: Launch the worker under bwrap

**Files:**
- Modify: `server/internal/daemon/daemon.go`
- Modify: `server/internal/daemon/config.go`
- Test: `server/internal/daemon/sandbox_launch_test.go`

**Interfaces:**
- Consumes: `sandbox.BuildArgs`, `sandbox.NewIPCBackend`.
- Produces: `daemon.Config.SandboxEnabled bool` and `daemon.Config.SandboxRequired bool`.

- [ ] **Step 1: Write the failing test**

`server/internal/daemon/sandbox_launch_test.go` asserts:

- With sandboxing enabled, the agent process is started through the bwrap argv, and the recorded argv contains the namespace flags from Task 11.
- When bwrap is missing and `SandboxRequired` is true, the task fails with a `sandbox_unavailable` failure reason and the agent is never started directly.
- When bwrap is missing and `SandboxRequired` is false, the daemon runs the task on the host and logs that the sandbox was unavailable.
- The host `SSH_AUTH_SOCK` is not present in the worker environment.

- [ ] **Step 2: Run the test to verify it fails, implement, then verify it passes**

Run: `cd server && go test ./internal/daemon/ -run TestSandboxLaunch -v`
Expected: FAIL then PASS.

- [ ] **Step 3: Implement the launch**

In `runTask`, when `SandboxEnabled`, build the sandbox policy from the task's env root, home, temp and checkout directories, the runtime roots, and the per-attempt agent socket. Build the bwrap argv with `sandbox.BuildArgs`, create an `sandbox.IPCBackend` and pass it to the same execution path that currently receives the resolved backend, so message draining, supplements, the idle watchdog and the result mapping stay in one place.

Private HOME: the worker's `HOME` is the attempt's home directory, never the daemon's. The per-task `CODEX_HOME` symlink to the host `~/.codex/auth.json` is not mounted into the sandbox; the AI auth material that the runtime needs is provided explicitly by the runtime profile.

- [ ] **Step 4: Run the backend suite and commit**

Run: `cd server && go test ./internal/daemon/... && make test`
Expected: PASS.

```bash
git add server/internal/daemon
git commit -m "feat(sandbox): run task attempts inside a bwrap worker"
```

### Task 15: Documentation and trackers

**Files:**
- Modify: `docs/security/per-user-git-credentials-plan.md`
- Modify: `docs/security/git-security-agent-handoff.md`

- [ ] **Step 1: Update the spec status**

Change the status line to record which MVP items are implemented, which are verified by tests and which remain open. Do not claim a runtime is deployed, that a production key exists or that the sandbox is proven in production.

- [ ] **Step 2: Update the handoff**

Replace the "three tasks" table with the delivered state and the exact commands used to verify it, including the checks that were skipped.

- [ ] **Step 3: Run the documentation checks**

Run: `git diff --check` and a link check over the two documents.
Expected: no whitespace errors and no broken local links.

- [ ] **Step 4: Commit**

```bash
git add docs/security
git commit -m "docs(security): record MVP implementation status"
```
