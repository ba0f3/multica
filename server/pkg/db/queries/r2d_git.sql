-- name: ListR2DGitProviders :many
-- Only enabled providers are offered to a user. A disabled provider stays in
-- the table so an operator can turn key management off without losing the
-- pinned host configuration.
SELECT id, label, kind, host, port, host_pins, enabled, created_at
FROM r2d_git_provider
WHERE enabled = true
ORDER BY label ASC, id ASC;

-- name: GetR2DGitProvider :one
SELECT id, label, kind, host, port, host_pins, enabled, created_at
FROM r2d_git_provider
WHERE id = $1;

-- name: GetR2DGitIdentity :one
SELECT id, user_id, provider_id, active_generation, epoch, revoked, created_at
FROM r2d_git_identity
WHERE id = $1;

-- name: GetR2DGitIdentityForUser :one
SELECT id, user_id, provider_id, active_generation, epoch, revoked, created_at
FROM r2d_git_identity
WHERE user_id = $1 AND provider_id = $2;

-- name: ListR2DGitIdentitiesForUser :many
SELECT id, user_id, provider_id, active_generation, epoch, revoked, created_at
FROM r2d_git_identity
WHERE user_id = $1
ORDER BY provider_id ASC;

-- name: ListR2DGitKeysForUser :many
-- Every generation of every identity the user owns, newest generation first.
-- The join keeps the ownership check in the query so a caller cannot ask for
-- another user's key by identity id alone.
SELECT k.identity_id, k.generation, k.public_key, k.fingerprint,
       k.internal_secret_ref, k.state, k.account_id, k.login, k.verified_at,
       k.cleanup_pending, k.diagnostic, k.consent_project_ids, k.created_at,
       i.provider_id, i.active_generation, i.revoked AS identity_revoked
FROM r2d_git_key k
JOIN r2d_git_identity i ON i.id = k.identity_id
WHERE i.user_id = $1
ORDER BY i.provider_id ASC, k.generation DESC;

-- name: GetR2DGitKey :one
SELECT identity_id, generation, public_key, fingerprint, internal_secret_ref,
       state, account_id, login, verified_at, cleanup_pending, diagnostic,
       consent_project_ids, created_at
FROM r2d_git_key
WHERE identity_id = $1 AND generation = $2;

-- name: CreateR2DGitIdentity :one
INSERT INTO r2d_git_identity (id, user_id, provider_id, active_generation, epoch, revoked)
VALUES ($1, $2, $3, 0, 1, false)
RETURNING id, user_id, provider_id, active_generation, epoch, revoked, created_at;

-- name: SetR2DGitIdentityActiveGeneration :one
-- Activating a generation bumps the epoch so a lease bound to the previous
-- epoch stops being accepted.
UPDATE r2d_git_identity
SET active_generation = $2,
    epoch = epoch + 1
WHERE id = $1 AND revoked = false
RETURNING id, user_id, provider_id, active_generation, epoch, revoked, created_at;

-- name: RevokeR2DGitIdentity :one
-- Revocation clears the active generation in the same statement so no new
-- lease can be bound to this identity.
UPDATE r2d_git_identity
SET revoked = true,
    active_generation = 0,
    epoch = epoch + 1
WHERE id = $1 AND user_id = $2
RETURNING id, user_id, provider_id, active_generation, epoch, revoked, created_at;

-- name: CreateR2DGitKey :one
INSERT INTO r2d_git_key (identity_id, generation, public_key, fingerprint,
                          internal_secret_ref, state, account_id, login,
                          verified_at, cleanup_pending, diagnostic, consent_project_ids)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING identity_id, generation, public_key, fingerprint, internal_secret_ref,
          state, account_id, login, verified_at, cleanup_pending, diagnostic,
          consent_project_ids, created_at;

-- name: MarkR2DGitKeyReady :one
UPDATE r2d_git_key
SET state = 'ready',
    account_id = $3,
    login = $4,
    verified_at = $5,
    diagnostic = ''
WHERE identity_id = $1 AND generation = $2 AND state = 'pending_verification' 
RETURNING identity_id, generation, public_key, fingerprint, internal_secret_ref,
          state, account_id, login, verified_at, cleanup_pending, diagnostic,
          consent_project_ids, created_at;

-- name: RevokeR2DGitKey :one
-- Revocation marks the generation unusable and records that its secret still
-- has to be destroyed by the cleanup job.
UPDATE r2d_git_key
SET state = 'revoked',
    cleanup_pending = true
WHERE identity_id = $1 AND generation = $2
RETURNING identity_id, generation, public_key, fingerprint, internal_secret_ref,
          state, account_id, login, verified_at, cleanup_pending, diagnostic,
          consent_project_ids, created_at;

-- name: ClearR2DGitKeyCleanupPending :one
UPDATE r2d_git_key
SET cleanup_pending = false
WHERE identity_id = $1 AND generation = $2
RETURNING identity_id, generation, public_key, fingerprint, internal_secret_ref,
          state, account_id, login, verified_at, cleanup_pending, diagnostic,
          consent_project_ids, created_at;

-- name: CreateR2DGitKeyJob :one
INSERT INTO r2d_git_key_job (id, user_id, identity_id, generation, kind,
                              idempotency_key, state, last_error)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, user_id, identity_id, generation, kind, idempotency_key, state,
          last_error, created_at, updated_at;

-- name: GetR2DGitKeyJobByIdempotencyKey :one
SELECT id, user_id, identity_id, generation, kind, idempotency_key, state,
       last_error, created_at, updated_at
FROM r2d_git_key_job
WHERE idempotency_key = $1;

-- name: UpdateR2DGitKeyJobState :one
UPDATE r2d_git_key_job
SET state = $2,
    last_error = $3,
    updated_at = now()
WHERE id = $1
RETURNING id, user_id, identity_id, generation, kind, idempotency_key, state,
          last_error, created_at, updated_at;

-- name: ListPendingR2DGitKeyJobs :many
SELECT id, user_id, identity_id, generation, kind, idempotency_key, state,
       last_error, created_at, updated_at
FROM r2d_git_key_job
WHERE state = 'pending'
ORDER BY created_at ASC;

-- name: GetTaskOriginatorUserID :one
-- The human who authorized the task.
--
-- Empty when the task has no provable human originator: a scheduled run, a
-- webhook trigger and an audit-only fallback all leave this empty. The
-- value is the only one that may select a Git signing key, so a task
-- without one never gets a credential.
SELECT originator_user_id
FROM agent_task_queue
WHERE id = $1;
