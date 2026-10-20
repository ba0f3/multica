-- A retried "generate" request must reuse the same job instead of creating a
-- second key, so the idempotency key is unique.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS r2d_git_key_job_idempotency_idx
    ON r2d_git_key_job (idempotency_key);
