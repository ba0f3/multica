CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS r2d_git_job_request_idx ON r2d_git_key_job (user_id,idempotency_key);
