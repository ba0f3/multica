-- Backing index for r2d_git_key_job's primary key, attached in 900112 via
-- PRIMARY KEY USING INDEX. Own single-statement migration so CONCURRENTLY runs
-- outside an implicit transaction (repo convention).
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS r2d_git_key_job_pkey_uidx
    ON r2d_git_key_job (id);
