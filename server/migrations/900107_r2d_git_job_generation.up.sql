CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS r2d_git_job_generation_idx ON r2d_git_key_job (identity_id,generation,kind);
