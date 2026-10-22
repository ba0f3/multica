-- Backing index for r2d_git_key's primary key, attached in 900110 via
-- PRIMARY KEY USING INDEX. Own single-statement migration so CONCURRENTLY runs
-- outside an implicit transaction (repo convention).
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS r2d_git_key_generation_uidx
    ON r2d_git_key (identity_id, generation);
