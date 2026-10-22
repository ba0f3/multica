-- Backing index for r2d_git_provider's primary key, attached in 900105 via
-- PRIMARY KEY USING INDEX. Own single-statement migration so CONCURRENTLY runs
-- outside an implicit transaction (repo convention).
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS r2d_git_provider_pkey_uidx
    ON r2d_git_provider (id);
