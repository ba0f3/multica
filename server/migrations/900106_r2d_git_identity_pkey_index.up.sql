-- Backing index for r2d_git_identity's primary key, attached in 900107 via
-- PRIMARY KEY USING INDEX. Own single-statement migration so CONCURRENTLY runs
-- outside an implicit transaction (repo convention).
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS r2d_git_identity_pkey_uidx
    ON r2d_git_identity (id);
