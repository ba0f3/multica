CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS r2d_git_key_secret_ref_uidx
    ON r2d_git_key_secret (secret_ref);
