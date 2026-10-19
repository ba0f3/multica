CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS r2d_git_identity_owner_idx ON r2d_git_identity (user_id,provider_id);
