-- One identity per (user, provider). The unique index is what makes a
-- concurrent double "generate" resolve to one identity instead of two.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS r2d_git_identity_user_provider_idx
    ON r2d_git_identity (user_id, provider_id);
