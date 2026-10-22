-- One Git identity per (user, provider) pair (900101).
--
-- The identity is the stable handle a task grant points at. active_generation
-- names the generation a run may use; it is 0 while no generation is ready.
-- user_id and provider_id are application-layer relations by repo rule, so
-- there are no foreign keys.
CREATE TABLE IF NOT EXISTS r2d_git_identity (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    provider_id UUID NOT NULL,
    active_generation BIGINT NOT NULL DEFAULT 0 CHECK (active_generation >= 0),
    epoch BIGINT NOT NULL DEFAULT 1 CHECK (epoch >= 1),
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
