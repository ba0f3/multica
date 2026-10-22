-- Durable lifecycle jobs for Git key custody (900103).
--
-- A provision job records that a key was generated and handed to custody; a
-- destroy job records that a revoked generation still has secret material to
-- remove. The idempotency key makes a retried request reuse the same job
-- instead of creating a second key.
CREATE TABLE IF NOT EXISTS r2d_git_key_job (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    identity_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    kind TEXT NOT NULL CHECK (kind IN ('provision', 'destroy')),
    idempotency_key TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'done', 'error')),
    last_error TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
