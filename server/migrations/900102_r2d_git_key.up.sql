-- Key generations of a Git identity (900102).
--
-- internal_secret_ref points into the encrypted custody store. It is an
-- internal reference, not a path a caller may supply, and it is never
-- returned to a browser. The (identity_id, generation) primary key is
-- attached in 900110 from the CONCURRENTLY-built index in 900109.
CREATE TABLE IF NOT EXISTS r2d_git_key (
    identity_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    public_key TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL DEFAULT '',
    internal_secret_ref TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('provisioning', 'pending_verification', 'ready', 'revoked')),
    account_id TEXT NOT NULL DEFAULT '',
    login TEXT NOT NULL DEFAULT '',
    verified_at TIMESTAMPTZ,
    cleanup_pending BOOLEAN NOT NULL DEFAULT FALSE,
    diagnostic TEXT NOT NULL DEFAULT '',
    consent_project_ids JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(consent_project_ids) = 'array'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
