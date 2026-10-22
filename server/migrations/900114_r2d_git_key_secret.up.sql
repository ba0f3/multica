-- Encrypted Git private key material at rest (900114).
--
-- internal_secret_ref on r2d_git_key points at secret_ref here. The sealed
-- column holds a secretbox ciphertext; plaintext never appears in the database.
CREATE TABLE IF NOT EXISTS r2d_git_key_secret (
    secret_ref TEXT NOT NULL,
    sealed BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
