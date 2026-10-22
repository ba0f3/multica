-- Attach the CONCURRENTLY-built unique index as the table's primary key.
ALTER TABLE r2d_git_identity
    ADD CONSTRAINT r2d_git_identity_pkey PRIMARY KEY USING INDEX r2d_git_identity_pkey_uidx;
