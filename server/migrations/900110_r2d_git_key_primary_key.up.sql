-- Attach the CONCURRENTLY-built unique index as the table's primary key.
ALTER TABLE r2d_git_key
    ADD CONSTRAINT r2d_git_key_pkey PRIMARY KEY USING INDEX r2d_git_key_generation_uidx;
