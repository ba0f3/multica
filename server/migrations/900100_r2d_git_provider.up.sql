-- Approved Git provider instances (900100).
--
-- A provider row is operator-approved configuration: the host, port and the
-- pinned host keys a Git connection to it must present. The table holds no
-- user data and references no upstream table, so it carries no foreign key.
--
-- id is NOT declared inline as PRIMARY KEY: the repo convention (see 332-334)
-- is to build the table without a primary key, create the backing unique
-- index CONCURRENTLY in its own single-statement migration (900104), then
-- attach it with PRIMARY KEY USING INDEX (900105). An inline PRIMARY KEY would
-- build its index non-concurrently, which the project's migration rules forbid
-- even on a new table.
CREATE TABLE IF NOT EXISTS r2d_git_provider (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    label TEXT NOT NULL CHECK (char_length(label) BETWEEN 1 AND 120),
    kind TEXT NOT NULL CHECK (kind IN ('github', 'gitea')),
    host TEXT NOT NULL CHECK (char_length(host) BETWEEN 1 AND 255),
    port INTEGER NOT NULL DEFAULT 22 CHECK (port > 0 AND port < 65536),
    host_pins JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(host_pins) = 'array'),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
