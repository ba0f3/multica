ALTER TABLE r2d_git_key ADD COLUMN IF NOT EXISTS consent_project_ids jsonb NOT NULL DEFAULT '[]';
ALTER TABLE r2d_git_key_job ADD COLUMN IF NOT EXISTS worker_token uuid;
ALTER TABLE r2d_git_key_job ADD COLUMN IF NOT EXISTS lease_until timestamptz;
