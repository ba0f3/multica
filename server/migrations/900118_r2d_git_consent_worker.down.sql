ALTER TABLE r2d_git_key_job DROP COLUMN IF EXISTS lease_until;
ALTER TABLE r2d_git_key_job DROP COLUMN IF EXISTS worker_token;
ALTER TABLE r2d_git_key DROP COLUMN IF EXISTS consent_project_ids;
