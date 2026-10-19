-- Protected execution must remain paused during rollback; never restore ambient credentials.
DROP TABLE IF EXISTS r2d_git_run_grant;
DROP TABLE IF EXISTS r2d_git_run_context;
DROP FUNCTION IF EXISTS r2d_git_grant_immutable();
DROP FUNCTION IF EXISTS r2d_git_context_immutable();
DROP TABLE IF EXISTS r2d_git_security_event;
DROP TABLE IF EXISTS r2d_git_repository;
DROP TABLE IF EXISTS r2d_git_project_grant;
DROP TABLE IF EXISTS r2d_git_project_policy;
DROP TABLE IF EXISTS r2d_git_key_job;
DROP TABLE IF EXISTS r2d_git_key;
DROP TABLE IF EXISTS r2d_git_identity;
DROP TABLE IF EXISTS r2d_git_provider;
