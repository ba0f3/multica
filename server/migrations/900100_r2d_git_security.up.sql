-- Local allocation: docs/security/git-security-migrations.md. No upstream schema changes.
CREATE TABLE r2d_git_provider (
 id uuid NOT NULL, label text NOT NULL, kind text NOT NULL CHECK (kind IN ('github','gitea')),
 host text NOT NULL, port integer NOT NULL DEFAULT 22 CHECK (port > 0 AND port < 65536),
 host_pins jsonb NOT NULL DEFAULT '[]', enabled boolean NOT NULL DEFAULT false
);
CREATE TABLE r2d_git_identity (
 id uuid NOT NULL, user_id uuid NOT NULL, provider_id uuid NOT NULL,
 active_generation bigint NOT NULL DEFAULT 0, epoch bigint NOT NULL DEFAULT 1,
 revoked boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE r2d_git_key (
 identity_id uuid NOT NULL, generation bigint NOT NULL CHECK (generation > 0),
 public_key text NOT NULL DEFAULT '', fingerprint text NOT NULL DEFAULT '',
 internal_secret_ref text NOT NULL, state text NOT NULL CHECK (state IN ('provisioning','pending_verification','ready','revoked')),
 account_id text NOT NULL DEFAULT '', login text NOT NULL DEFAULT '', verified_at timestamptz,
 cleanup_pending boolean NOT NULL DEFAULT false, diagnostic text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE r2d_git_key_job (
 id uuid NOT NULL, user_id uuid NOT NULL, identity_id uuid NOT NULL, generation bigint NOT NULL,
 kind text NOT NULL CHECK (kind IN ('provision','destroy')),
 idempotency_key text NOT NULL, state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','done','error')),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE r2d_git_project_policy (
 project_id uuid NOT NULL, workspace_id uuid NOT NULL, epoch bigint NOT NULL DEFAULT 1
);
CREATE TABLE r2d_git_project_grant (
 project_id uuid NOT NULL, subject_kind text NOT NULL CHECK (subject_kind IN ('user','workspace')),
 subject_id uuid NOT NULL, role text NOT NULL CHECK (role IN ('viewer','member','manager'))
);
CREATE TABLE r2d_git_repository (
 id uuid NOT NULL, project_id uuid NOT NULL, provider_id uuid NOT NULL, canonical_repository text NOT NULL,
 epoch bigint NOT NULL DEFAULT 1, protected boolean NOT NULL DEFAULT true,
 allow_read boolean NOT NULL DEFAULT true, allow_write boolean NOT NULL DEFAULT false,
 write_refs jsonb NOT NULL DEFAULT '[]'
);
CREATE TABLE r2d_git_run_context (
 id uuid NOT NULL, task_id uuid NOT NULL, root_id uuid NOT NULL, parent_id uuid,
 authorizing_user_id uuid NOT NULL, spec jsonb NOT NULL, derivation text NOT NULL,
 state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','completed','revoked')),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE r2d_git_run_grant (
 id uuid NOT NULL, context_id uuid NOT NULL, identity_id uuid NOT NULL,
 spec jsonb NOT NULL, state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','revoked'))
);
CREATE TABLE r2d_git_security_event (
 id uuid NOT NULL, user_id uuid NOT NULL, subject_id uuid NOT NULL,
 action text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION r2d_git_context_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.id,NEW.task_id,NEW.root_id,NEW.parent_id,NEW.authorizing_user_id,NEW.spec,NEW.derivation)
 IS DISTINCT FROM (OLD.id,OLD.task_id,OLD.root_id,OLD.parent_id,OLD.authorizing_user_id,OLD.spec,OLD.derivation) THEN
  RAISE EXCEPTION 'immutable Git run context';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER r2d_git_context_immutable BEFORE UPDATE ON r2d_git_run_context FOR EACH ROW EXECUTE FUNCTION r2d_git_context_immutable();
CREATE FUNCTION r2d_git_grant_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.id,NEW.context_id,NEW.identity_id,NEW.spec) IS DISTINCT FROM (OLD.id,OLD.context_id,OLD.identity_id,OLD.spec) THEN
  RAISE EXCEPTION 'immutable Git run grant';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER r2d_git_grant_immutable BEFORE UPDATE ON r2d_git_run_grant FOR EACH ROW EXECUTE FUNCTION r2d_git_grant_immutable();
