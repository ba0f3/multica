CREATE OR REPLACE FUNCTION r2d_git_authority_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE old_row jsonb; new_row jsonb; workspace uuid; resource_workspace uuid; audience uuid; guarded boolean := false;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM r2d_git_restore_checkpoint)
 OR current_setting('multica.git_authority_mutation',true)='witnessed' THEN
  IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
 END IF;
 old_row:=to_jsonb(OLD); new_row:=to_jsonb(NEW);
 IF TG_TABLE_NAME='user' THEN
  audience:=COALESCE((old_row->>'id')::uuid,(new_row->>'id')::uuid);
  guarded:=TG_OP='DELETE' OR (old_row->'email' IS DISTINCT FROM new_row->'email');
 ELSIF TG_TABLE_NAME='workspace' THEN
  workspace:=COALESCE((old_row->>'id')::uuid,(new_row->>'id')::uuid); guarded:=TG_OP='DELETE';
 ELSIF TG_TABLE_NAME='agent_invocation_target' THEN
  SELECT a.workspace_id INTO workspace FROM agent a WHERE a.id=COALESCE((old_row->>'agent_id')::uuid,(new_row->>'agent_id')::uuid); guarded:=true;
 ELSE
  workspace:=COALESCE((old_row->>'workspace_id')::uuid,(new_row->>'workspace_id')::uuid);
  IF TG_TABLE_NAME='member' THEN guarded:=true;
  ELSIF TG_TABLE_NAME='agent' THEN guarded:=TG_OP<>'UPDATE' OR (old_row->'workspace_id',old_row->'runtime_id',old_row->'owner_id',old_row->'permission_mode',old_row->'archived_at') IS DISTINCT FROM (new_row->'workspace_id',new_row->'runtime_id',new_row->'owner_id',new_row->'permission_mode',new_row->'archived_at');
  ELSIF TG_TABLE_NAME='agent_runtime' THEN guarded:=TG_OP='DELETE' OR old_row->'workspace_id' IS DISTINCT FROM new_row->'workspace_id';
  ELSIF TG_TABLE_NAME='project' THEN guarded:=TG_OP='DELETE' OR old_row->'workspace_id' IS DISTINCT FROM new_row->'workspace_id';
  ELSIF TG_TABLE_NAME='issue' THEN guarded:=TG_OP='DELETE' OR (old_row->'workspace_id',old_row->'project_id') IS DISTINCT FROM (new_row->'workspace_id',new_row->'project_id');
  ELSIF TG_TABLE_NAME='agent_task_queue' THEN
   SELECT a.workspace_id INTO workspace FROM agent a WHERE a.id=COALESCE((old_row->>'agent_id')::uuid,(new_row->>'agent_id')::uuid);
   SELECT i.workspace_id INTO resource_workspace FROM issue i WHERE i.id=COALESCE((old_row->>'issue_id')::uuid,(new_row->>'issue_id')::uuid);
   guarded:=TG_OP<>'UPDATE' OR
    (old_row->'agent_id',old_row->'runtime_id',old_row->'issue_id',old_row->'originator_user_id',old_row->'originator_source',old_row->'status',old_row->'parent_task_id',old_row->'retry_of_task_id',old_row->'delegated_from_task_id',old_row->'rerun_of_task_id',old_row->'chat_session_id',old_row->'autopilot_run_id',old_row->'context') IS DISTINCT FROM
    (new_row->'agent_id',new_row->'runtime_id',new_row->'issue_id',new_row->'originator_user_id',new_row->'originator_source',new_row->'status',new_row->'parent_task_id',new_row->'retry_of_task_id',new_row->'delegated_from_task_id',new_row->'rerun_of_task_id',new_row->'chat_session_id',new_row->'autopilot_run_id',new_row->'context');
  END IF;
 END IF;
 IF guarded AND EXISTS(SELECT 1 FROM r2d_git_source_quarantine q WHERE (q.kind='workspace' AND q.subject_id IN(workspace,resource_workspace,(new_row->>'workspace_id')::uuid)) OR (q.kind='audience' AND q.subject_id=audience)) THEN
  RAISE EXCEPTION 'protected authority requires witnessed mutation';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;
-- Standalone side-table migration fixtures have no upstream tables. A skipped
-- attachment must be rerun explicitly after recovering any missing upstream table.
DO $attach$
BEGIN
 IF to_regclass('member') IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('member') AND tgname='r2d_git_member_guard') THEN
  CREATE TRIGGER r2d_git_member_guard BEFORE INSERT OR UPDATE OR DELETE ON member FOR EACH ROW EXECUTE FUNCTION r2d_git_authority_guard();
 END IF;
 IF to_regclass('"user"') IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('"user"') AND tgname='r2d_git_user_guard') THEN
  CREATE TRIGGER r2d_git_user_guard BEFORE UPDATE OR DELETE ON "user" FOR EACH ROW EXECUTE FUNCTION r2d_git_authority_guard();
 END IF;
 IF to_regclass('workspace') IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('workspace') AND tgname='r2d_git_workspace_guard') THEN
  CREATE TRIGGER r2d_git_workspace_guard BEFORE UPDATE OR DELETE ON workspace FOR EACH ROW EXECUTE FUNCTION r2d_git_authority_guard();
 END IF;
 IF to_regclass('agent') IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('agent') AND tgname='r2d_git_agent_guard') THEN
  CREATE TRIGGER r2d_git_agent_guard BEFORE UPDATE OR DELETE ON agent FOR EACH ROW EXECUTE FUNCTION r2d_git_authority_guard();
 END IF;
 IF to_regclass('agent_runtime') IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('agent_runtime') AND tgname='r2d_git_runtime_guard') THEN
  CREATE TRIGGER r2d_git_runtime_guard BEFORE UPDATE OR DELETE ON agent_runtime FOR EACH ROW EXECUTE FUNCTION r2d_git_authority_guard();
 END IF;
 IF to_regclass('agent_invocation_target') IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('agent_invocation_target') AND tgname='r2d_git_invocation_guard') THEN
  CREATE TRIGGER r2d_git_invocation_guard BEFORE INSERT OR UPDATE OR DELETE ON agent_invocation_target FOR EACH ROW EXECUTE FUNCTION r2d_git_authority_guard();
 END IF;
 IF to_regclass('project') IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('project') AND tgname='r2d_git_project_guard') THEN
  CREATE TRIGGER r2d_git_project_guard BEFORE UPDATE OR DELETE ON project FOR EACH ROW EXECUTE FUNCTION r2d_git_authority_guard();
 END IF;
 IF to_regclass('issue') IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('issue') AND tgname='r2d_git_issue_guard') THEN
  CREATE TRIGGER r2d_git_issue_guard BEFORE UPDATE OR DELETE ON issue FOR EACH ROW EXECUTE FUNCTION r2d_git_authority_guard();
 END IF;
 IF to_regclass('agent_task_queue') IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=to_regclass('agent_task_queue') AND tgname='r2d_git_task_guard') THEN
  CREATE TRIGGER r2d_git_task_guard BEFORE INSERT OR UPDATE OR DELETE ON agent_task_queue FOR EACH ROW EXECUTE FUNCTION r2d_git_authority_guard();
 END IF;
END $attach$;
