-- name: IsR2DGitProtectedTask :one
WITH RECURSIVE lineage AS (
 SELECT t.id,0 AS depth FROM agent_task_queue t WHERE t.id=sqlc.arg(task_id)::uuid
 UNION
 SELECT parent.id,lineage.depth+1
 FROM lineage JOIN agent_task_queue child ON child.id=lineage.id
 JOIN agent_task_queue parent ON parent.id IN (child.parent_task_id,child.retry_of_task_id,child.delegated_from_task_id,child.rerun_of_task_id)
 WHERE lineage.depth<16
)
SELECT EXISTS(SELECT 1 FROM r2d_git_run_context c JOIN lineage ON lineage.id=c.task_id)
 OR EXISTS(SELECT 1 FROM lineage WHERE depth=16)
 OR EXISTS(SELECT 1 FROM lineage JOIN agent_task_queue t ON t.id=lineage.id
 LEFT JOIN issue i ON i.id=t.issue_id
 LEFT JOIN chat_session chat ON chat.id=t.chat_session_id
 LEFT JOIN autopilot_run ar ON ar.id=t.autopilot_run_id
 LEFT JOIN autopilot ap ON ap.id=ar.autopilot_id
 LEFT JOIN issue parent_issue ON parent_issue.id::text=t.context->>'parent_issue_id'
 LEFT JOIN issue_source_context capture ON capture.origin_task_id=t.id OR capture.id::text=t.context->>'source_context_id'
 LEFT JOIN issue captured_issue ON captured_issue.id=capture.source_issue_id
 JOIN r2d_git_repository r ON (r.project_id=i.project_id OR r.project_id=chat.project_id OR r.project_id=ap.project_id
 OR r.project_id=parent_issue.project_id OR r.project_id=captured_issue.project_id OR r.project_id::text=t.context->>'project_id')
 WHERE r.protected)::boolean AS protected;

-- name: ListR2DGitTaskProtection :many
WITH RECURSIVE lineage AS (
 SELECT t.id AS root_id,t.id,0 AS depth FROM agent_task_queue t WHERE t.id=ANY(sqlc.arg(task_ids)::uuid[])
 UNION
 SELECT lineage.root_id,parent.id,lineage.depth+1
 FROM lineage JOIN agent_task_queue child ON child.id=lineage.id
 JOIN agent_task_queue parent ON parent.id IN (child.parent_task_id,child.retry_of_task_id,child.delegated_from_task_id,child.rerun_of_task_id)
 WHERE lineage.depth<16
)
SELECT requested.id::uuid AS task_id, (NOT EXISTS(SELECT 1 FROM agent_task_queue t WHERE t.id=requested.id)
 OR EXISTS(SELECT 1 FROM r2d_git_run_context c JOIN lineage ON lineage.id=c.task_id WHERE lineage.root_id=requested.id)
 OR EXISTS(SELECT 1 FROM lineage WHERE depth=16 AND root_id=requested.id)
 OR EXISTS(SELECT 1 FROM lineage JOIN agent_task_queue t ON t.id=lineage.id
 LEFT JOIN issue i ON i.id=t.issue_id
 LEFT JOIN chat_session chat ON chat.id=t.chat_session_id
 LEFT JOIN autopilot_run ar ON ar.id=t.autopilot_run_id
 LEFT JOIN autopilot ap ON ap.id=ar.autopilot_id
 LEFT JOIN issue parent_issue ON parent_issue.id::text=t.context->>'parent_issue_id'
 LEFT JOIN issue_source_context capture ON capture.origin_task_id=t.id OR capture.id::text=t.context->>'source_context_id'
 LEFT JOIN issue captured_issue ON captured_issue.id=capture.source_issue_id
 JOIN r2d_git_repository r ON (r.project_id=i.project_id OR r.project_id=chat.project_id OR r.project_id=ap.project_id
 OR r.project_id=parent_issue.project_id OR r.project_id=captured_issue.project_id OR r.project_id::text=t.context->>'project_id')
 WHERE r.protected AND lineage.root_id=requested.id))::boolean AS protected
FROM unnest(sqlc.arg(task_ids)::uuid[]) AS requested(id);
