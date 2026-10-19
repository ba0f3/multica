package r2dgit

import "context"

// SettleWorkspaceDeletion runs inside the workspace teardown transaction after
// its workspace/task-owner fences. Keys belong to humans, not teams. Immutable
// contexts, revoked grants and security events survive as authorization history.
func SettleWorkspaceDeletion(ctx context.Context, db Database, workspace, actor string) error {
	const roots = `SELECT root_id FROM r2d_git_run_context WHERE spec->'binding'->>'execution_workspace_id'=$1 OR spec->'binding'->>'resource_workspace_id'=$1`
	const projects = `SELECT project_id FROM r2d_git_project_policy WHERE workspace_id=$1::uuid UNION SELECT id FROM project WHERE workspace_id=$1::uuid`
	for _, statement := range []string{
		`UPDATE r2d_git_run_context SET state='revoked' WHERE root_id IN (` + roots + `)`,
		`UPDATE r2d_git_run_grant SET state='revoked' WHERE context_id IN (SELECT id FROM r2d_git_run_context WHERE root_id IN (` + roots + `))`,
		`UPDATE r2d_git_project_policy SET epoch=epoch+1 WHERE project_id IN (SELECT project_id FROM r2d_git_project_grant WHERE subject_kind='workspace' AND subject_id=$1::uuid)`,
		`DELETE FROM r2d_git_project_grant WHERE project_id IN (` + projects + `) OR (subject_kind='workspace' AND subject_id=$1::uuid)`,
		`DELETE FROM r2d_git_repository WHERE project_id IN (` + projects + `)`,
		`DELETE FROM r2d_git_project_policy WHERE workspace_id=$1::uuid`,
	} {
		if _, err := db.Exec(ctx, statement, workspace); err != nil {
			return err
		}
	}
	return event(ctx, db, actor, workspace, "workspace_deleted")
}
