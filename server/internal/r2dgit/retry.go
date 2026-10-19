package r2dgit

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/multica-ai/multica/server/internal/util"
	"github.com/multica-ai/multica/server/pkg/dbid"
)

// EnqueueRetry is trusted worker orchestration, never a public/task-token
// endpoint. It derives the principal solely from the immutable predecessor.
// It does not resume a session, extend consent, or replay an uncertain write.
func (s *Service) EnqueueRetry(ctx context.Context, parentID string) (RunInfo, error) {
	var out RunInfo
	err := s.Store.transaction(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET TRANSACTION ISOLATION LEVEL READ COMMITTED`); err != nil {
			return err
		}
		parent, previous, err := loadRun(ctx, tx, parentID, s.Now())
		if err != nil {
			return err
		}
		b := parent.spec.Binding
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "r2d_git_retry:"+parent.spec.RootID); err != nil {
			return err
		}
		if err = lockRunWorkspaces(ctx, tx, b); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `SELECT id FROM r2d_git_run_context WHERE root_id=$1 ORDER BY id FOR SHARE`, parent.spec.RootID); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `SELECT project_id FROM r2d_git_project_policy WHERE project_id=$1 FOR SHARE`, b.ProjectID); err != nil {
			return err
		}
		var status, issue string
		var attempt, maxAttempts int
		if err = tx.QueryRow(ctx, `SELECT status,issue_id::text,attempt,max_attempts FROM agent_task_queue WHERE id=$1 FOR UPDATE`, b.TaskID).Scan(&status, &issue, &attempt, &maxAttempts); err != nil || status != "failed" || attempt >= maxAttempts {
			return ErrScope
		}
		actual, _, err := loadTaskBinding(ctx, tx, b.TaskID)
		if err != nil || actual != b {
			return ErrPrincipal
		}
		var unsafe bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM r2d_git_run_context WHERE parent_id=$1 AND derivation='retry') OR EXISTS(SELECT 1 FROM r2d_git_operation op JOIN r2d_git_run_context c ON c.id::text=op.spec->>'ContextID' WHERE c.root_id=$2 AND op.spec->>'Operation'='write' AND COALESCE(op.spec->>'NewObject','')<>'' AND op.outcome IN ('pending','indeterminate','succeeded'))`, parentID, parent.spec.RootID).Scan(&unsafe); err != nil || unsafe {
			return ErrConflict
		}
		var count, rootMax int
		if err = tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM r2d_git_run_context WHERE root_id=$1 AND derivation='retry'),t.max_attempts FROM r2d_git_run_context root JOIN agent_task_queue t ON t.id=root.task_id WHERE root.id=$1`, parent.spec.RootID).Scan(&count, &rootMax); err != nil || count+1 >= rootMax {
			return ErrScope
		}
		request := RunRequest{AgentID: b.AgentID, IssueID: issue, RepositoryID: previous.spec.RepositoryID, Operations: previous.Spec().Operations, WriteRefs: previous.Spec().WriteRefs}
		binding, err := resolveNewBinding(ctx, tx, b.OriginatorUserID, b.ExecutionWorkspaceID, request, s.Now())
		if err != nil {
			return err
		}
		binding.TaskID = util.UUIDToString(dbid.NewV7())
		binding.ParentTaskID = b.TaskID
		binding.OriginatorSource = "delegation"
		now := s.Now().UTC()
		run, err := Derive(parent, uuid.NewString(), uuid.NewString(), binding, Retry, now, parent.spec.ExpiresAt)
		if err != nil {
			return err
		}
		spec, err := grantFor(ctx, tx, run, request, now)
		if err != nil {
			return err
		}
		grant, err := NarrowGrant(previous, run, spec, now)
		if err != nil {
			return err
		}
		if err = persistRun(ctx, tx, run, grant, issue, "retry"); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE agent_task_queue SET retry_of_task_id=$2,attempt=$3,max_attempts=$4 WHERE id=$1`, binding.TaskID, b.TaskID, attempt+1, maxAttempts); err != nil {
			return err
		}
		current, err := s.currentIn(ctx, tx, run.spec, grant.spec)
		if err != nil || !currentIssuable(current, run, grant) {
			return ErrRevoked
		}
		if err = event(ctx, tx, b.OriginatorUserID, run.spec.ID, "protected_retry_authorized"); err != nil {
			return err
		}
		out = RunInfo{Context: run.Spec(), Grant: grant.Spec()}
		return nil
	})
	return out, err
}
