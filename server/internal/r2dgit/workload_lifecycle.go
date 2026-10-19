package r2dgit

import (
	"context"
	"reflect"

	"github.com/jackc/pgx/v5"
)

// transitionWorkload is a private protected path. It never invokes ordinary task
// completion, comments, notifications, retry, native sessions or result storage.
type WorkloadTerminalSettlement func(context.Context, pgx.Tx, string) error

func (s *Service) transitionWorkload(ctx context.Context, run RunSecurityContext, grant RepositoryGrant, issueID, outputID string, settle WorkloadTerminalSettlement) error {
	return s.Store.transaction(ctx, func(tx pgx.Tx) error {
		r, g, err := s.lockOutputRun(ctx, tx, run.spec.ID)
		if err != nil {
			return err
		}
		if r.spec != run.spec || !reflect.DeepEqual(g.spec, grant.spec) {
			return ErrPrincipal
		}
		var actualIssue string
		if err := tx.QueryRow(ctx, `SELECT issue_id::text FROM agent_task_queue WHERE id=$1`, run.spec.Binding.TaskID).Scan(&actualIssue); err != nil || actualIssue != issueID {
			return ErrPrincipal
		}
		from, to := "queued", "running"
		if outputID != "" {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM r2d_git_output WHERE id=$1 AND context_id=$2)`, outputID, run.spec.ID).Scan(&exists); err != nil || !exists {
				return ErrScope
			}
			from, to = "running", "completed"
		}
		tag, err := tx.Exec(ctx, `UPDATE agent_task_queue SET status=$2,started_at=COALESCE(started_at,now()),completed_at=CASE WHEN $2='completed' THEN now() ELSE NULL END,prepare_lease_expires_at=NULL WHERE id=$1 AND status=$3`, run.spec.Binding.TaskID, to, from)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrConflict
		}
		if to == "completed" {
			if settle == nil {
				return ErrUnavailable
			}
			if err := settle(ctx, tx, run.spec.Binding.TaskID); err != nil {
				return err
			}
			// Queue status is the execution terminal authority. Do not upgrade
			// context SHARE locks here: child admission takes context then queue locks.
		}
		return event(ctx, tx, run.spec.Binding.OriginatorUserID, run.spec.ID, "restricted_workload_"+to)
	})
}

func (s *Service) failWorkload(ctx context.Context, run RunSecurityContext, settle WorkloadTerminalSettlement) error {
	return s.Store.transaction(ctx, func(tx pgx.Tx) error {
		// The immutable side-table spec binds the exact attempt even after expiry
		// or root revocation, when loading an issuable run is no longer possible.
		tag, err := tx.Exec(ctx, `UPDATE agent_task_queue t SET status='failed',completed_at=now(),prepare_lease_expires_at=NULL WHERE t.id=$1 AND t.runtime_id=$2 AND t.status IN ('queued','running') AND EXISTS(SELECT 1 FROM r2d_git_run_context c WHERE c.id=$3 AND c.task_id=t.id AND c.spec=$4::jsonb)`, run.spec.Binding.TaskID, run.spec.Binding.RuntimeID, run.spec.ID, encode(run.spec))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var terminal bool
			if err := tx.QueryRow(ctx, `SELECT t.status IN ('completed','failed','cancelled') FROM agent_task_queue t JOIN r2d_git_run_context c ON c.task_id=t.id WHERE t.id=$1 AND c.id=$2 AND c.spec=$3::jsonb`, run.spec.Binding.TaskID, run.spec.ID, encode(run.spec)).Scan(&terminal); err != nil || !terminal {
				return ErrPrincipal
			}
			return nil
		}
		if settle == nil {
			return ErrUnavailable
		}
		if err := settle(ctx, tx, run.spec.Binding.TaskID); err != nil {
			return err
		}
		return event(ctx, tx, run.spec.Binding.OriginatorUserID, run.spec.ID, "restricted_workload_failed")
	})
}
