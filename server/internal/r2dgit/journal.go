package r2dgit

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
)

// SQLJournal records intent before source delivery and rejects replay after a
// worker restart. Pending/indeterminate rows require reconciliation, not retry.
type SQLJournal struct {
	DB      Database
	Restore *RestoreGuard
}

func (j SQLJournal) Lookup(ctx context.Context, id string) (BoundOperation, string, error) {
	var op BoundOperation
	var raw []byte
	var outcome string
	if j.Restore != nil {
		if err := j.Restore.check(ctx, j.DB); err != nil {
			return op, "", err
		}
	}
	if j.DB == nil || !nonempty(id) || len(id) > 128 {
		return op, "", ErrAudit
	}
	if j.DB.QueryRow(ctx, `SELECT spec,outcome FROM r2d_git_operation WHERE id=$1`, id).Scan(&raw, &outcome) != nil {
		return op, "", ErrAudit
	}
	if json.Unmarshal(raw, &op) != nil {
		return BoundOperation{}, "", ErrAudit
	}
	return op, outcome, nil
}

func (j SQLJournal) Begin(ctx context.Context, id string, op BoundOperation) (bool, error) {
	if j.DB == nil || len(id) > 128 || !nonempty(id, op.UserID, op.ContextID, op.TaskID, op.AttemptID, op.ProviderID, op.RepositoryID, op.IdentityID) || op.Generation == 0 || (op.Operation != Read && op.Operation != Write) {
		return false, ErrAudit
	}
	spec, err := json.Marshal(op)
	if err != nil {
		return false, ErrAudit
	}
	database := j.DB
	var tx pgx.Tx
	if op.Operation == Write || j.Restore != nil {
		transactions, ok := j.DB.(Transactions)
		if !ok {
			return false, ErrAudit
		}
		tx, err = transactions.Begin(ctx)
		if err != nil {
			return false, ErrAudit
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, `SET TRANSACTION ISOLATION LEVEL READ COMMITTED`); err != nil {
			return false, ErrAudit
		}
		if j.Restore != nil {
			if err = j.Restore.check(ctx, tx); err != nil {
				return false, err
			}
		}
		if op.Operation == Write {
			var root string
			if err = tx.QueryRow(ctx, `SELECT root_id::text FROM r2d_git_run_context WHERE id=$1 AND task_id=$2 AND authorizing_user_id=$3 AND spec->>'attempt_id'=$4`, op.ContextID, op.TaskID, op.UserID, op.AttemptID).Scan(&root); err != nil {
				return false, ErrAudit
			}
			if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "r2d_git_retry:"+root); err != nil {
				return false, ErrAudit
			}
			var live bool
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM r2d_git_run_context c JOIN agent_task_queue t ON t.id=c.task_id JOIN r2d_git_run_context root ON root.id=c.root_id WHERE c.id=$1 AND c.state='active' AND root.state='active' AND t.status='running')`, op.ContextID).Scan(&live); err != nil || !live {
				return false, ErrRevoked
			}
		}
		database = tx
	}
	result, err := database.Exec(ctx, `INSERT INTO r2d_git_operation(id,spec) VALUES($1,$2) ON CONFLICT(id) DO NOTHING`, id, spec)
	if err != nil {
		return false, ErrAudit
	}
	if tx != nil {
		if j.Restore != nil {
			if err = j.Restore.commit(ctx, tx); err != nil {
				return false, err
			}
			return result.RowsAffected() == 1, nil
		}
		if err = tx.Commit(ctx); err != nil {
			return false, ErrAudit
		}
	}
	return result.RowsAffected() == 1, nil
}

func (j SQLJournal) Complete(ctx context.Context, id, outcome string) error {
	if j.DB == nil || (outcome != "succeeded" && outcome != "denied" && outcome != "indeterminate") {
		return ErrAudit
	}
	if j.Restore != nil {
		transactions, ok := j.DB.(Transactions)
		if !ok {
			return ErrAudit
		}
		tx, err := transactions.Begin(ctx)
		if err != nil {
			return ErrAudit
		}
		defer tx.Rollback(ctx)
		if err = j.Restore.check(ctx, tx); err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `UPDATE r2d_git_operation SET outcome=$2 WHERE id=$1 AND (outcome='pending' OR outcome=$2)`, id, outcome)
		if err != nil || result.RowsAffected() != 1 {
			return ErrAudit
		}
		return j.Restore.commit(ctx, tx)
	}
	result, err := j.DB.Exec(ctx, `UPDATE r2d_git_operation SET outcome=$2 WHERE id=$1 AND (outcome='pending' OR outcome=$2)`, id, outcome)
	if err != nil || result.RowsAffected() != 1 {
		return ErrAudit
	}
	return nil
}
