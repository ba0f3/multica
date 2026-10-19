package r2dgit

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"time"
)

// RestoreWitness is held outside the database backup/restore domain. CAS must
// be durable and monotonic: neither startup nor reconciliation may lower it.
// A shared rollback of database AND witness is outside this trust boundary.
type RestoreWitness interface {
	Current(context.Context) (string, error)
	Advance(context.Context, string, string) error
	Locked(context.Context, func(string, func(string) error) error) error
}

type RestoreGuard struct {
	ID      string
	Witness RestoreWitness
	DB      Database
	close   func()
}

func (g *RestoreGuard) Close() {
	if g != nil && g.close != nil {
		g.close()
	}
}

func (s *Service) CheckSourceState(ctx context.Context) error {
	if s == nil || s.Store == nil {
		return ErrUnavailable
	}
	return s.checkRestore(ctx, s.Store.DB)
}

func (g *RestoreGuard) check(ctx context.Context, db Database) error {
	if g == nil || g.Witness == nil || g.DB == nil || uuid.Validate(g.ID) != nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	return g.Witness.Locked(ctx, func(current string, _ func(string) error) error { return g.checkCheckpoint(ctx, current) })
}
func (g *RestoreGuard) checkCheckpoint(ctx context.Context, current string) error {
	var checkpoint string
	var count int
	if g.DB.QueryRow(ctx, `SELECT count(*) FROM r2d_git_restore_checkpoint`).Scan(&count) != nil || count != 1 {
		return ErrRevoked
	}
	if g.DB.QueryRow(ctx, `SELECT checkpoint::text FROM r2d_git_restore_checkpoint WHERE id=$1`, g.ID).Scan(&checkpoint) != nil || checkpoint != current {
		return ErrRevoked
	}
	return nil
}

func (s *Service) checkRestore(ctx context.Context, db Database) error {
	if s == nil || s.Store == nil || db == nil {
		return ErrUnavailable
	}
	if s.Store.Restore == nil {
		var installed bool
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM r2d_git_restore_checkpoint)`).Scan(&installed); err != nil {
			return err
		}
		if installed {
			return ErrUnavailable
		}
		return nil // Explicitly uninitialized legacy instance only.
	}
	return s.Store.Restore.check(ctx, db)
}

// commit holds the witness lock through DB commit. Readers acquire the same
// lock and use a fresh pool view, so normal in-flight writes cannot look like a
// rollback, even if their authorization transaction has an older snapshot.
func (g *RestoreGuard) commit(ctx context.Context, tx pgx.Tx) error { return g.commitAt(ctx, tx, "") }
func (g *RestoreGuard) commitAt(ctx context.Context, tx pgx.Tx, expected string) error {
	if g == nil || g.Witness == nil || g.DB == nil || uuid.Validate(g.ID) != nil {
		return ErrUnavailable
	}
	finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	var readOnly string
	if err := tx.QueryRow(finalCtx, `SHOW transaction_read_only`).Scan(&readOnly); err != nil {
		return err
	}
	if readOnly == "on" {
		return g.Witness.Locked(finalCtx, func(current string, _ func(string) error) error {
			if err := g.checkCheckpoint(finalCtx, current); err != nil {
				return err
			}
			var snapshot string
			if err := tx.QueryRow(finalCtx, `SELECT checkpoint::text FROM r2d_git_restore_checkpoint WHERE id=$1`, g.ID).Scan(&snapshot); err != nil {
				return ErrRevoked
			}
			if snapshot != current {
				return errStaleAuthorizationSnapshot
			}
			return tx.Commit(finalCtx)
		})
	}
	return g.Witness.Locked(finalCtx, func(current string, advance func(string) error) error {
		if expected != "" && current != expected {
			return ErrRevoked
		}
		var old string
		var count int
		if tx.QueryRow(finalCtx, `SELECT count(*) FROM r2d_git_restore_checkpoint`).Scan(&count) != nil || count != 1 {
			return ErrRevoked
		}
		if err := tx.QueryRow(finalCtx, `SELECT checkpoint::text FROM r2d_git_restore_checkpoint WHERE id=$1 FOR UPDATE`, g.ID).Scan(&old); err != nil || old != current {
			return ErrRevoked
		}
		next := uuid.NewString()
		if err := advance(next); err != nil {
			return err
		}
		if _, err := tx.Exec(finalCtx, `UPDATE r2d_git_restore_checkpoint SET checkpoint=$2 WHERE id=$1`, g.ID, next); err != nil {
			return err
		}
		return tx.Commit(finalCtx)
	})
}

// InitializeRestoreGuard is trusted first-install tooling, never an HTTP route.
// It refuses an existing DB anchor; recovery uses destructive invalidation below.
func InitializeRestoreGuard(ctx context.Context, store *Store, g *RestoreGuard) error {
	if store == nil || g == nil || g.Witness == nil || uuid.Validate(g.ID) != nil {
		return ErrUnavailable
	}
	if w, ok := g.Witness.(interface{ InstanceID() string }); ok && w.InstanceID() != g.ID {
		return ErrPrincipal
	}
	if g.DB == nil {
		if err := attachRestoreVerifier(g, store.DB); err != nil {
			return err
		}
	}
	current, err := g.Witness.Current(ctx)
	if err != nil || uuid.Validate(current) != nil {
		return ErrUnavailable
	}
	tx, err := store.Transactions.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('r2d_git_restore_bootstrap',0))`); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO r2d_git_restore_checkpoint(id,checkpoint) SELECT $1,$2 WHERE NOT EXISTS(SELECT 1 FROM r2d_git_restore_checkpoint)`, g.ID, current)
	if err != nil || tag.RowsAffected() != 1 {
		return ErrConflict
	}
	err = tx.Commit(ctx)
	if err == nil {
		store.Restore = g
	}
	return err
}

// ReconcileRestoredDatabase never accepts old credentials or classifications.
// It quarantines all known source scopes, revokes every restored key/run/grant,
// invalidates enrollment acceptance, and advances the external witness. Lost
// post-backup tombstones need not be reconstructed to keep old access denied.
// Fresh consent, keys, admission and operator acceptance are required afterwards.
func (s *Service) ReconcileRestoredDatabase(ctx context.Context) error {
	if s == nil || s.Store == nil || s.Store.Restore == nil {
		return ErrUnavailable
	}
	g := s.Store.Restore
	_, err := g.Witness.Current(ctx)
	if err != nil {
		return ErrUnavailable
	}
	tx, err := s.Store.Transactions.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET LOCAL multica.git_authority_mutation='witnessed'`); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, g.ID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO r2d_git_source_quarantine(kind,subject_id)
 SELECT 'workspace',id FROM workspace UNION SELECT 'audience',id FROM "user" UNION SELECT 'restore',id FROM project UNION SELECT 'execution',id FROM workspace ON CONFLICT DO NOTHING`); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO r2d_git_source_quarantine(kind,subject_id) SELECT 'audience',m.user_id FROM member m JOIN r2d_git_source_quarantine q ON q.kind='workspace' AND q.subject_id=m.workspace_id ON CONFLICT DO NOTHING`); err != nil {
		return err
	}
	for _, query := range []string{
		`UPDATE r2d_git_identity SET revoked=true,active_generation=0,epoch=epoch+1`,
		`UPDATE r2d_git_key SET state='revoked',cleanup_pending=true,diagnostic='git_restore_invalidated'`,
		`UPDATE r2d_git_run_grant SET state='revoked'`,
		`UPDATE r2d_git_run_context SET state='revoked'`,
		`UPDATE agent_task_queue SET status='cancelled',completed_at=clock_timestamp(),error='git_restore_invalidated',result=NULL WHERE status IN ('queued','dispatched','running')`,
		`UPDATE r2d_git_project_policy SET epoch=epoch+1`,
		`DELETE FROM r2d_git_project_grant`,
		`UPDATE r2d_git_security_event SET action='restore_invalidated_runtime' WHERE action='operator_runtime_accepted'`,
		`UPDATE r2d_git_security_event SET action='restore_invalidated_control' WHERE action IN ('control_challenge','control_authenticated')`,
		`UPDATE r2d_git_security_event SET action='restore_invalidated_classification' WHERE action IN ('assignment_classified','restore_execution_approved')`,
		`INSERT INTO r2d_git_key_job(id,user_id,identity_id,generation,kind,idempotency_key) SELECT gen_random_uuid(),i.user_id,k.identity_id,k.generation,'destroy','restore:'||k.identity_id::text||':'||k.generation FROM r2d_git_key k JOIN r2d_git_identity i ON i.id=k.identity_id ON CONFLICT DO NOTHING`,
	} {
		if _, err = tx.Exec(ctx, query); err != nil {
			return err
		}
	}
	finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	return g.Witness.Locked(finalCtx, func(_ string, advance func(string) error) error {
		next := uuid.NewString()
		if err := advance(next); err != nil {
			return err
		}
		if _, err := tx.Exec(finalCtx, `INSERT INTO r2d_git_restore_checkpoint(id,checkpoint) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET checkpoint=EXCLUDED.checkpoint`, g.ID, next); err != nil {
			return err
		}
		return tx.Commit(finalCtx)
	})
}
