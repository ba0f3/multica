package r2dgit

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/multica-ai/multica/server/internal/auth"
)

// CheckControlSession is a pure witnessed reader. It cannot recreate a session
// from its event; the isolated authentication registry must also hold its secret.
// Snapshot finalization shares the current-rights/offboarding rollback fence.
func (s *Service) CheckControlSession(ctx context.Context, user, email, id string) error {
	if s == nil || s.Store == nil || s.Store.Restore == nil || uuid.Validate(user) != nil || uuid.Validate(id) != nil {
		return ErrPrincipal
	}
	return s.Store.readOnly(ctx, func(tx pgx.Tx) error {
		var current string
		var active bool
		if err := tx.QueryRow(ctx, `SELECT email,EXISTS(SELECT 1 FROM r2d_git_security_event WHERE id=$2 AND subject_id=$2 AND user_id=$1 AND action='control_authenticated') FROM "user" WHERE id=$1`, user, id).Scan(&current, &active); err != nil {
			return err
		}
		if !active || current != email || auth.IsTemporarilyDisabledUser(user, current) {
			return ErrPrincipal
		}
		return nil
	})
}
