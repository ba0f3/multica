package r2dgit

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type RestoreGovernanceApproval struct {
	ProjectID   string   `json:"project_id"`
	WorkspaceID string   `json:"workspace_id"`
	Checkpoint  string   `json:"checkpoint"`
	Managers    []string `json:"managers"`
	Signature   []byte   `json:"signature"`
}

func RestoreGovernanceBytes(a RestoreGovernanceApproval) []byte {
	a.Signature = nil
	raw, _ := json.Marshal(a)
	return append([]byte("multica-restore-governance-v1:"), raw...)
}

// Reapproval is trusted operator tooling with an out-of-band verification key,
// not a human/session API. Project managers receive no workspace-admin role. It never declassifies historical generic surfaces.
func (s *Service) ApproveRestoredProject(ctx context.Context, a RestoreGovernanceApproval, key ed25519.PublicKey) error {
	if s == nil || s.Store == nil || s.Store.Restore == nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, RestoreGovernanceBytes(a), a.Signature) || uuid.Validate(a.ProjectID) != nil || uuid.Validate(a.WorkspaceID) != nil || len(a.Managers) == 0 || len(a.Managers) > 16 {
		return ErrPrincipal
	}
	current, err := s.Store.Restore.Witness.Current(ctx)
	if err != nil || current != a.Checkpoint {
		return ErrRevoked
	}
	return s.Store.transactionAt(ctx, a.Checkpoint, func(tx pgx.Tx) error {
		var workspace string
		if tx.QueryRow(ctx, `SELECT workspace_id::text FROM project WHERE id=$1 FOR UPDATE`, a.ProjectID).Scan(&workspace) != nil || workspace != a.WorkspaceID {
			return ErrScope
		}
		tag, err := tx.Exec(ctx, `DELETE FROM r2d_git_source_quarantine WHERE kind='restore' AND subject_id=$1`, a.ProjectID)
		if err != nil || tag.RowsAffected() != 1 {
			return ErrConflict
		}
		if _, err = tx.Exec(ctx, `UPDATE member SET role='member' WHERE workspace_id=$1 AND role IN ('owner','admin')`, workspace); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, user := range a.Managers {
			if uuid.Validate(user) != nil || seen[user] || !activeHuman(ctx, tx, user) {
				return ErrPrincipal
			}
			seen[user] = true
			if _, err = tx.Exec(ctx, `INSERT INTO r2d_git_project_grant(project_id,subject_kind,subject_id,role) VALUES($1,'user',$2,'manager') ON CONFLICT(project_id,subject_kind,subject_id) DO UPDATE SET role='manager'`, a.ProjectID, user); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `UPDATE r2d_git_project_policy SET epoch=epoch+1 WHERE project_id=$1`, a.ProjectID)
		return err
	})
}

// Legacy/background authority edits in quarantined scopes are denied by DB
// triggers. Reviewed trusted services use this transaction so the external
// witness also records membership/offboarding/binding changes before commit.
func (s *Service) MutateAuthority(ctx context.Context, fn func(Database) error) error {
	if s == nil || s.Store == nil || s.Store.Restore == nil || fn == nil {
		return ErrUnavailable
	}
	return s.Store.transaction(ctx, func(tx pgx.Tx) error { return fn(tx) })
}
