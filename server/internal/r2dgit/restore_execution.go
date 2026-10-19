package r2dgit

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"time"
)

type RestoreExecutionApproval struct {
	ID          string    `json:"id"`
	Checkpoint  string    `json:"checkpoint"`
	UserID      string    `json:"user_id"`
	WorkspaceID string    `json:"workspace_id"`
	AgentID     string    `json:"agent_id"`
	RuntimeID   string    `json:"runtime_id"`
	ProjectID   string    `json:"project_id"`
	ExpiresAt   time.Time `json:"expires_at"`
	Signature   []byte    `json:"signature"`
}

func RestoreExecutionBytes(a RestoreExecutionApproval) []byte {
	a.Signature = nil
	raw, _ := json.Marshal(a)
	return append([]byte("multica-restore-execution-v1:"), raw...)
}

// This exact tuple reapproval is independent of project-manager reapproval.
// The verification key is supplied by trusted tooling, never a request body.
func (s *Service) ApproveRestoredExecution(ctx context.Context, a RestoreExecutionApproval, key ed25519.PublicKey) error {
	if s == nil || s.Store == nil || s.Store.Restore == nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, RestoreExecutionBytes(a), a.Signature) || !a.ExpiresAt.After(s.Now()) || a.ExpiresAt.After(s.Now().Add(time.Hour)) {
		return ErrPrincipal
	}
	for _, id := range []string{a.ID, a.Checkpoint, a.UserID, a.WorkspaceID, a.AgentID, a.RuntimeID, a.ProjectID} {
		if uuid.Validate(id) != nil {
			return ErrScope
		}
	}
	return s.Store.transactionAt(ctx, a.Checkpoint, func(tx pgx.Tx) error {
		var bound bool
		if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent a JOIN agent_runtime r ON r.id=a.runtime_id AND r.workspace_id=a.workspace_id JOIN member m ON m.workspace_id=a.workspace_id AND m.user_id=$1 AND m.role IN ('owner','admin','member') WHERE a.id=$2 AND a.runtime_id=$3 AND a.workspace_id=$4 AND a.archived_at IS NULL)`, a.UserID, a.AgentID, a.RuntimeID, a.WorkspaceID).Scan(&bound) != nil || !bound || !activeHuman(ctx, tx, a.UserID) {
			return ErrPrincipal
		}
		_, err := tx.Exec(ctx, `INSERT INTO r2d_git_security_event(id,user_id,subject_id,action,details) VALUES($1,$2,$3,'restore_execution_approved',$4)`, a.ID, a.UserID, a.AgentID, encode(a))
		return err
	})
}
func restoredExecutionAllowed(ctx context.Context, db Database, b TaskBinding, now time.Time) bool {
	var allowed bool
	err := db.QueryRow(ctx, `SELECT NOT EXISTS(SELECT 1 FROM r2d_git_source_quarantine WHERE kind='execution' AND subject_id=$1) OR EXISTS(SELECT 1 FROM r2d_git_security_event e WHERE e.action='restore_execution_approved' AND e.user_id=$2 AND e.subject_id=$3 AND e.details->>'workspace_id'=$1::text AND e.details->>'runtime_id'=$4::text AND e.details->>'project_id'=$5::text AND (e.details->>'expires_at')::timestamptz>$6)`, b.ExecutionWorkspaceID, b.OriginatorUserID, b.AgentID, b.RuntimeID, b.ProjectID, now).Scan(&allowed)
	return err == nil && allowed
}
