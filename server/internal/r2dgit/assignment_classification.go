package r2dgit

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"time"
)

// This is a trusted migration/review assertion about exact assignment bytes.
// Neither current project membership nor a task payload can classify history.
type AssignmentClassification struct {
	ID           string    `json:"id"`
	ActorID      string    `json:"actor_id"`
	IssueID      string    `json:"issue_id"`
	ProjectID    string    `json:"project_id"`
	ProviderID   string    `json:"provider_id"`
	RepositoryID string    `json:"repository_id"`
	Digest       string    `json:"digest"`
	ExpiresAt    time.Time `json:"expires_at"`
	Signature    []byte    `json:"signature"`
}

func AssignmentClassificationBytes(a AssignmentClassification) []byte {
	a.Signature = nil
	raw, _ := json.Marshal(a)
	return append([]byte("multica-assignment-classification-v1:"), raw...)
}
func WorkloadAssignmentDigest(a WorkloadAssignment) string {
	raw, _ := json.Marshal(a)
	return hexDigest(raw)
}
func (s *Service) RecordAssignmentClassification(ctx context.Context, a AssignmentClassification, key ed25519.PublicKey) error {
	if s == nil || s.Now == nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, AssignmentClassificationBytes(a), a.Signature) || !a.ExpiresAt.After(s.Now()) || a.ExpiresAt.After(s.Now().Add(24*time.Hour)) || len(a.Digest) != 64 {
		return ErrPrincipal
	}
	for _, id := range []string{a.ID, a.ActorID, a.IssueID, a.ProjectID, a.ProviderID, a.RepositoryID} {
		if uuid.Validate(id) != nil {
			return ErrScope
		}
	}
	return s.Store.transaction(ctx, func(tx pgx.Tx) error {
		var assignment WorkloadAssignment
		if !activeHuman(ctx, tx, a.ActorID) || tx.QueryRow(ctx, `SELECT i.title,COALESCE(i.description,'') FROM issue i JOIN r2d_git_repository r ON r.project_id=i.project_id AND r.id=$3 AND r.provider_id=$4 AND r.protected WHERE i.id=$1 AND i.project_id=$2`, a.IssueID, a.ProjectID, a.RepositoryID, a.ProviderID).Scan(&assignment.Title, &assignment.Description) != nil || WorkloadAssignmentDigest(assignment) != a.Digest {
			return ErrScope
		}
		_, err := tx.Exec(ctx, `INSERT INTO r2d_git_security_event(id,user_id,subject_id,action,details) VALUES($1,$2,$3,'assignment_classified',$4)`, a.ID, a.ActorID, a.IssueID, encode(a))
		return err
	})
}

func (s *Service) assignmentClassified(ctx context.Context, db Database, issue string, project string, assignment WorkloadAssignment, grant GrantSpec, key ed25519.PublicKey) error {
	rows, err := db.Query(ctx, `SELECT details FROM r2d_git_security_event WHERE subject_id=$1 AND action='assignment_classified' ORDER BY created_at DESC,id LIMIT 16`, issue)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		var a AssignmentClassification
		if rows.Scan(&raw) != nil || json.Unmarshal(raw, &a) != nil {
			return ErrScope
		}
		if a.IssueID == issue && a.ProjectID == project && a.ProviderID == grant.ProviderID && a.RepositoryID == grant.RepositoryID && a.Digest == WorkloadAssignmentDigest(assignment) && a.ExpiresAt.After(s.Now()) && ed25519.Verify(key, AssignmentClassificationBytes(a), a.Signature) {
			return nil
		}
	}
	return ErrScope
}
