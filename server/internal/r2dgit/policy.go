package r2dgit

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/multica-ai/multica/server/internal/auth"
)

type ProjectOption struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// Only explicit user/workspace grants confer protected project rights. Team is
// the existing Workspace; resource-workspace membership is not required for a
// direct cross-workspace grant, and workspace governance alone is not a grant.
const projectRoleSQL = `SELECT COALESCE(max(CASE g.role WHEN 'manager' THEN 3 WHEN 'member' THEN 2 WHEN 'viewer' THEN 1 ELSE 0 END),0)
 FROM r2d_git_project_grant g JOIN r2d_git_project_policy policy ON policy.project_id=g.project_id
 JOIN project p ON p.id=policy.project_id AND p.workspace_id=policy.workspace_id
 WHERE p.id=$2 AND NOT EXISTS(SELECT 1 FROM r2d_git_source_quarantine hold WHERE hold.kind='restore' AND hold.subject_id=p.id) AND ((g.subject_kind='user' AND g.subject_id=$1) OR (g.subject_kind='workspace' AND EXISTS(
 SELECT 1 FROM member m WHERE m.workspace_id=g.subject_id AND m.user_id=$1 AND m.role IN ('owner','admin','member'))))`

func activeHuman(ctx context.Context, db Database, userID string) bool {
	var email string
	return db.QueryRow(ctx, `SELECT email FROM "user" WHERE id=$1`, userID).Scan(&email) == nil && !auth.IsTemporarilyDisabledUser(userID, email)
}
func projectRole(ctx context.Context, db Database, userID, projectID string) (int, error) {
	if !activeHuman(ctx, db, userID) {
		return 0, ErrPrincipal
	}
	var rank int
	err := db.QueryRow(ctx, projectRoleSQL, userID, projectID).Scan(&rank)
	return rank, err
}

// SetProjectGrant is the narrow policy-management prerequisite. Workspace
// owners/admins may bootstrap governance; existing explicit project managers
// may manage grants. This never exposes foreign agent/squad/VCS inventory.
func (s *Service) SetProjectGrant(ctx context.Context, actor, projectID, kind, subject, role string) error {
	if kind != "user" && kind != "workspace" {
		return ErrScope
	}
	if role != "viewer" && role != "member" && role != "manager" && role != "" {
		return ErrScope
	}
	return s.Store.transaction(ctx, func(tx pgx.Tx) error {
		var held bool
		if tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM r2d_git_source_quarantine WHERE kind='restore' AND subject_id=$1)`, projectID).Scan(&held) != nil || held {
			return ErrRevoked
		}
		if !activeHuman(ctx, tx, actor) {
			return ErrPrincipal
		}
		var workspace string
		var governor bool
		if err := tx.QueryRow(ctx, `SELECT p.workspace_id::text,EXISTS(SELECT 1 FROM member m WHERE m.workspace_id=p.workspace_id AND m.user_id=$2 AND m.role IN ('owner','admin')) FROM project p JOIN workspace w ON w.id=p.workspace_id WHERE p.id=$1 FOR KEY SHARE OF w`, projectID, actor).Scan(&workspace, &governor); err != nil {
			return ErrScope
		}
		var policyExists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM r2d_git_project_policy WHERE project_id=$1)`, projectID).Scan(&policyExists); err != nil {
			return err
		}
		if !policyExists && !governor {
			return ErrScope
		}
		if kind == "user" && !activeHuman(ctx, tx, subject) {
			return ErrScope
		}
		if kind == "workspace" {
			var id string
			if err := tx.QueryRow(ctx, `SELECT id::text FROM workspace WHERE id=$1 FOR KEY SHARE`, subject).Scan(&id); err != nil {
				return ErrScope
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO r2d_git_project_policy(project_id,workspace_id) VALUES($1,$2) ON CONFLICT(project_id) DO NOTHING`, projectID, workspace); err != nil {
			return err
		}
		// Serialize policy mutations against admission/revocation snapshots.
		var policyWorkspace string
		if err := tx.QueryRow(ctx, `SELECT workspace_id::text FROM r2d_git_project_policy WHERE project_id=$1 FOR UPDATE`, projectID).Scan(&policyWorkspace); err != nil {
			return err
		}
		if policyWorkspace != workspace {
			return ErrScope
		}
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM member WHERE workspace_id=$1 AND user_id=$2 AND role IN ('owner','admin'))`, workspace, actor).Scan(&governor); err != nil {
			return err
		}
		if !governor {
			rank, err := projectRole(ctx, tx, actor, projectID)
			if err != nil || rank < 3 {
				return ErrScope
			}
		}
		workspaces := []string{workspace}
		var users []string
		if kind == "workspace" {
			workspaces = append(workspaces, subject)
		} else {
			users = []string{subject}
		}
		if err := quarantineScopes(ctx, tx, workspaces, users); err != nil {
			return err
		}
		if role == "" {
			if _, err := tx.Exec(ctx, `DELETE FROM r2d_git_project_grant WHERE project_id=$1 AND subject_kind=$2 AND subject_id=$3`, projectID, kind, subject); err != nil {
				return err
			}
		} else {
			if _, err := tx.Exec(ctx, `INSERT INTO r2d_git_project_grant(project_id,subject_kind,subject_id,role) VALUES($1,$2,$3,$4) ON CONFLICT(project_id,subject_kind,subject_id) DO UPDATE SET role=excluded.role`, projectID, kind, subject, role); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE r2d_git_project_policy SET epoch=epoch+1 WHERE project_id=$1`, projectID); err != nil {
			return err
		}
		return event(ctx, tx, actor, projectID, "project_grant_changed")
	})
}

func projectsFor(ctx context.Context, db Database, user string) ([]ProjectOption, error) {
	out := []ProjectOption{}
	rows, err := db.Query(ctx, `SELECT p.id::text,'' AS title FROM project p JOIN r2d_git_project_policy policy ON policy.project_id=p.id AND policy.workspace_id=p.workspace_id WHERE EXISTS(SELECT 1 FROM r2d_git_project_grant g WHERE g.project_id=p.id AND ((g.subject_kind='user' AND g.subject_id=$1) OR (g.subject_kind='workspace' AND EXISTS(SELECT 1 FROM member m WHERE m.workspace_id=g.subject_id AND m.user_id=$1 AND m.role IN ('owner','admin','member'))))) ORDER BY p.id`, user)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var p ProjectOption
		if err := rows.Scan(&p.ID, &p.Title); err != nil {
			return out, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func scopeError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrScope
	}
	return err
}
