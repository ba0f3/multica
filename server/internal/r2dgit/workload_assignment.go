package r2dgit

import (
	"context"
	"encoding/json"
)

const maxAssignmentBytes = 16 << 10

// WorkloadAssignment is a prepare-time issue snapshot. No comments, attachments,
// arbitrary commands, environment, identity overrides or native memory enter it.
type WorkloadAssignment struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

func loadWorkloadAssignment(ctx context.Context, db Database, run RunSecurityContext) (WorkloadAssignment, string, error) {
	var assignment WorkloadAssignment
	var issue string
	b := run.spec.Binding
	err := db.QueryRow(ctx, `SELECT i.title,COALESCE(i.description,''),i.id::text FROM agent_task_queue t JOIN issue i ON i.id=t.issue_id WHERE t.id=$1 AND i.project_id=$2 AND i.workspace_id=$3`, b.TaskID, b.ProjectID, b.ResourceWorkspaceID).Scan(&assignment.Title, &assignment.Description, &issue)
	if err != nil {
		return assignment, "", ErrScope
	}
	raw, err := json.Marshal(assignment)
	if err != nil || len(raw) > maxAssignmentBytes || !nonempty(assignment.Title) {
		return WorkloadAssignment{}, "", ErrScope
	}
	return assignment, issue, nil
}
