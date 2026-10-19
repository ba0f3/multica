package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/util"
)

// restrictTaskHistory applies after all hydration. Generic run history is a
// progress surface, never a second source-output reader, even for the originator.
// A whitelist prevents newly added narrative/session fields escaping by default.
func (h *Handler) restrictTaskHistory(ctx context.Context, rows []AgentTaskResponse) error {
	if len(rows) == 0 {
		return nil
	}
	ids := make([]pgtype.UUID, len(rows))
	for i, row := range rows {
		var err error
		ids[i], err = util.ParseUUID(row.ID)
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	classified, err := h.Queries.ListR2DGitTaskProtection(ctx, ids)
	if err != nil {
		return err
	}
	protected := map[string]bool{}
	for _, row := range classified {
		protected[uuidToString(row.TaskID)] = row.Protected
	}
	for i, row := range rows {
		value, found := protected[row.ID]
		if found && !value {
			continue
		}
		rows[i] = AgentTaskResponse{ID: row.ID, AgentID: row.AgentID, RuntimeID: row.RuntimeID, IssueID: row.IssueID, WorkspaceID: row.WorkspaceID, Status: row.Status, Priority: row.Priority, Attempt: row.Attempt, MaxAttempts: row.MaxAttempts, ParentTaskID: row.ParentTaskID, CreatedAt: row.CreatedAt, DispatchedAt: row.DispatchedAt, StartedAt: row.StartedAt, CompletedAt: row.CompletedAt, DeliveredCommentIDs: []string{}}
	}
	return nil
}

func (h *Handler) writeTaskHistory(w http.ResponseWriter, r *http.Request, rows []AgentTaskResponse) {
	w.Header().Set("Cache-Control", "no-store")
	if err := h.restrictTaskHistory(r.Context(), rows); err != nil {
		writeError(w, http.StatusServiceUnavailable, "git_policy_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (h *Handler) writeTaskHistoryRow(w http.ResponseWriter, r *http.Request, status int, row AgentTaskResponse) {
	w.Header().Set("Cache-Control", "no-store")
	rows := []AgentTaskResponse{row}
	if err := h.restrictTaskHistory(r.Context(), rows); err != nil {
		writeError(w, http.StatusServiceUnavailable, "git_policy_unavailable")
		return
	}
	writeJSON(w, status, rows[0])
}
