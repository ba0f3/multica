package handler

import (
	"log/slog"
	"net/http"

	"github.com/multica-ai/multica/server/internal/middleware"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

// requireDaemonSigningAccess admits only a real daemon token to the Git
// signing routes.
//
// The /api/daemon group also accepts personal access tokens, cloud PATs and
// session JWTs, because most of its routes are safe for a human operator to
// call. Signing is not one of them: a signing lease is a capability to act
// as the task's originator, and only the supervisor that runs the task may
// hold it.
func (h *Handler) requireDaemonSigningAccess(w http.ResponseWriter, r *http.Request) (string, bool) {
	if middleware.DaemonAuthPathFromContext(r.Context()) != middleware.DaemonAuthPathDaemonToken {
		writeErrorCode(w, http.StatusForbidden, "git_daemon_token_required", "Git signing is only available to the daemon that runs the task.")
		return "", false
	}
	daemonID := middleware.DaemonIDFromContext(r.Context())
	if daemonID == "" {
		writeErrorCode(w, http.StatusForbidden, "git_daemon_token_required", "Git signing is only available to the daemon that runs the task.")
		return "", false
	}
	return daemonID, true
}

// requireTaskRuntimeOwnedByDaemon checks that the task runs on a runtime this
// daemon hosts.
//
// Workspace membership is not enough: two daemons can share a workspace, and
// a lease issued for a task on the other machine would let this one sign as
// that task's originator.
func (h *Handler) requireTaskRuntimeOwnedByDaemon(w http.ResponseWriter, r *http.Request, task db.AgentTaskQueue, daemonID string) bool {
	if !task.RuntimeID.Valid {
		writeErrorCode(w, http.StatusForbidden, "git_daemon_token_required", "Git signing is only available to the daemon that runs the task.")
		return false
	}
	runtime, err := h.Queries.GetAgentRuntime(r.Context(), task.RuntimeID)
	if err != nil {
		slog.Warn("git signing: could not load the task runtime", "task_id", task.ID, "error", err)
		writeErrorCode(w, http.StatusForbidden, "git_daemon_token_required", "Git signing is only available to the daemon that runs the task.")
		return false
	}
	if !runtime.DaemonID.Valid || runtime.DaemonID.String != daemonID {
		writeErrorCode(w, http.StatusForbidden, "git_daemon_token_required", "Git signing is only available to the daemon that runs the task.")
		return false
	}
	return true
}
