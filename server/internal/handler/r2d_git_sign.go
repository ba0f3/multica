package handler

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/r2dgit"
)

// maxGitSignaturePayload bounds the bytes a daemon may ask the server to
// sign.
//
// A Git signature covers a request the runner assembles itself, so the
// payload is small. The cap keeps a daemon from turning the server into a
// bulk signing oracle.
const maxGitSignaturePayload = 64 << 10

// OpenGitSigningLease issues a signing permission for a task attempt.
//
// The daemon asks; the server decides. The key is chosen from the task's
// authenticated originator, so a daemon cannot name the user, the identity
// or the generation whose key signs the run.
func (h *Handler) OpenGitSigningLease(w http.ResponseWriter, r *http.Request) {
	daemonID, ok := h.requireDaemonSigningAccess(w, r)
	if !ok {
		return
	}
	taskID := chi.URLParam(r, "taskId")
	task, _, ok := h.requireDaemonTaskAccessWithWorkspace(w, r, taskID)
	if !ok {
		return
	}
	if !h.requireTaskRuntimeOwnedByDaemon(w, r, task, daemonID) {
		return
	}
	if !taskEligibleForNewSigningLease(task) {
		writeErrorCode(w, http.StatusForbidden, "git_signing_unavailable", "Git signing is not available for this task.")
		return
	}
	service, ok := h.gitService(w)
	if !ok {
		return
	}
	var body struct {
		ProviderID string `json:"provider_id"`
	}
	if !gitJSONBody(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.ProviderID) == "" {
		writeErrorCode(w, http.StatusBadRequest, "git_invalid_request", "A provider id is required.")
		return
	}

	lease, err := service.OpenSigningLease(r.Context(), taskID, taskSigningAttemptID(task.Attempt, task.DispatchedAt), body.ProviderID, daemonID)
	if err != nil {
		gitServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, lease)
}

func taskSigningAttemptID(attempt int32, dispatchedAt pgtype.Timestamptz) string {
	if dispatchedAt.Valid {
		return fmt.Sprintf("%d:%d", attempt, dispatchedAt.Time.UTC().UnixNano())
	}
	return fmt.Sprintf("%d:undispatched", attempt)
}

func (h *Handler) requireGitSigningLeaseTaskEligible(w http.ResponseWriter, r *http.Request, service *r2dgit.Service, leaseID, daemonID string) bool {
	taskID, leaseAttemptID, err := service.LeaseScope(r.Context(), leaseID, daemonID)
	if err != nil {
		gitServiceError(w, err)
		return false
	}
	task, _, ok := h.requireDaemonTaskAccessWithWorkspace(w, r, taskID)
	if !ok {
		return false
	}
	if !h.requireTaskRuntimeOwnedByDaemon(w, r, task, daemonID) {
		return false
	}
	if !taskEligibleForNewSigningLease(task) {
		writeErrorCode(w, http.StatusForbidden, "git_signing_unavailable", "Git signing is not available for this task.")
		return false
	}
	if leaseAttemptID != taskSigningAttemptID(task.Attempt, task.DispatchedAt) {
		writeErrorCode(w, http.StatusForbidden, "git_signing_stale_attempt", "Git signing lease belongs to an older task attempt.")
		return false
	}
	return true
}

// SignGitData signs bytes with the key a lease is bound to.
//
// The private key never leaves the custody store: the daemon forwards the
// bytes and receives the signature, so the runner can use the key without
// ever holding it.
func (h *Handler) SignGitData(w http.ResponseWriter, r *http.Request) {
	daemonID, ok := h.requireDaemonSigningAccess(w, r)
	if !ok {
		return
	}
	service, ok := h.gitService(w)
	if !ok {
		return
	}
	var body struct {
		LeaseID string `json:"lease_id"`
		Data    string `json:"data"`
	}
	if !gitJSONBody(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.LeaseID) == "" {
		writeErrorCode(w, http.StatusBadRequest, "git_invalid_request", "A lease id is required.")
		return
	}
	if len(body.Data) > base64.StdEncoding.EncodedLen(maxGitSignaturePayload) {
		writeErrorCode(w, http.StatusBadRequest, "git_invalid_request", "The payload to sign is too large.")
		return
	}
	payload, err := base64.StdEncoding.DecodeString(body.Data)
	if err != nil {
		writeErrorCode(w, http.StatusBadRequest, "git_invalid_request", "The payload to sign is not valid base64.")
		return
	}
	if len(payload) > maxGitSignaturePayload {
		writeErrorCode(w, http.StatusBadRequest, "git_invalid_request", "The payload to sign is too large.")
		return
	}
	if !h.requireGitSigningLeaseTaskEligible(w, r, service, body.LeaseID, daemonID) {
		return
	}

	signature, err := service.Sign(r.Context(), body.LeaseID, daemonID, payload)
	if err != nil {
		gitServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"signature": base64.StdEncoding.EncodeToString(signature),
	})
}

// RenewGitSigningLease keeps a running daemon's signing permission alive.
func (h *Handler) RenewGitSigningLease(w http.ResponseWriter, r *http.Request) {
	daemonID, ok := h.requireDaemonSigningAccess(w, r)
	if !ok {
		return
	}
	service, ok := h.gitService(w)
	if !ok {
		return
	}
	var body struct {
		LeaseID string `json:"lease_id"`
	}
	if !gitJSONBody(w, r, &body) {
		return
	}
	if !h.requireGitSigningLeaseTaskEligible(w, r, service, body.LeaseID, daemonID) {
		return
	}
	if err := service.RenewSigningLease(r.Context(), body.LeaseID, daemonID); err != nil {
		gitServiceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
