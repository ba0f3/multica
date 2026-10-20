package handler

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
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
	taskID := chi.URLParam(r, "taskId")
	if _, _, ok := h.requireDaemonTaskAccessWithWorkspace(w, r, taskID); !ok {
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

	lease, err := service.OpenSigningLease(r.Context(), taskID, body.ProviderID)
	if err != nil {
		gitServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, lease)
}

// SignGitData signs bytes with the key a lease is bound to.
//
// The private key never leaves the custody store: the daemon forwards the
// bytes and receives the signature, so the runner can use the key without
// ever holding it.
func (h *Handler) SignGitData(w http.ResponseWriter, r *http.Request) {
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

	signature, err := service.Sign(r.Context(), body.LeaseID, payload)
	if err != nil {
		gitServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"signature": base64.StdEncoding.EncodeToString(signature),
	})
}
