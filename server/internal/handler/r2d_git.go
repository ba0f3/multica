package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/multica-ai/multica/server/internal/middleware"
	"github.com/multica-ai/multica/server/internal/r2dgit"
)

// gitRecentAuthWindow bounds how long a session may be considered freshly
// authenticated. A credential change is a high-consequence action, so it
// asks the user to prove their session is current.
const gitRecentAuthWindow = 15 * time.Minute

// gitHumanSession resolves the acting human of a credential request.
//
// The user id never comes from the request body or a path segment: it is the
// id of the session that authenticated the call. A request without a human
// session — a personal access token, a task token, an unauthenticated call —
// is refused.
func gitHumanSession(w http.ResponseWriter, r *http.Request, requireRecent bool) (string, bool) {
	session, ok := middleware.HumanSessionFromContext(r.Context())
	if !ok {
		writeErrorCode(w, http.StatusForbidden, "git_human_session_required", "This action needs a signed-in user session.")
		return "", false
	}
	if requireRecent && time.Since(session.AuthenticatedAt) > gitRecentAuthWindow {
		writeErrorCode(w, http.StatusForbidden, "git_recent_auth_required", "Please sign in again to confirm this change.")
		return "", false
	}
	return session.UserID, true
}

// gitService resolves the credential service, refusing the request when the
// deployment has no credential custody configured.
//
// A deployment without custody must not look like a working one: it answers
// that the capability is unavailable instead of pretending a key was created.
func (h *Handler) gitService(w http.ResponseWriter) (*r2dgit.Service, bool) {
	if h == nil || h.GitSecurity == nil {
		writeErrorCode(w, http.StatusServiceUnavailable, "git_service_unavailable", "Git credentials are not configured on this server.")
		return nil, false
	}
	return h.GitSecurity, true
}

// gitServiceError maps a credential error to a response.
//
// A credential that belongs to somebody else is reported as unavailable
// rather than forbidden: a forbidden answer would confirm that the id exists.
func gitServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, r2dgit.ErrUnavailable):
		writeErrorCode(w, http.StatusServiceUnavailable, "git_service_unavailable", "Git credentials are not available right now.")
	case errors.Is(err, r2dgit.ErrPrincipal):
		// Reached only by the daemon route: the browser route rejects a
		// missing session before the service is called.
		writeErrorCode(w, http.StatusForbidden, "git_principal_unproven", "This run has no provable human owner.")
	case errors.Is(err, r2dgit.ErrProviderNotFound):
		writeErrorCode(w, http.StatusNotFound, "git_provider_not_configured", "That Git host is not configured or is disabled.")
	case errors.Is(err, r2dgit.ErrScope):
		writeErrorCode(w, http.StatusNotFound, "git_resource_unavailable", "That Git credential is not available.")
	case errors.Is(err, r2dgit.ErrIdentity):
		writeErrorCode(w, http.StatusConflict, "git_identity_unverified", "This Git key is not verified yet.")
	case errors.Is(err, r2dgit.ErrConflict):
		writeErrorCode(w, http.StatusConflict, "git_identity_conflict", "That Git key request is already in progress.")
	case errors.Is(err, r2dgit.ErrRevoked):
		writeErrorCode(w, http.StatusConflict, "git_grant_revoked", "That Git key was revoked.")
	case errors.Is(err, r2dgit.ErrProvider):
		writeErrorCode(w, http.StatusBadGateway, "git_provider_unavailable", "The Git provider did not answer as expected.")
	default:
		writeErrorCode(w, http.StatusInternalServerError, "git_service_unavailable", "Git credentials are not available right now.")
	}
}

// gitJSONBody decodes a request body, rejecting unknown fields.
//
// An unknown field is a client that sends something the server does not
// understand. Refusing it keeps a caller from believing a field it sent —
// a user id, a scope — had an effect.
func gitJSONBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeErrorCode(w, http.StatusBadRequest, "git_invalid_request", "That request body could not be read.")
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeErrorCode(w, http.StatusBadRequest, "git_invalid_request", "That request body could not be read.")
		return false
	}
	return true
}

// ListGitIdentities returns the caller's Git credentials and the providers
// they may use.
func (h *Handler) ListGitIdentities(w http.ResponseWriter, r *http.Request) {
	userID, ok := gitHumanSession(w, r, false)
	if !ok {
		return
	}
	service, ok := h.gitService(w)
	if !ok {
		return
	}
	profile, err := service.Profile(r.Context(), userID)
	if err != nil {
		gitServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

// GenerateGitIdentity creates a new key generation for a provider.
//
// The response carries the public key and nothing else: the private key
// stays in the encrypted custody store and is never rendered to a browser.
func (h *Handler) GenerateGitIdentity(w http.ResponseWriter, r *http.Request) {
	userID, ok := gitHumanSession(w, r, false)
	if !ok {
		return
	}
	service, ok := h.gitService(w)
	if !ok {
		return
	}
	var body struct {
		ProviderID string `json:"provider_id"`
		RequestID  string `json:"request_id"`
	}
	if !gitJSONBody(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.ProviderID) == "" || strings.TrimSpace(body.RequestID) == "" {
		writeErrorCode(w, http.StatusBadRequest, "git_invalid_request", "A provider and a request id are required.")
		return
	}
	identity, err := service.Generate(r.Context(), userID, body.ProviderID, body.RequestID, nil)
	if err != nil {
		gitServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, identity)
}

// VerifyGitIdentity proves a key authenticates the user's provider account
// and makes it the active generation.
func (h *Handler) VerifyGitIdentity(w http.ResponseWriter, r *http.Request) {
	userID, ok := gitHumanSession(w, r, false)
	if !ok {
		return
	}
	service, ok := h.gitService(w)
	if !ok {
		return
	}
	identityID := chi.URLParam(r, "identityId")
	generation, err := strconv.ParseUint(chi.URLParam(r, "generation"), 10, 64)
	if err != nil || generation == 0 {
		writeErrorCode(w, http.StatusBadRequest, "git_invalid_request", "That key generation is not valid.")
		return
	}
	identity, err := service.Verify(r.Context(), userID, identityID, generation)
	if err != nil {
		switch {
		case errors.Is(err, r2dgit.ErrIdentity):
			writeErrorCode(w, http.StatusConflict, "git_identity_unverified",
				"Multica could not authenticate this key over SSH. On Gitea, finish key verification in the web UI (paste the signature), confirm the public key is on your account, wait a minute, then try again.")
		case errors.Is(err, r2dgit.ErrProvider):
			writeErrorCode(w, http.StatusBadGateway, "git_provider_unreachable",
				"Multica could not reach that Git host over SSH. Ask an administrator to check MULTICA_GIT_PROVIDERS, host fingerprints, and that the API server can open the SSH port.")
		default:
			gitServiceError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, identity)
}

// SignGiteaGitIdentityVerification signs Gitea's SSH key verification token
// with the stored private key and returns the armored signature for pasting
// into Gitea.
func (h *Handler) SignGiteaGitIdentityVerification(w http.ResponseWriter, r *http.Request) {
	userID, ok := gitHumanSession(w, r, false)
	if !ok {
		return
	}
	service, ok := h.gitService(w)
	if !ok {
		return
	}
	identityID := chi.URLParam(r, "identityId")
	generation, err := strconv.ParseUint(chi.URLParam(r, "generation"), 10, 64)
	if err != nil || generation == 0 {
		writeErrorCode(w, http.StatusBadRequest, "git_invalid_request", "That key generation is not valid.")
		return
	}
	var body struct {
		Token string `json:"token"`
	}
	if !gitJSONBody(w, r, &body) {
		return
	}
	signature, err := service.SignGiteaSSHKeyVerification(r.Context(), userID, identityID, generation, body.Token)
	if err != nil {
		switch {
		case errors.Is(err, r2dgit.ErrScope):
			writeErrorCode(w, http.StatusBadRequest, "git_invalid_request",
				"Enter the verification token from Gitea and make sure this key is still pending verification.")
		case errors.Is(err, r2dgit.ErrRevoked):
			writeErrorCode(w, http.StatusConflict, "git_grant_revoked", "This Git key was revoked.")
		default:
			gitServiceError(w, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"signature": signature})
}

// RevokeGitIdentity stops the use of a key and destroys its stored secret.
//
// Revocation takes effect locally even when the custody store cannot be
// reached; the outstanding cleanup is retried in the background.
func (h *Handler) RevokeGitIdentity(w http.ResponseWriter, r *http.Request) {
	userID, ok := gitHumanSession(w, r, true)
	if !ok {
		return
	}
	service, ok := h.gitService(w)
	if !ok {
		return
	}
	identityID := chi.URLParam(r, "identityId")
	if err := service.Revoke(r.Context(), userID, identityID); err != nil {
		gitServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"locally_revoked": true})
}
