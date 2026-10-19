package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/multica-ai/multica/server/internal/middleware"
	"github.com/multica-ai/multica/server/internal/r2dgit"
)

func gitHuman(w http.ResponseWriter, r *http.Request, recent bool) (string, bool) {
	s, ok := middleware.HumanSessionFromContext(r.Context())
	if !ok || s.AuthenticatedAt.IsZero() || s.AuthenticatedAt.After(time.Now().Add(time.Minute)) {
		writeError(w, http.StatusForbidden, "git_human_session_required")
		return "", false
	}
	if recent && time.Since(s.AuthenticatedAt) > 15*time.Minute {
		writeError(w, http.StatusForbidden, "git_recent_auth_required")
		return "", false
	}
	return s.UserID, true
}

func gitJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid Git request")
		return false
	}
	return true
}

func gitError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, pgx.ErrNoRows), errors.Is(err, r2dgit.ErrScope), errors.Is(err, r2dgit.ErrPrincipal):
		writeError(w, http.StatusNotFound, "git_resource_unavailable")
	case errors.Is(err, r2dgit.ErrIdentity):
		writeError(w, http.StatusConflict, "git_identity_unverified")
	case errors.Is(err, r2dgit.ErrConflict):
		writeError(w, http.StatusConflict, "git_identity_conflict")
	case errors.Is(err, r2dgit.ErrRevoked):
		writeError(w, http.StatusConflict, "git_grant_revoked")
	default:
		writeError(w, http.StatusServiceUnavailable, "git_service_unavailable")
	}
}

func (h *Handler) ListGitIdentities(w http.ResponseWriter, r *http.Request) {
	user, ok := gitHuman(w, r, false)
	if !ok {
		return
	}
	out, err := h.GitSecurity.Profile(r.Context(), user)
	if err != nil {
		gitError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
func (h *Handler) GenerateGitIdentity(w http.ResponseWriter, r *http.Request) {
	user, ok := gitHuman(w, r, true)
	if !ok {
		return
	}
	var request struct {
		ProviderID      string   `json:"provider_id"`
		RequestID       string   `json:"request_id"`
		ConsentProjects []string `json:"consent_project_ids"`
	}
	if !gitJSON(w, r, &request) {
		return
	}
	if _, ok := parseUUIDOrBadRequest(w, request.ProviderID, "provider_id"); !ok {
		return
	}
	if _, ok := parseUUIDOrBadRequest(w, request.RequestID, "request_id"); !ok {
		return
	}
	if len(request.ConsentProjects) > 64 {
		writeError(w, http.StatusBadRequest, "too many consent projects")
		return
	}
	for _, project := range request.ConsentProjects {
		if _, ok := parseUUIDOrBadRequest(w, project, "consent_project_ids"); !ok {
			return
		}
	}
	out, err := h.GitSecurity.Generate(r.Context(), user, request.ProviderID, request.RequestID, request.ConsentProjects)
	if err != nil {
		gitError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}
func gitIdentityParams(w http.ResponseWriter, r *http.Request) (string, uint64, bool) {
	id := chi.URLParam(r, "identityId")
	if _, ok := parseUUIDOrBadRequest(w, id, "identity_id"); !ok {
		return "", 0, false
	}
	generation, err := strconv.ParseUint(chi.URLParam(r, "generation"), 10, 63)
	if err != nil || generation == 0 {
		writeError(w, http.StatusBadRequest, "invalid generation")
		return "", 0, false
	}
	return id, generation, true
}
func (h *Handler) VerifyGitIdentity(w http.ResponseWriter, r *http.Request) {
	user, ok := gitHuman(w, r, true)
	if !ok {
		return
	}
	id, g, ok := gitIdentityParams(w, r)
	if !ok {
		return
	}
	out, err := h.GitSecurity.Verify(r.Context(), user, id, g)
	if err != nil {
		gitError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
func (h *Handler) ActivateGitIdentity(w http.ResponseWriter, r *http.Request) {
	user, ok := gitHuman(w, r, true)
	if !ok {
		return
	}
	id, g, ok := gitIdentityParams(w, r)
	if !ok {
		return
	}
	out, err := h.GitSecurity.Activate(r.Context(), user, id, g)
	if err != nil {
		gitError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
func (h *Handler) RevokeGitIdentity(w http.ResponseWriter, r *http.Request) {
	user, ok := gitHuman(w, r, true)
	if !ok {
		return
	}
	id := chi.URLParam(r, "identityId")
	if _, ok := parseUUIDOrBadRequest(w, id, "identity_id"); !ok {
		return
	}
	if err := h.GitSecurity.Revoke(r.Context(), user, id); err != nil {
		gitError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"locally_revoked": true})
}
func (h *Handler) CleanupGitIdentity(w http.ResponseWriter, r *http.Request) {
	user, ok := gitHuman(w, r, true)
	if !ok {
		return
	}
	id := chi.URLParam(r, "identityId")
	if _, ok := parseUUIDOrBadRequest(w, id, "identity_id"); !ok {
		return
	}
	// Verify ownership before invoking any custody worker.
	profile, err := h.GitSecurity.Profile(r.Context(), user)
	if err != nil {
		gitError(w, err)
		return
	}
	found := false
	for _, key := range profile.Identities {
		if key.ID == id {
			found = true
		}
	}
	if !found {
		gitError(w, pgx.ErrNoRows)
		return
	}
	if err := h.GitSecurity.Cleanup(r.Context(), user, id); err != nil {
		gitError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"cleanup_complete": true})
}

// MountGitAccountRoutes is shared by the production router and auth integration
// tests. It must be mounted inside middleware.Auth, without a workspace gate.
func (h *Handler) MountGitAccountRoutes(r chi.Router) {
 r.Group(func(r chi.Router){
 r.Use(h.GitSourceBoundary)
	r.Get("/api/me/git-identities", h.ListGitIdentities)
	r.Post("/api/me/git-identities", h.GenerateGitIdentity)
	r.Post("/api/me/git-identities/{identityId}/{generation}/verify", h.VerifyGitIdentity)
	r.Post("/api/me/git-identities/{identityId}/{generation}/activate", h.ActivateGitIdentity)
	r.Post("/api/me/git-identities/{identityId}/revoke", h.RevokeGitIdentity)
	r.Post("/api/me/git-identities/{identityId}/cleanup", h.CleanupGitIdentity)
	r.Post("/api/me/git-runs", h.EnqueueGitRun)
	r.Get("/api/me/git-runs/{contextId}", h.GetGitRun)
	r.Post("/api/me/git-runs/{contextId}/revoke", h.RevokeGitRun)
	r.Post("/api/git-runs/{contextId}/children", h.EnqueueGitChild)
	r.Post("/api/git-runs/{contextId}/outputs", h.StoreGitOutput)
	r.Get("/api/me/git-outputs/{outputId}", h.ReadGitOutput)
	r.Put("/api/projects/{projectId}/git-policy/grants", h.SetGitProjectGrant)
 })
}

func validateGitRunRequest(w http.ResponseWriter, r *http.Request) (r2dgit.RunRequest, bool) {
	var request r2dgit.RunRequest
	if !gitJSON(w, r, &request) {
		return request, false
	}
	for name, value := range map[string]string{"agent_id": request.AgentID, "issue_id": request.IssueID, "repository_id": request.RepositoryID} {
		if _, ok := parseUUIDOrBadRequest(w, value, name); !ok {
			return request, false
		}
	}
	return request, true
}
func (h *Handler) EnqueueGitRun(w http.ResponseWriter, r *http.Request) {
	user, ok := gitHuman(w, r, true)
	if !ok {
		return
	}
	request, ok := validateGitRunRequest(w, r)
	if !ok {
		return
	}
	workspace := middleware.ResolveWorkspaceIDFromRequest(r, h.Queries)
	if _, ok := parseUUIDOrBadRequest(w, workspace, "workspace_id"); !ok {
		return
	}
	out, err := h.GitSecurity.EnqueueHuman(r.Context(), user, workspace, request)
	if err != nil {
		gitError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}
func (h *Handler) EnqueueGitChild(w http.ResponseWriter, r *http.Request) {
	token, ok := middleware.TaskSessionFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusForbidden, "git_task_token_required")
		return
	}
	request, ok := validateGitRunRequest(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "contextId")
	if _, ok := parseUUIDOrBadRequest(w, id, "context_id"); !ok {
		return
	}
	out, err := h.GitSecurity.EnqueueChild(r.Context(), id, token.TaskID, token.AgentID, token.WorkspaceID, request)
	if err != nil {
		gitError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}
func (h *Handler) GetGitRun(w http.ResponseWriter, r *http.Request) {
	user, ok := gitHuman(w, r, false)
	if !ok {
		return
	}
	id := chi.URLParam(r, "contextId")
	if _, ok := parseUUIDOrBadRequest(w, id, "context_id"); !ok {
		return
	}
	out, err := h.GitSecurity.GetRun(r.Context(), user, id)
	if err != nil {
		gitError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
func (h *Handler) RevokeGitRun(w http.ResponseWriter, r *http.Request) {
	user, ok := gitHuman(w, r, true)
	if !ok {
		return
	}
	id := chi.URLParam(r, "contextId")
	if _, ok := parseUUIDOrBadRequest(w, id, "context_id"); !ok {
		return
	}
	if err := h.GitSecurity.RevokeRoot(r.Context(), user, id); err != nil {
		gitError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}
func (h *Handler) SetGitProjectGrant(w http.ResponseWriter, r *http.Request) {
	user, ok := gitHuman(w, r, true)
	if !ok {
		return
	}
	id := chi.URLParam(r, "projectId")
	if _, ok := parseUUIDOrBadRequest(w, id, "project_id"); !ok {
		return
	}
	var request struct {
		Kind      string `json:"subject_kind"`
		SubjectID string `json:"subject_id"`
		Role      string `json:"role"`
	}
	if !gitJSON(w, r, &request) {
		return
	}
	if _, ok := parseUUIDOrBadRequest(w, request.SubjectID, "subject_id"); !ok {
		return
	}
	if err := h.GitSecurity.SetProjectGrant(r.Context(), user, id, request.Kind, request.SubjectID, request.Role); err != nil {
		gitError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"updated": true})
}
