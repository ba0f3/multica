package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/multica-ai/multica/server/internal/middleware"
	"github.com/multica-ai/multica/server/internal/r2dgit"
)

func (h *Handler) StoreGitOutput(w http.ResponseWriter, r *http.Request) {
	task, ok := middleware.TaskSessionFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusForbidden, "git_task_session_required")
		return
	}
	contextID := chi.URLParam(r, "contextId")
	if _, ok := parseUUIDOrBadRequest(w, contextID, "context_id"); !ok {
		return
	}
	var request struct {
		Kind    string `json:"kind"`
		Content string `json:"content"`
	}
	if !gitJSON(w, r, &request) {
		return
	}
	id, err := h.GitSecurity.StoreOutput(r.Context(), contextID, task.TaskID, task.AgentID, task.WorkspaceID, request.Kind, []byte(request.Content))
	if err != nil {
		gitError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func (h *Handler) ReadGitOutput(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	user, ok := gitHuman(w, r, false)
	if !ok {
		return
	}
	id := chi.URLParam(r, "outputId")
	if _, ok := parseUUIDOrBadRequest(w, id, "output_id"); !ok {
		return
	}
	sink, err := newGitHTTPOutputSink(w)
	if err != nil {
		gitError(w, err)
		return
	}
	if err := h.GitSecurity.DeliverOutput(r.Context(), user, id, sink); err != nil {
		if sink.begun {
			panic(http.ErrAbortHandler)
		}
		gitError(w, err)
	}
}

type gitHTTPOutputSink struct {
	writer     http.ResponseWriter
	controller *http.ResponseController
	begun      bool
	flush      func() error
}

// Chi status/metrics writers pass data through but their errorless Flush hides
// transport failures. Keep writes/accounting on the original writer and require
// the underlying trusted controller's FlushError. Unknown buffering adapters deny.
func newGitHTTPOutputSink(w http.ResponseWriter) (*gitHTTPOutputSink, error) {
	controlled := w
	for range 16 {
		if wrapped, ok := controlled.(chimw.WrapResponseWriter); ok {
			controlled = wrapped.Unwrap()
			continue
		}
		flush, ok := controlled.(interface{ FlushError() error })
		if !ok {
			return nil, r2dgit.ErrRuntime
		}
		if _, ok := controlled.(interface{ SetWriteDeadline(time.Time) error }); !ok {
			return nil, r2dgit.ErrRuntime
		}
		return &gitHTTPOutputSink{writer: w, controller: http.NewResponseController(controlled), flush: flush.FlushError}, nil
	}
	return nil, r2dgit.ErrRuntime
}

func (s *gitHTTPOutputSink) SetWriteDeadline(deadline time.Time) error {
	return s.controller.SetWriteDeadline(deadline)
}
func (s *gitHTTPOutputSink) Begin(size int) {
	s.writer.Header().Set("Content-Type", "application/octet-stream")
	s.writer.Header().Set("Content-Length", strconv.Itoa(size))
	s.writer.Header().Set("Content-Disposition", `attachment; filename="restricted-output.bin"`)
	s.writer.Header().Set("X-Content-Type-Options", "nosniff")
	s.begun = true
	s.writer.WriteHeader(http.StatusOK)
}
func (s *gitHTTPOutputSink) Write(body []byte) (int, error) {
	n, err := s.writer.Write(body)
	if err != nil {
		return n, err
	}
	return n, s.flush()
}

// Legacy daemon reports fan out through comments/chat/WebSocket/notifications.
// Protected source must enter only the restricted store, before any persistence
// or broadcast. This gate also applies if a daemon bypasses task-token auth.
func (h *Handler) denyProtectedGitReport(w http.ResponseWriter, r *http.Request, taskID string) bool {
	if err := h.GitSecurity.CheckSourceState(r.Context()); err != nil {
		writeError(w, 503, "git_policy_unavailable")
		return true
	}
	id, ok := parseUUIDOrBadRequest(w, taskID, "task_id")
	if !ok {
		return true
	}
	protected, err := h.Queries.IsR2DGitProtectedTask(r.Context(), id)
	if err != nil || !protected.Valid {
		writeError(w, http.StatusServiceUnavailable, "git_policy_unavailable")
		return true
	}
	if protected.Bool {
		writeError(w, http.StatusForbidden, "git_restricted_output_required")
		return true
	}
	return false
}
