package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type humanSessionKey struct{}
type taskSessionKey struct{}
type TaskSession struct{ TaskID, AgentID, WorkspaceID string }

// Protected task credentials never reach generic comment, upload, MCP, search,
// WebSocket or credential-exchange routes. Each allowed handler rebinds the
// authenticated task to the sealed context independently of this route gate.
func protectedGitTaskRoute(r *http.Request) bool {
	parts := strings.Split(r.URL.Path, "/")
	if r.Method != http.MethodPost || len(parts) != 5 || parts[0] != "" || parts[1] != "api" || parts[2] != "git-runs" || (parts[4] != "children" && parts[4] != "outputs") {
		return false
	}
	_, err := uuid.Parse(parts[3])
	return err == nil
}

func TaskSessionFromContext(ctx context.Context) (TaskSession, bool) {
	s, ok := ctx.Value(taskSessionKey{}).(TaskSession)
	return s, ok && s.TaskID != "" && s.AgentID != "" && s.WorkspaceID != ""
}

// HumanSession is produced only by verified JWT authentication. Headers cannot
// supply it. AuthenticatedAt is original login time, never sliding issuance.
type HumanSession struct {
	UserID          string
	AuthenticatedAt time.Time
	SessionID       string
}

func HumanSessionFromContext(ctx context.Context) (HumanSession, bool) {
	s, ok := ctx.Value(humanSessionKey{}).(HumanSession)
	return s, ok && s.UserID != "" && s.SessionID != "" && !s.AuthenticatedAt.IsZero()
}

func humanSessionContext(r *http.Request, s HumanSession) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), humanSessionKey{}, s))
}
