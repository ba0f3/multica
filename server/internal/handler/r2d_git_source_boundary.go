package handler

import (
	"context"
	"github.com/google/uuid"
	"net/http"
	"strings"
	"time"
)

// Only these existing routes have their own sealed-source/current-reader
// boundary. New generic APIs default to quarantine, not an inferred public label.
func restrictedGitRoute(r *http.Request) bool {
	p := strings.Split(r.URL.Path, "/")
	if len(p) < 4 || p[0] != "" || p[1] != "api" {
		return false
	}
	if p[2] == "me" {
		switch p[3] {
		case "git-identities":
			if len(p) == 4 {
				return r.Method == "GET" || r.Method == "POST"
			}
			if uuid.Validate(p[4]) != nil || r.Method != "POST" {
				return false
			}
			return (len(p) == 6 && (p[5] == "revoke" || p[5] == "cleanup")) || (len(p) == 7 && (p[6] == "verify" || p[6] == "activate"))
		case "git-runs":
			return (len(p) == 4 && r.Method == "POST") || (len(p) == 5 && r.Method == "GET" && uuid.Validate(p[4]) == nil) || (len(p) == 6 && r.Method == "POST" && uuid.Validate(p[4]) == nil && p[5] == "revoke")
		case "git-outputs":
			return len(p) == 5 && r.Method == "GET" && uuid.Validate(p[4]) == nil
		}
	}
	if p[2] == "git-runs" {
		return len(p) == 5 && r.Method == "POST" && uuid.Validate(p[3]) == nil && (p[4] == "children" || p[4] == "outputs")
	}
	return len(p) == 6 && p[2] == "projects" && uuid.Validate(p[3]) == nil && p[4] == "git-policy" && p[5] == "grants" && r.Method == "PUT"
}

// Unknown historical content is unavailable on generic human/PAT/plugin/daemon
// paths. Quarantined audiences also lose generic cross-workspace aggregations:
// a caller header or current object location is not source provenance.
func (h *Handler) GitSourceBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This fixed liveness response contains no stored data and must survive a DB outage.
		if r.Method == http.MethodGet && r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		if h.GitSecurity == nil {
			writeError(w, 503, "git_policy_unavailable")
			return
		}
		stateCtx, stop := context.WithTimeout(r.Context(), time.Second)
		err := h.GitSecurity.CheckSourceState(stateCtx)
		stop()
		if err != nil {
			writeError(w, 503, "git_policy_unavailable")
			return
		}
		if restrictedGitRoute(r) {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		blocked, err := h.GitSecurity.ReaderlessSourceBlocked(ctx)
		if err != nil {
			writeError(w, 503, "git_policy_unavailable")
			return
		}
		if blocked {
			w.Header().Set("Cache-Control", "no-store")
			writeError(w, 403, "git_historical_source_quarantined")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// These public capabilities cannot identify a current reader. Old signed URLs,
// user/legacy storage keys and plugin capabilities get no compatibility fallback.
func (h *Handler) GitReaderlessBoundary(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.GitSecurity == nil {
			writeError(w, 503, "git_policy_unavailable")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		blocked, err := h.GitSecurity.ReaderlessSourceBlocked(ctx)
		if err != nil {
			writeError(w, 503, "git_policy_unavailable")
			return
		}
		if blocked {
			w.Header().Set("Cache-Control", "no-store")
			writeError(w, 403, "git_historical_source_quarantined")
			return
		}
		next.ServeHTTP(w, r)
	})
}
