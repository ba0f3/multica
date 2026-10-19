package handler

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/middleware"
	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/internal/util"
)

func TestR2DGitS5HistoricalSourceDefaultDeny(t *testing.T) {
	f := newGitHTTPFixture(t)
	const marker = "synthetic-history-source-needle"
	dbfx.Exec(t, `UPDATE issue SET description=$2 WHERE id=$1`, f.issue, marker)
	dbfx.Exec(t, `UPDATE project SET title=$2 WHERE id=$1`, f.project, marker)
	r := chi.NewRouter()
	r.Use(middleware.Auth(f.h.Queries, auth.NewPATCache(nil), nil, nil))
	r.Use(f.h.GitSourceBoundary)
	f.h.MountGitAccountRoutes(r)
	routes := map[string]http.HandlerFunc{
		"/api/issues/search":                      f.h.SearchIssues,
		"/api/search-index/manifest":              f.h.GetSearchIndexManifest,
		"/api/search-index/snapshot":              f.h.GetSearchIndexSnapshot,
		"/api/search-index/changes":               f.h.ListSearchIndexChanges,
		"/api/issues/{id}/comments":               f.h.ListComments,
		"/api/chat/sessions":                      f.h.ListChatSessions,
		"/api/chat/sessions/{id}/messages":        f.h.ListChatMessages,
		"/api/chat/sessions/{id}/messages/page":   f.h.ListChatMessagesPage,
		"/api/chat/sessions/{id}/draft-restores":  f.h.ListChatDraftRestores,
		"/api/inbox":                              f.h.ListInbox,
		"/api/attachments/{id}":                   f.h.GetAttachmentByID,
		"/api/attachments/{id}/download":          f.h.DownloadAttachment,
		"/api/attachments/{id}/download-metadata": f.h.GetAttachmentForDownload,
		"/api/attachments/{id}/content":           f.h.GetAttachmentContent,
	}
	for path, call := range routes {
		r.Get(path, call)
	}
	r.Get("/api/future-source", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(marker)) })
	r.Post("/api/issue-transfer", func(w http.ResponseWriter, _ *http.Request) { t.Error("unclassified transfer reached handler") })
	f.router = r
	for path := range routes {
		path = strings.ReplaceAll(path, "{id}", f.issue)
		out := f.call(t, f.token, "GET", path, nil, 403)
		if strings.Contains(out.Body.String(), marker) {
			t.Fatal("historical source escaped", path)
		}
	}
	// Client-selected scope and a future endpoint do not establish provenance.
	out := f.call(t, f.token, "GET", "/api/future-source", nil, 403)
	if !strings.Contains(out.Body.String(), "quarantined") {
		t.Fatal(out.Body)
	}
	f.call(t, f.token, "POST", "/api/issue-transfer", nil, 403)
	// Public key management remains available, but historical project titles do not.
	out = f.call(t, f.token, "GET", "/api/me/git-identities", nil, 200)
	if strings.Contains(out.Body.String(), marker) || !strings.Contains(out.Body.String(), f.project) {
		t.Fatal("unsafe project option", out.Body)
	}
	// A distinct human cannot infer that unknown cross-workspace history is public.
	user := dbfx.User(t, "Ordinary", "ordinary-"+uuid.NewString()+"@fixture.invalid")
	row, err := f.h.Queries.GetUser(context.Background(), util.MustParseUUID(user))
	if err != nil {
		t.Fatal(err)
	}
	token, err := f.h.issueJWT(row)
	if err != nil {
		t.Fatal(err)
	}
	f.call(t, token, "GET", "/api/future-source", nil, 403)
	// Repository removal cannot remove the historical hold.
	dbfx.Exec(t, `UPDATE r2d_git_repository SET protected=false WHERE id=$1`, f.repo)
	f.call(t, f.token, "GET", "/api/future-source", nil, 403)
}

func TestR2DGitS5ReaderlessHistoricalCapabilitiesDenied(t *testing.T) {
	f := newGitHTTPFixture(t)
	r := chi.NewRouter()
	r.Use(f.h.GitReaderlessBoundary)
	r.Get("/api/attachments/{id}/signed-download", f.h.DownloadAttachmentWithCapability)
	r.Get("/uploads/*", f.h.ServeLocalUpload)
	r.Get("/plugin-surfaces/{token}", f.h.ServePluginSurface)
	r.Get("/api/avatars/{sig}/*", f.h.ServeAvatar)
	id := uuid.NewString()
	for _, path := range []string{attachmentCapabilityPath(id, time.Now()), "/uploads/users/unknown/legacy.txt", "/uploads/workspaces/" + f.workspace + "/history.txt", "/plugin-surfaces/legacy", "/api/avatars/legacy/users/unknown.png"} {
		req := testutil.JSONRequest("GET", path, nil)
		req.Header.Set("X-User-ID", f.other) // A forged header is not a current reader.
		testutil.Call(t, r.ServeHTTP, req).Want(403)
	}
}
