package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/r2dgit"
)

func TestR2DGitGitHubCurrentWritePolicy(t *testing.T) {
	for _, mode := range []string{"allowed", "wrong-user", "protected", "default", "rules", "missing", "redirect", "no-account"} {
		t.Run(mode, func(t *testing.T) {
			f := newGitHTTPFixture(t)
			f.ready(t)
			ctx := context.Background()
			s := f.h.GitSecurity
			dbfx.Exec(t, `UPDATE r2d_git_repository SET allow_write=true,write_refs='["refs/heads/task/a"]' WHERE id=$1`, f.repo)
			dbfx.Exec(t, `UPDATE r2d_git_provider SET host='github.com',kind='github' WHERE id=$1`, f.provider)
			dbfx.Exec(t, `UPDATE r2d_git_key k SET account_id='',login='synthetic-a' FROM r2d_git_identity i WHERE i.id=k.identity_id AND i.user_id=$1`, f.user)
			request := f.runRequest()
			request.Operations = []r2dgit.Operation{r2dgit.Read, r2dgit.Write}
			request.WriteRefs = []string{"refs/heads/task/a"}
			var run r2dgit.RunInfo
			f.call(t, f.token, "POST", "/api/me/git-runs", request, 201).JSON(&run)
			dbfx.Exec(t, `UPDATE agent_task_queue SET status='running' WHERE id=$1`, run.Context.Binding.TaskID)
			api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer synthetic-user-a" || r.Method != "GET" {
					t.Error("wrong API authority")
				}
				w.Header().Set("Content-Type", "application/json")
				switch {
				case mode == "redirect":
					http.Redirect(w, r, "https://forbidden.invalid", 307)
				case r.URL.Path == "/user":
					login := "synthetic-a"
					if mode == "wrong-user" {
						login = "admin"
					}
					json.NewEncoder(w).Encode(map[string]any{"id": 42, "login": login})
				case strings.Contains(r.URL.Path, "/rules/branches/"):
					rules := []any{}
					if mode == "rules" {
						rules = append(rules, map[string]any{"type": "required_signatures"})
					}
					json.NewEncoder(w).Encode(rules)
				case strings.Contains(r.URL.Path, "/branches/"):
					if mode == "missing" {
						http.NotFound(w, r)
						return
					}
					json.NewEncoder(w).Encode(map[string]any{"name": "task/a", "protected": mode == "protected"})
				default:
					branch := "main"
					if mode == "default" {
						branch = "task/a"
					}
					json.NewEncoder(w).Encode(map[string]any{"default_branch": branch})
				}
			}))
			defer api.Close()
			user := f.user
			if mode == "no-account" {
				user = f.other
			}
			policy, err := r2dgit.NewGitHubWritePolicy(s, api.URL, api.Client(), []r2dgit.GitHubPolicyAccount{{UserID: user, Token: "synthetic-user-a", ExpiresAt: time.Now().Add(time.Hour)}})
			if err != nil {
				t.Fatal(err)
			}
			s.WritePolicy = policy
			op := r2dgit.BoundOperation{UserID: f.user, ContextID: run.Context.ID, TaskID: run.Context.Binding.TaskID, AttemptID: run.Context.AttemptID, ProviderID: f.provider, RepositoryID: f.repo, IdentityID: run.Grant.IdentityID, Generation: run.Grant.CredentialGeneration, Operation: r2dgit.Write, Ref: "refs/heads/task/a"}
			err = s.CheckGitWritePolicy(ctx, op)
			if mode == "allowed" {
				if err != nil {
					t.Fatal(err)
				}
				if err := s.RevokeRoot(ctx, f.user, run.Context.ID); err != nil {
					t.Fatal(err)
				}
				if s.CheckGitWritePolicy(ctx, op) == nil {
					t.Fatal("revoked source still permits write")
				}
			} else if err == nil {
				t.Fatal("unproven GitHub branch/user policy allowed")
			}
		})
	}
}
