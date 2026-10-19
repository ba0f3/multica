//go:build linux

package handler

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/multica-ai/multica/server/internal/r2dgit"
)

func TestR2DGitDurableFreshRetryAndMutationFence(t *testing.T) {
	for _, mode := range []string{"fresh", "revoked-root", "lost-project", "cancelled", "max-attempts", "uncertain-write"} {
		t.Run(mode, func(t *testing.T) {
			f := newGitWorkloadFixture(t)
			s := f.f.h.GitSecurity
			ctx := context.Background()
			original := f.admit(t, f.f.token, f.f.runRequest())
			dbfx.Exec(t, `UPDATE agent_task_queue SET max_attempts=3,status='running' WHERE id=$1`, original.Context.Binding.TaskID)
			op := r2dgit.BoundOperation{UserID: f.f.user, ContextID: original.Context.ID, TaskID: original.Context.Binding.TaskID, AttemptID: original.Context.AttemptID, ProviderID: f.f.provider, RepositoryID: f.f.repo, IdentityID: original.Grant.IdentityID, Generation: original.Grant.CredentialGeneration, Operation: r2dgit.Write, NewObject: strings.Repeat("b", 40)}
			if mode == "uncertain-write" {
				// RootID deliberately omitted: the journal/root join is authoritative.
				if fresh, err := (r2dgit.SQLJournal{DB: testPool}).Begin(ctx, "synthetic-retry-"+uuid.NewString(), op); err != nil || !fresh {
					t.Fatal(err)
				}
			}
			dbfx.Exec(t, `UPDATE agent_task_queue SET status='failed',completed_at=now() WHERE id=$1`, original.Context.Binding.TaskID)
			switch mode {
			case "revoked-root":
				if err := s.RevokeRoot(ctx, f.f.user, original.Context.ID); err != nil {
					t.Fatal(err)
				}
			case "lost-project":
				dbfx.Exec(t, `DELETE FROM r2d_git_project_grant WHERE project_id=$1`, f.f.project)
			case "cancelled":
				dbfx.Exec(t, `UPDATE agent_task_queue SET status='cancelled' WHERE id=$1`, original.Context.Binding.TaskID)
			case "max-attempts":
				dbfx.Exec(t, `UPDATE agent_task_queue SET max_attempts=1 WHERE id=$1`, original.Context.Binding.TaskID)
			}
			retry, err := s.EnqueueRetry(ctx, original.Context.ID)
			if mode != "fresh" {
				if err == nil {
					t.Fatal("ineligible retry admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if retry.Context.RootID != original.Context.RootID || retry.Context.Binding.OriginatorUserID != f.f.user || retry.Context.ID == original.Context.ID || retry.Context.AttemptID == original.Context.AttemptID || retry.Context.Binding.TaskID == original.Context.Binding.TaskID || retry.Context.ExpiresAt.After(original.Context.ExpiresAt) {
				t.Fatal("retry reused or broadened immutable identity")
			}
			if _, err := s.EnqueueRetry(ctx, original.Context.ID); err == nil {
				t.Fatal("duplicate retry admitted")
			}
			if _, err := s.Current(ctx, original.Context, original.Grant); err == nil {
				t.Fatal("old failed predecessor became current")
			}
			if fresh, err := (r2dgit.SQLJournal{DB: testPool}).Begin(ctx, "synthetic-old-writer-"+uuid.NewString(), op); err == nil || fresh {
				t.Fatal("paused old write admitted after retry")
			}
			h, j := f.start(t, retry)
			client, err := r2dgit.NewWorkloadClient(j.socket)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if _, _, err := client.Prepare(ctx, "/usr/bin/git", t.TempDir()); err != nil {
				t.Fatal(err)
			}
			output, err := client.Submit(ctx, "artifact", "fresh retry private result")
			if err != nil {
				t.Fatal(err)
			}
			f.engine.exit(j, 0)
			if result := waitGitWorkload(t, h); result.Err != nil {
				t.Fatal(result.Err)
			}
			path := "/api/me/git-outputs/" + output
			f.f.call(t, f.f.token, "GET", path, nil, 200)
			f.f.call(t, f.f.otherToken, "GET", path, nil, 404)
			if err := s.RevokeRoot(ctx, f.f.user, original.Context.ID); err != nil {
				t.Fatal(err)
			}
			f.f.call(t, f.f.token, "GET", path, nil, 409)
		})
	}
}
