package service

import (
	"context"
	"github.com/jackc/pgx/v5"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"strings"
	"testing"

	"github.com/google/uuid"
	dbfx "github.com/multica-ai/multica/server/internal/testutil"
)

type recoveryPolicyOutage struct{ db.DBTX }

func (d recoveryPolicyOutage) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if strings.Contains(sql, "ListR2DGitTaskProtection") {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return d.DBTX.Query(ctx, sql, args...)
}

func TestR2DGitPendingRecoveryDoesNotCrossProtectedBoundary(t *testing.T) {
	for _, mode := range []string{"ordinary", "protected-worker", "protected-coordinator", "policy-outage"} {
		t.Run(mode, func(t *testing.T) {
			f, svc := seedDelegatedFailureFixture(t)
			ctx := context.Background()
			fx := dbfx.New(f.pool, f.workspaceID, f.userID)
			failed := f.insertWorkerTask(t, "failed", "comment", 1, 2)
			target, created, err := svc.ensureDelegatedFailureRecoveryComment(ctx, failed)
			if err != nil || target == nil || !created {
				t.Fatal("ordinary outbox positive control", err)
			}
			// Protection is registered only AFTER a genuine pending recovery was
			// persisted, modelling replay after the source's trust boundary changed.
			if mode == "protected-worker" || mode == "protected-coordinator" {
				project := fx.Insert(t, "project", dbfx.Cols{"workspace_id": f.workspaceID, "title": "synthetic protected recovery"})
				provider := fx.Insert(t, "r2d_git_provider", dbfx.Cols{"id": uuid.NewString(), "label": "synthetic", "kind": "github", "host": "fixture.invalid"})
				fx.Insert(t, "r2d_git_repository", dbfx.Cols{"id": uuid.NewString(), "project_id": project, "provider_id": provider, "canonical_repository": "fixtures/recovery", "protected": true})
				issue := f.workerIssue
				if mode == "protected-coordinator" {
					issue = f.issueID
				}
				fx.Exec(t, `UPDATE issue SET project_id=$2 WHERE id=$1`, issue, project)
			}
			if mode == "policy-outage" {
				svc.Queries = db.New(recoveryPolicyOutage{f.pool})
			}
			if _, err := svc.RecoverPendingDelegatedFailures(ctx, 100); err != nil {
				t.Fatal(err)
			}

			var count int
			fx.QueryRow(t, `SELECT count(*) FROM agent_task_queue WHERE trigger_evidence_kind='delegated_failure' AND trigger_evidence_ref_id=$1`, failed).Scan(&count)
			if (count == 1) != (mode == "ordinary") {
				t.Fatalf("recovery crossed %s boundary: %d generic tasks", mode, count)
			}
			if mode != "ordinary" {
				if f.settled(t, target.comment.ID) {
					t.Fatal("denied recovery was silently acknowledged")
				}
				if mode != "policy-outage" {
					next, _, err := svc.ensureDelegatedFailureRecoveryComment(ctx, failed)
					if err != nil || next != nil {
						t.Fatalf("protected recovery comment entry remained usable: %v %v", next, err)
					}
				}
			}
		})
	}
}
