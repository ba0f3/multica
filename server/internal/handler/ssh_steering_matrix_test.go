package handler

import (
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

// Exercise both selection branches with actual negotiated running tasks and
// an explicit recipient. An empty recipient list or missing capability would
// make a denial test pass without ever reaching the principal guard.
func TestSSHSteeringPrincipalMatrix(t *testing.T) {
	for _, mode := range []string{"named", "all"} {
		for _, sameUser := range []bool{true, false} {
			name := mode + "/same-user"
			if !sameUser {
				name = mode + "/cross-user"
			}
			t.Run(name, func(t *testing.T) {
				f := newSupplementFixture(t, "codex", "running", true)
				owner := testUserID
				if !sameUser {
					owner = seedSecurityTestOwner(t, "steering-matrix-"+mode)
				}
				dbfx.Exec(t, `UPDATE agent_task_queue SET originator_user_id=$2, accountable_user_id=$2 WHERE id=$1`, f.taskID, owner)
				commentID := dbfx.Comment(t, f.issueID, "steering matrix instruction")
				issue := db.Issue{ID: parseUUID(f.issueID), WorkspaceID: parseUUID(testWorkspaceID)}
				comment := db.Comment{ID: parseUUID(commentID), AuthorType: "member", AuthorID: parseUUID(testUserID)}
				triggers := []commentAgentTrigger{{Agent: db.Agent{ID: parseUUID(f.agentID)}}}
				steer := commentSteerRequest{All: mode == "all"}
				if mode == "named" {
					steer.TaskIDs = []pgtype.UUID{parseUUID(f.taskID)}
				}
				kept, steered := testHandler.steerCommentAgentTriggers(t.Context(), issue, comment, "member", testUserID, testUserID, triggers, steer)
				count := dbfx.Count(t, `SELECT count(*) FROM task_supplement WHERE task_id=$1 AND comment_id=$2`, f.taskID, commentID)
				if sameUser {
					if len(kept) != 0 || len(steered) != 1 || count != 1 {
						t.Fatalf("positive control did not steer: kept=%d, steered=%d, rows=%d", len(kept), len(steered), count)
					}
				} else if len(kept) != 1 || len(steered) != 0 || count != 0 {
					t.Fatalf("cross-user instruction reached task: kept=%d, steered=%d, rows=%d", len(kept), len(steered), count)
				}
			})
		}
	}
}
