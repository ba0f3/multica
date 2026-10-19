package handler

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/multica-ai/multica/server/internal/testutil"
)

// Claims must own their runtime freshness and agent capacity. Selecting an
// arbitrary workspace agent couples the assertion to unrelated queued work.
func isolatedClaimAgent(t *testing.T) (string, string) {
	t.Helper()
	name := t.Name() + "-" + uuid.NewString()
	runtime := dbfx.Runtime(t, name)
	agent := dbfx.Agent(t, name, runtime)
	return agent, runtime
}

func TestClaimTaskFixtureIgnoresOccupiedWorkspaceAgent(t *testing.T) {
	if testHandler == nil {
		t.Skip("database not available")
	}
	inheritedAgent, inheritedRuntime := isolatedClaimAgent(t)
	issue := dbfx.Issue(t, "isolated claim fixture")
	claim := func(runtime string) *testutil.Response {
		r := withURLParam(newDaemonTokenRequest(http.MethodPost, "/claim", nil, testWorkspaceID, "fixture-control"), "runtimeId", runtime)
		return testutil.Call(t, testHandler.ClaimTaskByRuntime, r).Want(http.StatusOK)
	}
	// Own the borrowed fixture too: unrelated agents on a shared runtime must
	// not make this controlled reproduction depend on test order.
	control := dbfx.Task(t, inheritedAgent, testutil.Cols{"runtime_id": inheritedRuntime, "issue_id": issue})
	var initial struct {
		Task *struct {
			ID string `json:"id"`
		} `json:"task"`
	}
	claim(inheritedRuntime).JSON(&initial)
	if initial.Task == nil || initial.Task.ID != control {
		t.Fatal("fresh inherited fixture failed pre-occupancy positive control")
	}
	if _, err := testPool.Exec(context.Background(), `UPDATE agent_task_queue SET status='completed' WHERE id=$1`, control); err != nil {
		t.Fatal(err)
	}
	// Reproduce the empty-task outcome by occupying a previously eligible
	// fixture. This establishes the mechanism, not the historical failure cause.
	var capacity int
	dbfx.QueryRow(t, `SELECT max_concurrent_tasks FROM agent WHERE id=$1`, inheritedAgent).Scan(&capacity)
	for i := 0; i < capacity; i++ {
		dbfx.Task(t, inheritedAgent, testutil.Cols{"runtime_id": inheritedRuntime, "status": "running"})
	}
	dbfx.Task(t, inheritedAgent, testutil.Cols{"runtime_id": inheritedRuntime, "issue_id": issue})
	var blocked struct {
		Task any `json:"task"`
	}
	claim(inheritedRuntime).JSON(&blocked)
	if blocked.Task != nil {
		t.Fatal("occupied arbitrary agent should reproduce the empty claim")
	}
	agent, runtime := isolatedClaimAgent(t)
	task := dbfx.Task(t, agent, testutil.Cols{"runtime_id": runtime, "issue_id": issue})
	var ready struct {
		Task *struct {
			ID string `json:"id"`
		} `json:"task"`
	}
	claim(runtime).JSON(&ready)
	if ready.Task == nil || ready.Task.ID != task {
		t.Fatalf("owned claim fixture did not return its task: %+v", ready.Task)
	}
}
