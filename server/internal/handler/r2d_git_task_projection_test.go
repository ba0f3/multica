package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/events"
	"github.com/multica-ai/multica/server/internal/service"
	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/multica-ai/multica/server/pkg/protocol"
)

// Scope an outage to this caller so independent DB test packages are not
// stalled by a global table lock. Ordinary reads still hit real PostgreSQL.
type projectionPolicyOutage struct{ db.DBTX }

func (d projectionPolicyOutage) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if strings.Contains(sql, "ListR2DGitTaskProtection") {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return d.DBTX.Query(ctx, sql, args...)
}

func TestR2DGitHistoricalTaskHistoryIsProgressOnly(t *testing.T) {
	f := newGitHTTPFixture(t)
	f.ready(t)
	ctx := context.Background()
	run, err := f.h.GitSecurity.EnqueueHuman(ctx, f.user, f.workspace, f.runRequest())
	if err != nil {
		t.Fatal(err)
	}
	id := run.Context.Binding.TaskID
	const marker = "synthetic-A-only-source-marker"
	result, _ := json.Marshal(map[string]string{"output": marker})
	dbfx.Exec(t, `UPDATE agent_task_queue SET status='running',result=$2,error=$3,session_id=$3,work_dir=$3,durable_work_dir=$3,branch_name=$3,handoff_note=$3,trigger_summary=$3 WHERE id=$1`, id, result, marker)
	ordinary := dbfx.Task(t, f.agent, testutil.Cols{"runtime_id": f.runtime, "status": "running", "result": testutil.Raw(`'{"output":"ordinary-positive-control"}'::jsonb`)})
	r := f.router.(*chi.Mux)
	r.Get("/api/agents/{id}/tasks", f.h.ListAgentTasks)
	r.Get("/api/task-snapshot", f.h.ListWorkspaceAgentTaskSnapshot)
	for _, path := range []string{"/api/agents/" + f.agent + "/tasks", "/api/task-snapshot"} {
		response := f.call(t, f.token, http.MethodGet, path, nil, 200)
		if strings.Contains(response.Body.String(), marker) {
			t.Fatalf("historical source escaped %s: %s", path, response.Body)
		}
		if !strings.Contains(response.Body.String(), "ordinary-positive-control") {
			t.Fatalf("ordinary detail lost %s", response.Body)
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cacheable progress projection")
		}
		var rows []AgentTaskResponse
		response.JSON(&rows)
		found := false
		for _, row := range rows {
			if row.ID == id {
				found = true
				if row.Result != nil || row.Error != nil || row.WorkDir != "" || row.HandoffNote != "" || row.BranchName != "" || row.Status != "running" {
					t.Fatalf("not progress-only %+v", row)
				}
			}
		}
		if !found {
			t.Fatal("protected progress disappeared")
		}
	}
	// Check the issue read paths using its resource-workspace owner; being an
	// owner is still not permission to receive source in generic history.
	for _, call := range []func(http.ResponseWriter, *http.Request){f.h.ListTasksByIssue, f.h.GetActiveTaskForIssue} {
		request := withURLParam(newRequest(http.MethodGet, "/runs", nil), "id", f.issue)
		request.Header.Set("X-Workspace-ID", f.resourceWorkspace)
		response := testutil.Call(t, call, request).Want(200)
		if strings.Contains(response.Body.String(), marker) || !strings.Contains(response.Body.String(), id) {
			t.Fatalf("issue history projection %s", response.Body)
		}
	}
	// The batch classifier never treats an unrelated ordinary row as protected.
	rows, err := f.h.Queries.ListR2DGitTaskProtection(ctx, []pgtype.UUID{util.MustParseUUID(id), util.MustParseUUID(ordinary), util.MustParseUUID(uuid.NewString())})
	if err != nil || len(rows) != 3 {
		t.Fatal("batch classification", rows, err)
	}
	classes := map[string]bool{}
	for _, row := range rows {
		classes[uuidToString(row.TaskID)] = row.Protected
	}
	if !classes[id] || classes[ordinary] {
		t.Fatal("cross-task classification contamination", classes)
	}
}

func TestR2DGitTaskProjectionPolicyOutageDoesNotReturnDetails(t *testing.T) {
	f := newGitHTTPFixture(t)
	id := dbfx.Task(t, f.agent, testutil.Cols{"runtime_id": f.runtime, "result": testutil.Raw(`'{"output":"synthetic-policy-outage-source"}'::jsonb`)})
	r := f.router.(*chi.Mux)
	r.Get("/api/agents/{id}/tasks", f.h.ListAgentTasks)
	f.h.Queries = db.New(projectionPolicyOutage{testPool})
	request := testutil.WithHeaders(testutil.JSONRequest(http.MethodGet, "/api/agents/"+f.agent+"/tasks", nil), "Authorization", "Bearer "+f.token, "X-Workspace-ID", f.workspace)
	start := time.Now()
	response := testutil.Call(t, r.ServeHTTP, request).Want(503)
	if strings.Contains(response.Body.String(), "synthetic-policy-outage-source") {
		t.Fatal("policy failure returned source")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("policy lookup failed to honor bound")
	}
	_ = id
}

func TestR2DGitLifecycleEventsCarryNoSourceDetails(t *testing.T) {
	f := newGitHTTPFixture(t)
	f.ready(t)
	ctx := context.Background()
	run, err := f.h.GitSecurity.EnqueueHuman(ctx, f.user, f.workspace, f.runRequest())
	if err != nil {
		t.Fatal(err)
	}
	task, err := f.h.Queries.GetAgentTask(ctx, util.MustParseUUID(run.Context.Binding.TaskID))
	if err != nil {
		t.Fatal(err)
	}
	bus := events.New()
	taskService := service.NewTaskService(f.h.Queries, testPool, f.h.TaskService.Hub, bus)
	var received []events.Event
	bus.Subscribe(protocol.EventTaskFailed, func(e events.Event) { received = append(received, e) })
	// Exercise the real post-failure publisher, which also feeds WS/outbound
	// subscribers, rather than testing an unused standalone serializer.
	task.Status = "failed"
	task.Error = pgtype.Text{String: "synthetic-A-only-event-source", Valid: true}
	task.MaxAttempts = 3
	task.FailureReason = pgtype.Text{String: "runtime_offline", Valid: true}
	dbfx.Exec(t, `UPDATE agent_task_queue SET status='failed' WHERE id=$1`, task.ID)
	taskService.HandleFailedTasks(ctx, []db.AgentTaskQueue{task})
	if len(received) != 1 {
		t.Fatalf("missing progress event %d", len(received))
	}
	payload, _ := json.Marshal(received[0].Payload)
	if strings.Contains(string(payload), "synthetic-A-only") || strings.Contains(string(payload), "error") {
		t.Fatalf("lifecycle source escaped %s", payload)
	}
	if !strings.Contains(string(payload), uuidToString(task.ID)) {
		t.Fatal("progress lost task binding")
	}
	// Direct internal progress publication is also denied for protected/unknown
	// tasks, so a handler-only fence is not the sole output boundary.
	var summaries []events.Event
	bus.Subscribe(protocol.EventTaskProgress, func(e events.Event) { summaries = append(summaries, e) })
	taskService.ReportProgress(ctx, run.Context.Binding.TaskID, f.workspace, "synthetic-protected-progress", 1, 2)
	taskService.ReportProgress(ctx, uuid.NewString(), f.workspace, "synthetic-unknown-progress", 1, 2)
	ordinary := dbfx.Task(t, f.agent, testutil.Cols{"runtime_id": f.runtime})
	taskService.ReportProgress(ctx, ordinary, f.workspace, "ordinary-progress", 1, 2)
	if len(summaries) != 1 {
		t.Fatalf("progress publication policy %d", len(summaries))
	}
}

func TestR2DGitClaimDispatchDoesNotBroadcastContext(t *testing.T) {
	for _, mode := range []string{"ordinary", "protected", "policy-outage"} {
		t.Run(mode, func(t *testing.T) {
			f := newGitHTTPFixture(t)
			ctx := context.Background()
			issue := f.issue
			if mode == "ordinary" || mode == "policy-outage" {
				issue = dbfx.Issue(t, "ordinary dispatch", testutil.Cols{"workspace_id": f.workspace})
			}
			id := dbfx.Task(t, f.agent, testutil.Cols{"runtime_id": f.runtime, "issue_id": issue, "context": `{"prompt":"synthetic-dispatch-source","session":"synthetic-dispatch-session"}`})
			bus := events.New()
			svc := service.NewTaskService(f.h.Queries, testPool, f.h.TaskService.Hub, bus)
			var dispatched []events.Event
			bus.Subscribe(protocol.EventTaskDispatch, func(e events.Event) { dispatched = append(dispatched, e) })
			claimCtx := ctx
			if mode == "policy-outage" {
				svc.Queries = db.New(projectionPolicyOutage{testPool})
			}

			task, err := svc.ClaimTask(claimCtx, util.MustParseUUID(f.agent))
			if err != nil || task == nil || uuidToString(task.ID) != id {
				t.Fatalf("real claim did not reach dispatch: %v %v", task, err)
			}
			if len(dispatched) != 1 {
				t.Fatalf("dispatch count %d", len(dispatched))
			}
			payload, _ := json.Marshal(dispatched[0].Payload)
			if strings.Contains(string(payload), "synthetic-dispatch") != (mode == "ordinary") {
				t.Fatalf("context publication crossed %s: %s", mode, payload)
			}
		})
	}
}

func TestR2DGitDirectLifecycleCannotPersistPublicSource(t *testing.T) {
	f := newGitHTTPFixture(t)
	ctx := context.Background()
	id := dbfx.Task(t, f.agent, testutil.Cols{"runtime_id": f.runtime, "issue_id": f.issue, "status": "running"})
	const source = "synthetic-direct-lifecycle-source"
	svc := f.h.TaskService
	if _, err := svc.CompleteTask(ctx, util.MustParseUUID(id), []byte(`{"output":"`+source+`"}`), source, source, source, false, "", source); err == nil {
		t.Fatal("direct completion bypassed protected handler fence")
	}
	task, transitioned, err := svc.FailTaskWithTransition(ctx, util.MustParseUUID(id), source, source, source, source, "runtime_offline", false, source, source)
	if err != nil || !transitioned || task == nil || task.Status != "failed" || task.Error.String != "git_runtime_ineligible" {
		t.Fatalf("protected refusal did not complete safely: %+v %t %v", task, transitioned, err)
	}
	if task.SessionID.Valid || task.WorkDir.Valid || task.BranchName.Valid {
		t.Fatal("source/session values persisted during refusal")
	}
	var comments int
	dbfx.QueryRow(t, `SELECT count(*) FROM comment WHERE issue_id=$1 AND content LIKE $2`, f.issue, "%"+source+"%").Scan(&comments)
	var retries int
	dbfx.QueryRow(t, `SELECT count(*) FROM agent_task_queue WHERE retry_of_task_id=$1`, id).Scan(&retries)
	if comments != 0 || retries != 0 {
		t.Fatal("protected refusal used public narrative/retry pipeline")
	}
}
