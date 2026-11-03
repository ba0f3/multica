package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/middleware"
	"github.com/multica-ai/multica/server/internal/r2dgit"
	"github.com/multica-ai/multica/server/internal/service"
	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

// TestRerunIssue_ExecutionPrincipalOverridesSourceOriginator is issue #109 F1.
func TestRerunIssue_ExecutionPrincipalOverridesSourceOriginator(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	ctx := context.Background()
	userA := seedSecurityTestOwner(t, "ssh-sign-a")
	userB := seedSecurityTestOwner(t, "ssh-sign-b")
	runtimeID := createCascadeFixtureRuntime(t, ctx, "ssh-sign rerun")
	agentID := seedPublicWorkspaceAgent(t, ctx, runtimeID, userA)

	issueID := seedMemberIssueAssignedToAgent(t, ctx, userB, agentID)
	sourceID := seedIssueTaskWithOriginator(t, ctx, issueID, agentID, runtimeID, userB)

	rerun, err := testHandler.TaskService.RerunIssue(
		ctx,
		util.MustParseUUID(issueID),
		util.MustParseUUID(sourceID),
		pgtype.UUID{},
		util.MustParseUUID(userA),
		false,
		func(db.Agent) bool { return true },
	)
	if err != nil {
		t.Fatalf("RerunIssue: %v", err)
	}
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM agent_task_queue WHERE id = $1`, rerun.ID) })

	var originator string
	if err := testPool.QueryRow(ctx, `SELECT originator_user_id::text FROM agent_task_queue WHERE id = $1`, rerun.ID).Scan(&originator); err != nil {
		t.Fatalf("load rerun originator: %v", err)
	}
	if originator != userA {
		t.Fatalf("rerun originator = %q, want execution principal %q (not source %q)", originator, userA, userB)
	}
}

func seedPublicWorkspaceAgent(t *testing.T, ctx context.Context, runtimeID, ownerID string) string {
	t.Helper()
	var agentID string
	if err := testPool.QueryRow(ctx, `
		INSERT INTO agent (workspace_id, name, description, runtime_mode, runtime_config,
			runtime_id, visibility, permission_mode, max_concurrent_tasks, owner_id,
			instructions, custom_env, custom_args)
		VALUES ($1, 'ssh-sign-agent', '', 'cloud', '{}'::jsonb, $2, 'private', 'public_to', 1, $3,
			'', '{}'::jsonb, '[]'::jsonb)
		RETURNING id`, testWorkspaceID, runtimeID, ownerID).Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM agent WHERE id = $1`, agentID) })
	if _, err := testPool.Exec(ctx, `
		INSERT INTO agent_invocation_target (agent_id, target_type, target_id)
		VALUES ($1, 'workspace', $2)`, agentID, testWorkspaceID); err != nil {
		t.Fatalf("seed workspace invocation target: %v", err)
	}
	return agentID
}

func seedMemberIssueAssignedToAgent(t *testing.T, ctx context.Context, creatorID, agentID string) string {
	t.Helper()
	var issueID string
	if err := testPool.QueryRow(ctx, `
		INSERT INTO issue (workspace_id, title, status, priority, creator_type, creator_id, assignee_type, assignee_id)
		VALUES ($1, 'ssh-sign issue', 'open', 'medium', 'member', $2, 'agent', $3)
		RETURNING id`, testWorkspaceID, creatorID, agentID).Scan(&issueID); err != nil {
		t.Fatalf("create issue: %v", err)
	}
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM issue WHERE id = $1`, issueID) })
	return issueID
}

func seedIssueTaskWithOriginator(t *testing.T, ctx context.Context, issueID, agentID, runtimeID, originatorID string) string {
	t.Helper()
	var taskID string
	if err := testPool.QueryRow(ctx, `
		INSERT INTO agent_task_queue (agent_id, runtime_id, issue_id, status, priority, context, originator_user_id, accountable_user_id)
		VALUES ($1, $2, $3, 'completed', 0, '{}'::jsonb, $4, $4)
		RETURNING id`, agentID, runtimeID, issueID, originatorID).Scan(&taskID); err != nil {
		t.Fatalf("seed source task: %v", err)
	}
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM agent_task_queue WHERE id = $1`, taskID) })
	return taskID
}

// TestIssueService_QuickCreateOriginMustMatchAuthenticatedTask is issue #109 F2.
func TestIssueService_QuickCreateOriginMustMatchAuthenticatedTask(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	ctx := context.Background()
	userA := seedSecurityTestOwner(t, "qc-service-a")
	runtimeID := createCascadeFixtureRuntime(t, ctx, "qc service")
	agentID := seedPublicWorkspaceAgent(t, ctx, runtimeID, userA)
	origin := seedQuickCreateTask(t, ctx, agentID, userA)
	other := seedQuickCreateTask(t, ctx, agentID, userA)

	_, err := testHandler.IssueService.Create(ctx, service.IssueCreateParams{
		WorkspaceID:         util.MustParseUUID(testWorkspaceID),
		Title:               "bad origin",
		Status:              "open",
		Priority:            "medium",
		CreatorType:         "agent",
		CreatorID:           util.MustParseUUID(agentID),
		OriginType:          pgtype.Text{String: "quick_create", Valid: true},
		OriginID:            util.MustParseUUID(origin),
		AuthenticatedTaskID: util.MustParseUUID(other),
	}, service.IssueCreateOpts{})
	if err == nil {
		t.Fatal("expected create to reject foreign quick_create origin")
	}
}

func seedQuickCreateTask(t *testing.T, ctx context.Context, agentID, originatorID string) string {
	t.Helper()
	ctxJSON := `{"type":"quick_create","workspace_id":"` + testWorkspaceID + `","requester_id":"` + originatorID + `"}`
	var taskID string
	if err := testPool.QueryRow(ctx, `
		INSERT INTO agent_task_queue (agent_id, runtime_id, status, priority, context, originator_user_id, accountable_user_id)
		SELECT $1, a.runtime_id, 'completed', 0, $2::jsonb, $3, $3
		FROM agent a WHERE a.id = $1
		RETURNING id`, agentID, ctxJSON, originatorID).Scan(&taskID); err != nil {
		t.Fatalf("seed quick-create task: %v", err)
	}
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM agent_task_queue WHERE id = $1`, taskID) })
	return taskID
}

// TestSteerComment_DeniesCrossUserCredentialTask is issue #109 F3.
func TestSteerComment_DeniesCrossUserCredentialTask(t *testing.T) {
	f := newSupplementFixture(t, "codex", "running", false)
	ctx := context.Background()
	userB := seedSecurityTestOwner(t, "steer-b")
	if _, err := testPool.Exec(ctx, `UPDATE agent_task_queue SET originator_user_id = $2, accountable_user_id = $2 WHERE id = $1`, f.taskID, userB); err != nil {
		t.Fatalf("retarget task originator: %v", err)
	}

	w := httptest.NewRecorder()
	body := map[string]any{
		"content":        "please push",
		"steer":          true,
		"steer_task_ids": []string{f.taskID},
	}
	req := withURLParam(newRequest(http.MethodPost, "/api/issues/"+f.issueID+"/comments", body), "id", f.issueID)
	testHandler.CreateComment(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("CreateComment: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var count int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM task_supplement WHERE task_id = $1`, f.taskID).Scan(&count); err != nil {
		t.Fatalf("count supplements: %v", err)
	}
	if count != 0 {
		t.Fatalf("cross-user steer created %d supplements, want 0", count)
	}
}

// TestOpenGitSigningLease_RejectsTerminalTask is issue #109 F5.
func TestOpenGitSigningLease_RejectsTerminalTask(t *testing.T) {
	installGitSigningService(t)
	provider := newGitTestProvider(t, "github", "github.com")
	recorder := httptest.NewRecorder()
	testHandler.GenerateGitIdentity(recorder, gitRequest(t, http.MethodPost, "/api/me/git-identities", `{"provider_id":"`+provider+`","request_id":"terminal-lease"}`, testUserID))
	var identity r2dgit.PublicIdentity
	if err := json.Unmarshal(recorder.Body.Bytes(), &identity); err != nil {
		t.Fatal(err)
	}
	verify := gitRequest(t, http.MethodPost, "/api/me/git-identities/"+identity.ID+"/"+itoa(identity.Generation)+"/verify", "", testUserID)
	verify = testutil.WithURLParams(verify, "identityId", identity.ID, "generation", itoa(identity.Generation))
	testutil.Call(t, testHandler.VerifyGitIdentity, verify).Want(http.StatusOK)

	runtime := dbfx.Runtime(t, "terminal lease runtime", testutil.Cols{"daemon_id": testDaemonID})
	agent := dbfx.Agent(t, "terminal lease agent", runtime)
	issue := dbfx.Issue(t, "terminal lease issue")
	task := dbfx.Task(t, agent, testutil.Cols{
		"runtime_id": runtime, "issue_id": issue, "status": "queued",
		"originator_user_id": testUserID, "accountable_user_id": testUserID,
	})

	claim := withURLParam(newRequest(http.MethodPost, "/api/daemon/runtimes/"+runtime+"/tasks/claim", map[string]any{}), "runtimeId", runtime)
	var response struct {
		Task *AgentTaskResponse `json:"task"`
	}
	testutil.Call(t, testHandler.ClaimTaskByRuntime, claim).Want(http.StatusOK).JSON(&response)
	if response.Task == nil || response.Task.GitSigningDaemonToken == "" {
		t.Fatal("expected signing daemon token from claim")
	}
	if _, err := testPool.Exec(context.Background(), `UPDATE agent_task_queue SET status = 'completed', completed_at = now() WHERE id = $1`, task); err != nil {
		t.Fatalf("mark task terminal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/daemon/tasks/"+task+"/git-signing-lease", strings.NewReader(`{"provider_id":"`+provider+`","attempt_id":"attempt-1"}`))
	req.Header.Set("Authorization", "Bearer "+response.Task.GitSigningDaemonToken)
	req.Header.Set("Content-Type", "application/json")
	req = testutil.WithURLParams(req, "taskId", task)
	protected := middleware.DaemonAuth(testHandler.Queries, nil, nil, nil)(http.HandlerFunc(testHandler.OpenGitSigningLease))
	testutil.Call(t, protected.ServeHTTP, req).Want(http.StatusForbidden)
}

func TestMayControlCredentialTaskForActor(t *testing.T) {
	task := db.AgentTaskQueue{OriginatorUserID: util.MustParseUUID("11111111-1111-1111-1111-111111111111")}
	if !mayControlCredentialTaskForActor(task, "11111111-1111-1111-1111-111111111111") {
		t.Fatal("same user should control credential task")
	}
	if mayControlCredentialTaskForActor(task, "22222222-2222-2222-2222-222222222222") {
		t.Fatal("different user must not control credential task")
	}
}

func TestTaskEligibleForNewSigningLease(t *testing.T) {
	if taskEligibleForNewSigningLease(db.AgentTaskQueue{Status: "completed"}) {
		t.Fatal("completed task must not receive a new lease")
	}
	if !taskEligibleForNewSigningLease(db.AgentTaskQueue{Status: "running"}) {
		t.Fatal("running task should receive a new lease")
	}
}
