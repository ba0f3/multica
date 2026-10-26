package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/middleware"

	"github.com/multica-ai/multica/server/internal/r2dgit"
	"github.com/multica-ai/multica/server/internal/testutil"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

func jsonUnmarshal(data []byte, out any) error {
	return json.Unmarshal(data, out)
}

func TestClaimedGitDaemonTokenAuthenticatesSigningEndpoint(t *testing.T) {
	installGitSigningService(t)
	provider := newGitTestProvider(t, "github", "github.com")
	recorder := httptest.NewRecorder()
	testHandler.GenerateGitIdentity(recorder, gitRequest(t, http.MethodPost, "/api/me/git-identities", `{"provider_id":"`+provider+`","request_id":"claim-signing"}`, testUserID))
	var identity r2dgit.PublicIdentity
	if err := json.Unmarshal(recorder.Body.Bytes(), &identity); err != nil {
		t.Fatal(err)
	}
	verify := gitRequest(t, http.MethodPost, "/api/me/git-identities/"+identity.ID+"/"+itoa(identity.Generation)+"/verify", "", testUserID)
	verify = testutil.WithURLParams(verify, "identityId", identity.ID, "generation", itoa(identity.Generation))
	testutil.Call(t, testHandler.VerifyGitIdentity, verify).Want(http.StatusOK)
	runtime := dbfx.Runtime(t, "Git-only claim", testutil.Cols{"daemon_id": testDaemonID})
	agent := dbfx.Agent(t, "Git-only claim agent", runtime)
	issue := dbfx.Issue(t, "Git-only claim issue")
	task := dbfx.Task(t, agent, testutil.Cols{"runtime_id": runtime, "issue_id": issue, "status": "queued", "originator_user_id": testUserID, "accountable_user_id": testUserID})
	claim := withURLParam(newRequest(http.MethodPost, "/api/daemon/runtimes/"+runtime+"/tasks/claim", map[string]any{}), "runtimeId", runtime)
	var response struct {
		Task *AgentTaskResponse `json:"task"`
	}
	testutil.Call(t, testHandler.ClaimTaskByRuntime, claim).Want(http.StatusOK).JSON(&response)
	if response.Task == nil || response.Task.ID != task || response.Task.GitSigningDaemonToken == "" || response.Task.RemoteMCPDaemonToken != "" {
		t.Fatal("Git-only task claim did not isolate supervisor authorization")
	}
	token := response.Task.GitSigningDaemonToken
	stored, err := testHandler.Queries.GetDaemonTokenByHash(context.Background(), auth.HashToken(token))
	if err != nil || stored.DaemonID != testDaemonID || uuidToString(stored.OwnerID) != testUserID {
		t.Fatal("claimed signing credential was not persisted with its owner/daemon")
	}
	req := httptest.NewRequest(http.MethodPost, "/api/daemon/tasks/"+task+"/git-signing-lease", strings.NewReader(`{"provider_id":"`+provider+`","attempt_id":"claim-test"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req = testutil.WithURLParams(req, "taskId", task)
	protected := middleware.DaemonAuth(testHandler.Queries, nil, nil, nil)(http.HandlerFunc(testHandler.OpenGitSigningLease))
	testutil.Call(t, protected.ServeHTTP, req).Want(http.StatusOK)
}

// dbRuntimeForTask loads the runtime row a task is bound to.
func dbRuntimeForTask(t *testing.T, runtimeID string) db.AgentRuntime {
	t.Helper()
	runtime, err := testHandler.Queries.GetAgentRuntime(context.Background(), parseUUID(runtimeID))
	if err != nil {
		t.Fatalf("load the runtime: %v", err)
	}
	return runtime
}

// claimForTask drives the claim response builder the way the daemon route
// does, so a test can assert what the daemon receives.
func claimForTask(t *testing.T, taskID string) AgentTaskResponse {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/daemon/tasks/"+taskID+"/claim", nil)
	task, workspaceID, ok := testHandler.requireDaemonTaskAccessWithWorkspace(
		httptest.NewRecorder(), testutil.WithHeaders(req,
			"X-User-ID", testUserID,
			"X-Workspace-ID", testWorkspaceID,
		), taskID)
	if !ok {
		t.Fatalf("the task fixture is not reachable in the test workspace")
	}
	runtimeID := uuidToString(task.RuntimeID)
	req = req.WithContext(context.Background())
	resp, _, _, _, _, failure := testHandler.buildClaimedTaskResponse(
		req, &task, dbRuntimeForTask(t, runtimeID), runtimeID, workspaceID,
	)
	if failure != nil {
		t.Fatalf("the claim was rejected: %+v", failure)
	}
	return resp
}

func TestClaimBindsTheOriginatorAndTheirReadyIdentity(t *testing.T) {
	installGitSigningService(t)
	providerID := newGitTestProvider(t, "gitea", "git.r2d.dev")
	if _, err := testPool.Exec(context.Background(), `UPDATE r2d_git_provider SET port = 2222 WHERE id = $1`, providerID); err != nil {
		t.Fatalf("set provider SSH port: %v", err)
	}
	userID := newGitTestUser(t, "git-claim@multica.ai")
	taskID := newGitSigningTask(t, userID)

	recorder := httptest.NewRecorder()
	testHandler.GenerateGitIdentity(recorder, gitRequest(t, http.MethodPost, "/api/me/git-identities",
		`{"provider_id":"`+providerID+`","request_id":"req-claim"}`, userID))
	var created r2dgit.PublicIdentity
	if err := jsonUnmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode identity: %v", err)
	}
	verifyReq := gitRequest(t, http.MethodPost,
		"/api/me/git-identities/"+created.ID+"/"+itoa(created.Generation)+"/verify", "", userID)
	verifyReq = testutil.WithURLParams(verifyReq, "identityId", created.ID, "generation", itoa(created.Generation))
	testHandler.VerifyGitIdentity(httptest.NewRecorder(), verifyReq)

	resp := claimForTask(t, taskID)
	if resp.ExecutionUserID != userID {
		t.Fatalf("execution user = %q, want the task originator %q", resp.ExecutionUserID, userID)
	}
	if len(resp.GitIdentities) != 1 {
		t.Fatalf("claim carried %d Git identities, want 1", len(resp.GitIdentities))
	}
	if resp.GitIdentities[0].ProviderID != providerID {
		t.Fatalf("provider id = %q, want %q", resp.GitIdentities[0].ProviderID, providerID)
	}
	if resp.GitIdentities[0].PublicKey == "" {
		t.Fatal("the claim carried no public key")
	}
	if resp.GitIdentities[0].Port != 2222 {
		t.Fatalf("provider SSH port = %d, want 2222", resp.GitIdentities[0].Port)
	}
}

func TestClaimNeverBindsTheRuntimeOwner(t *testing.T) {
	installGitSigningService(t)
	providerID := newGitTestProvider(t, "github", "github.com")

	// The runtime owner has a verified key...
	owner := newGitTestUser(t, "git-runtime-owner@multica.ai")
	recorder := httptest.NewRecorder()
	testHandler.GenerateGitIdentity(recorder, gitRequest(t, http.MethodPost, "/api/me/git-identities",
		`{"provider_id":"`+providerID+`","request_id":"req-owner"}`, owner))
	var created r2dgit.PublicIdentity
	if err := jsonUnmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode identity: %v", err)
	}
	verifyReq := gitRequest(t, http.MethodPost,
		"/api/me/git-identities/"+created.ID+"/"+itoa(created.Generation)+"/verify", "", owner)
	verifyReq = testutil.WithURLParams(verifyReq, "identityId", created.ID, "generation", itoa(created.Generation))
	testHandler.VerifyGitIdentity(httptest.NewRecorder(), verifyReq)

	// ...but the task is authorized by somebody else, who has no key.
	taskID := newGitSigningTask(t, uuid.NewString())
	resp := claimForTask(t, taskID)

	if len(resp.GitIdentities) != 0 {
		t.Fatalf("the claim borrowed a key that does not belong to the originator: %+v", resp.GitIdentities)
	}
}

func TestClaimWithoutAnOriginatorCarriesNoGitIdentity(t *testing.T) {
	installGitSigningService(t)
	newGitTestProvider(t, "github", "github.com")
	taskID := newGitSigningTask(t, "")

	resp := claimForTask(t, taskID)
	if resp.ExecutionUserID != "" {
		t.Fatalf("a task with no originator reported execution user %q", resp.ExecutionUserID)
	}
	if len(resp.GitIdentities) != 0 {
		t.Fatalf("a task with no originator carried credentials: %+v", resp.GitIdentities)
	}
}
