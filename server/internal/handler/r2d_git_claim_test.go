package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/multica-ai/multica/server/internal/r2dgit"
	"github.com/multica-ai/multica/server/internal/testutil"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

func jsonUnmarshal(data []byte, out any) error {
	return json.Unmarshal(data, out)
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
