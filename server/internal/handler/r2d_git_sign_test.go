package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/multica-ai/multica/server/internal/r2dgit"
	"github.com/multica-ai/multica/server/internal/testutil"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

// daemonRequest builds a request as the daemon client sends it: the task
// route is authorized by the caller's workspace membership, which the test
// supplies through the same headers the auth middleware would set.
func daemonRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return testutil.WithHeaders(req, "X-User-ID", testUserID, "X-Workspace-ID", testWorkspaceID)
}

// signingTaskRequest is daemonRequest for the signing-lease route: the
// handler reads the task id from the chi route context, which a handler
// called directly does not get from the router.
func signingTaskRequest(taskID, body string) *http.Request {
	req := daemonRequest(http.MethodPost, "/api/daemon/tasks/"+taskID+"/git-signing-lease", body)
	return testutil.WithURLParams(req, "taskId", taskID)
}

// installGitSigningService puts a signing-capable credential service on the
// shared test handler.
func installGitSigningService(t *testing.T) *r2dgit.Service {
	t.Helper()
	custody := newGitTestCustody()
	custody.signing = true
	service := r2dgit.NewService(
		r2dgit.NewSQLCStore(db.New(testPool)),
		custody,
		&gitTestVerifier{login: "octocat"},
	)
	previous := testHandler.GitSecurity
	testHandler.GitSecurity = service
	t.Cleanup(func() { testHandler.GitSecurity = previous })
	return service
}

// newGitSigningTask inserts a task with a known originator.
//
// accountable_user_id mirrors originator_user_id because the attribution
// invariant requires it: the task names a human as accountable exactly when
// the same human authorized it.
func newGitSigningTask(t *testing.T, originatorID string) string {
	t.Helper()
	issueID := dbfx.Issue(t, "Git signing task")
	agentID := dbfx.Agent(t, "Git Signing Agent", testRuntimeID)
	cols := testutil.Cols{
		"issue_id":   issueID,
		"status":     "running",
		"runtime_id": testRuntimeID,
	}
	if originatorID != "" {
		cols["originator_user_id"] = originatorID
		cols["accountable_user_id"] = originatorID
	}
	return dbfx.Task(t, agentID, cols)
}

func TestOpenGitSigningLeaseRequiresADaemonTask(t *testing.T) {
	installGitSigningService(t)

	req := daemonRequest(http.MethodPost, "/api/daemon/tasks/"+uuid.NewString()+"/git-signing-lease", `{"provider_id":"provider-1"}`)
	recorder := httptest.NewRecorder()
	testHandler.OpenGitSigningLease(recorder, req)

	if recorder.Code == http.StatusOK {
		t.Fatalf("a lease was issued for a task that does not exist: %s", recorder.Body.String())
	}
}

func TestOpenGitSigningLeaseRefusesATaskWithoutAnOriginator(t *testing.T) {
	installGitSigningService(t)
	providerID := newGitTestProvider(t, "github", "github.com")
	taskID := newGitSigningTask(t, "")

	req := signingTaskRequest(taskID, `{"provider_id":"`+providerID+`"}`)
	recorder := httptest.NewRecorder()
	testHandler.OpenGitSigningLease(recorder, req)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
	if code := gitErrorCode(t, recorder); code != "git_principal_unproven" {
		t.Fatalf("code = %q, want %q", code, "git_principal_unproven")
	}
}

func TestOpenGitSigningLeaseNeverCarriesPrivateMaterial(t *testing.T) {
	installGitSigningService(t)
	providerID := newGitTestProvider(t, "github", "github.com")
	userID := newGitTestUser(t, "git-lease@multica.ai")
	taskID := newGitSigningTask(t, userID)

	// The user needs a ready key for the lease to bind to.
	recorder := httptest.NewRecorder()
	testHandler.GenerateGitIdentity(recorder, gitRequest(t, http.MethodPost, "/api/me/git-identities",
		`{"provider_id":"`+providerID+`","request_id":"req-lease"}`, userID))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("generate status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var created r2dgit.PublicIdentity
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode identity: %v", err)
	}
	verifyReq := gitRequest(t, http.MethodPost,
		"/api/me/git-identities/"+created.ID+"/"+itoa(created.Generation)+"/verify", "", userID)
	verifyReq = testutil.WithURLParams(verifyReq, "identityId", created.ID, "generation", itoa(created.Generation))
	recorder = httptest.NewRecorder()
	testHandler.VerifyGitIdentity(recorder, verifyReq)
	if recorder.Code != http.StatusOK {
		t.Fatalf("verify status = %d: %s", recorder.Code, recorder.Body.String())
	}

	req := signingTaskRequest(taskID, `{"provider_id":"`+providerID+`"}`)
	recorder = httptest.NewRecorder()
	testHandler.OpenGitSigningLease(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("lease status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var lease r2dgit.SigningLease
	if err := json.Unmarshal(recorder.Body.Bytes(), &lease); err != nil {
		t.Fatalf("decode lease: %v", err)
	}
	if lease.LeaseID == "" || lease.PublicKey == "" {
		t.Fatalf("the lease is incomplete: %+v", lease)
	}
	for _, secret := range []string{"PRIVATE KEY", "private_key", "internal_secret_ref", "secret_ref"} {
		if strings.Contains(recorder.Body.String(), secret) {
			t.Fatalf("the lease leaked %q: %s", secret, recorder.Body.String())
		}
	}
}

func TestSignGitDataRefusesAnUnknownLease(t *testing.T) {
	installGitSigningService(t)

	req := daemonRequest(http.MethodPost, "/api/daemon/git-signatures",
		`{"lease_id":"nope","data":"`+base64.StdEncoding.EncodeToString([]byte("data"))+`"}`)
	recorder := httptest.NewRecorder()
	testHandler.SignGitData(recorder, req)

	if recorder.Code == http.StatusOK {
		t.Fatalf("an unknown lease was signed: %s", recorder.Body.String())
	}
}

func TestSignGitDataSignsWithTheLeasedKey(t *testing.T) {
	installGitSigningService(t)
	providerID := newGitTestProvider(t, "github", "github.com")
	userID := newGitTestUser(t, "git-sign@multica.ai")
	taskID := newGitSigningTask(t, userID)

	recorder := httptest.NewRecorder()
	testHandler.GenerateGitIdentity(recorder, gitRequest(t, http.MethodPost, "/api/me/git-identities",
		`{"provider_id":"`+providerID+`","request_id":"req-sign"}`, userID))
	var created r2dgit.PublicIdentity
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode identity: %v", err)
	}
	verifyReq := gitRequest(t, http.MethodPost,
		"/api/me/git-identities/"+created.ID+"/"+itoa(created.Generation)+"/verify", "", userID)
	verifyReq = testutil.WithURLParams(verifyReq, "identityId", created.ID, "generation", itoa(created.Generation))
	recorder = httptest.NewRecorder()
	testHandler.VerifyGitIdentity(recorder, verifyReq)
	if recorder.Code != http.StatusOK {
		t.Fatalf("verify status = %d: %s", recorder.Code, recorder.Body.String())
	}

	leaseReq := signingTaskRequest(taskID, `{"provider_id":"`+providerID+`"}`)
	recorder = httptest.NewRecorder()
	testHandler.OpenGitSigningLease(recorder, leaseReq)
	if recorder.Code != http.StatusOK {
		t.Fatalf("lease status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var lease r2dgit.SigningLease
	if err := json.Unmarshal(recorder.Body.Bytes(), &lease); err != nil {
		t.Fatalf("decode lease: %v", err)
	}

	payload := []byte("the bytes a git operation signs")
	signReq := daemonRequest(http.MethodPost, "/api/daemon/git-signatures",
		`{"lease_id":"`+lease.LeaseID+`","data":"`+base64.StdEncoding.EncodeToString(payload)+`"}`)
	recorder = httptest.NewRecorder()
	testHandler.SignGitData(recorder, signReq)

	if recorder.Code != http.StatusOK {
		t.Fatalf("sign status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var signed struct {
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &signed); err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		t.Fatalf("decode the signature: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("the signature is empty")
	}
}

func TestSignGitDataRejectsAnOversizedPayload(t *testing.T) {
	installGitSigningService(t)

	oversized := base64.StdEncoding.EncodeToString(make([]byte, 128<<10))
	req := daemonRequest(http.MethodPost, "/api/daemon/git-signatures",
		`{"lease_id":"nope","data":"`+oversized+`"}`)
	recorder := httptest.NewRecorder()
	testHandler.SignGitData(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
}

func itoa(value uint64) string {
	return strconv.FormatUint(value, 10)
}
