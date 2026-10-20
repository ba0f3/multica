package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/multica-ai/multica/server/internal/middleware"
	"github.com/multica-ai/multica/server/internal/r2dgit"
	"github.com/multica-ai/multica/server/internal/testutil"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

// --- test doubles -----------------------------------------------------------

type gitTestCustody struct {
	mu       sync.Mutex
	stored   map[string]r2dgit.KeyMaterial
	destroys []string
	// signing makes WithSigner hand out a real signer for the stored
	// material so a signing test can verify the produced signature.
	signing bool
}

func newGitTestCustody() *gitTestCustody {
	return &gitTestCustody{stored: map[string]r2dgit.KeyMaterial{}}
}

func (c *gitTestCustody) Store(_ context.Context, ref string, material r2dgit.KeyMaterial) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.stored[ref]; exists {
		return 0, r2dgit.ErrConflict
	}
	c.stored[ref] = material
	return 1, nil
}

func (c *gitTestCustody) DestroyAll(_ context.Context, ref string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.destroys = append(c.destroys, ref)
	delete(c.stored, ref)
	return nil
}

func (c *gitTestCustody) WithSigner(_ context.Context, ref string, fn func(ssh.Signer) error) error {
	c.mu.Lock()
	signing := c.signing
	material, ok := c.stored[ref]
	c.mu.Unlock()
	if !signing {
		return r2dgit.ErrUnavailable
	}
	if !ok {
		return r2dgit.ErrIdentity
	}
	signer, err := ssh.ParsePrivateKey(material.Private)
	if err != nil {
		return r2dgit.ErrIdentity
	}
	return fn(signer)
}

type gitTestVerifier struct {
	login string
}

func (v *gitTestVerifier) Verify(context.Context, r2dgit.Provider, string, uint64) (string, error) {
	return v.login, nil
}

// --- helpers ----------------------------------------------------------------

func newGitTestProvider(t *testing.T, kind, host string) string {
	t.Helper()
	ctx := context.Background()
	id := uuid.NewString()
	if _, err := testPool.Exec(ctx, `
		INSERT INTO r2d_git_provider (id, label, kind, host, port, host_pins, enabled)
		VALUES ($1, $2, $3, $4, 22, '["SHA256:test-pin"]'::jsonb, true)`,
		id, host, kind, host); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM r2d_git_provider WHERE id = $1`, id)
	})
	return id
}

func newGitTestUser(t *testing.T, email string) string {
	t.Helper()
	ctx := context.Background()
	var id string
	if err := testPool.QueryRow(ctx,
		`INSERT INTO "user" (name, email) VALUES ($1, $2) RETURNING id`,
		"Git Identity Test", email).Scan(&id); err != nil {
		t.Fatalf("insert test user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM "user" WHERE id = $1`, id)
	})
	return id
}

// installGitService puts a credential service on the shared test handler for
// the duration of the test.
func installGitService(t *testing.T, verifier *gitTestVerifier) *gitTestCustody {
	t.Helper()
	custody := newGitTestCustody()
	service := r2dgit.NewService(
		r2dgit.NewSQLCStore(db.New(testPool)),
		custody,
		verifier,
	)
	previous := testHandler.GitSecurity
	testHandler.GitSecurity = service
	t.Cleanup(func() { testHandler.GitSecurity = previous })
	return custody
}

func gitRequest(t *testing.T, method, path, body string, userID string) *http.Request {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	if userID != "" {
		req = req.WithContext(middleware.ContextWithHumanSession(req.Context(), middleware.HumanSession{
			UserID:          userID,
			SessionID:       uuid.NewString(),
			AuthenticatedAt: time.Now().UTC(),
		}))
	}
	return req
}

func gitErrorCode(t *testing.T, recorder *httptest.ResponseRecorder) string {
	t.Helper()
	var payload struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode error body %q: %v", recorder.Body.String(), err)
	}
	return payload.Code
}

// --- tests ------------------------------------------------------------------

func TestListGitIdentitiesRequiresAHumanSession(t *testing.T) {
	installGitService(t, &gitTestVerifier{login: "octocat"})

	recorder := httptest.NewRecorder()
	testHandler.ListGitIdentities(recorder, gitRequest(t, http.MethodGet, "/api/me/git-identities", "", ""))

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusForbidden)
	}
	if code := gitErrorCode(t, recorder); code != "git_human_session_required" {
		t.Fatalf("code = %q, want %q", code, "git_human_session_required")
	}
}

func TestListGitIdentitiesReturnsOnlyTheCallersIdentities(t *testing.T) {
	installGitService(t, &gitTestVerifier{login: "octocat"})
	providerID := newGitTestProvider(t, "github", "github.com")
	owner := newGitTestUser(t, "git-owner@multica.ai")
	other := newGitTestUser(t, "git-other@multica.ai")

	recorder := httptest.NewRecorder()
	testHandler.GenerateGitIdentity(recorder, gitRequest(t, http.MethodPost, "/api/me/git-identities",
		fmt.Sprintf(`{"provider_id":%q,"request_id":"req-1"}`, providerID), owner))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("generate status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	testHandler.ListGitIdentities(recorder, gitRequest(t, http.MethodGet, "/api/me/git-identities", "", owner))
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var profile r2dgit.Profile
	if err := json.Unmarshal(recorder.Body.Bytes(), &profile); err != nil {
		t.Fatalf("decode profile: %v", err)
	}
	if len(profile.Identities) != 1 {
		t.Fatalf("the owner sees %d identities, want 1", len(profile.Identities))
	}
	if profile.Identities[0].UserID != owner {
		t.Fatalf("profile leaked another user's identity: %+v", profile.Identities[0])
	}

	recorder = httptest.NewRecorder()
	testHandler.ListGitIdentities(recorder, gitRequest(t, http.MethodGet, "/api/me/git-identities", "", other))
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &profile); err != nil {
		t.Fatalf("decode profile: %v", err)
	}
	if len(profile.Identities) != 0 {
		t.Fatalf("another user sees %d identities, want 0", len(profile.Identities))
	}
}

func TestGenerateGitIdentityRejectsAUserIdInTheBody(t *testing.T) {
	installGitService(t, &gitTestVerifier{login: "octocat"})
	providerID := newGitTestProvider(t, "github", "github.com")
	userID := newGitTestUser(t, "git-body@multica.ai")

	recorder := httptest.NewRecorder()
	testHandler.GenerateGitIdentity(recorder, gitRequest(t, http.MethodPost, "/api/me/git-identities",
		fmt.Sprintf(`{"provider_id":%q,"request_id":"req-1","user_id":%q}`, providerID, uuid.NewString()), userID))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
}

func TestGenerateGitIdentityIsIdempotentPerRequest(t *testing.T) {
	installGitService(t, &gitTestVerifier{login: "octocat"})
	providerID := newGitTestProvider(t, "github", "github.com")
	userID := newGitTestUser(t, "git-idem@multica.ai")

	body := fmt.Sprintf(`{"provider_id":%q,"request_id":"req-1"}`, providerID)
	first := httptest.NewRecorder()
	testHandler.GenerateGitIdentity(first, gitRequest(t, http.MethodPost, "/api/me/git-identities", body, userID))
	second := httptest.NewRecorder()
	testHandler.GenerateGitIdentity(second, gitRequest(t, http.MethodPost, "/api/me/git-identities", body, userID))

	if first.Code != http.StatusCreated || second.Code != http.StatusCreated {
		t.Fatalf("statuses = %d and %d, want %d", first.Code, second.Code, http.StatusCreated)
	}
	var a, b r2dgit.PublicIdentity
	if err := json.Unmarshal(first.Body.Bytes(), &a); err != nil {
		t.Fatalf("decode first identity: %v", err)
	}
	if err := json.Unmarshal(second.Body.Bytes(), &b); err != nil {
		t.Fatalf("decode second identity: %v", err)
	}
	if a.ID != b.ID || a.Generation != b.Generation {
		t.Fatalf("a repeated request produced a different identity: %+v vs %+v", a, b)
	}
}

func TestGitIdentityResponsesNeverCarryPrivateKeyMaterial(t *testing.T) {
	installGitService(t, &gitTestVerifier{login: "octocat"})
	providerID := newGitTestProvider(t, "github", "github.com")
	userID := newGitTestUser(t, "git-secret@multica.ai")

	recorder := httptest.NewRecorder()
	testHandler.GenerateGitIdentity(recorder, gitRequest(t, http.MethodPost, "/api/me/git-identities",
		fmt.Sprintf(`{"provider_id":%q,"request_id":"req-1"}`, providerID), userID))

	body := recorder.Body.String()
	for _, secret := range []string{"PRIVATE KEY", "private_key", "internal_secret_ref", "secret_ref"} {
		if strings.Contains(body, secret) {
			t.Fatalf("the response leaked %q: %s", secret, body)
		}
	}
}

func TestRevokeGitIdentityHidesAnotherUsersIdentity(t *testing.T) {
	installGitService(t, &gitTestVerifier{login: "octocat"})
	providerID := newGitTestProvider(t, "github", "github.com")
	owner := newGitTestUser(t, "git-revoke-owner@multica.ai")
	other := newGitTestUser(t, "git-revoke-other@multica.ai")

	recorder := httptest.NewRecorder()
	testHandler.GenerateGitIdentity(recorder, gitRequest(t, http.MethodPost, "/api/me/git-identities",
		fmt.Sprintf(`{"provider_id":%q,"request_id":"req-1"}`, providerID), owner))
	var created r2dgit.PublicIdentity
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode identity: %v", err)
	}

	req := gitRequest(t, http.MethodPost, "/api/me/git-identities/"+created.ID+"/revoke", "", other)
	req = testutil.WithURLParams(req, "identityId", created.ID)
	recorder = httptest.NewRecorder()
	testHandler.RevokeGitIdentity(recorder, req)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusNotFound, recorder.Body.String())
	}
	if code := gitErrorCode(t, recorder); code != "git_resource_unavailable" {
		t.Fatalf("code = %q, want %q", code, "git_resource_unavailable")
	}
}

func TestRevokeGitIdentityStopsTheKey(t *testing.T) {
	installGitService(t, &gitTestVerifier{login: "octocat"})
	providerID := newGitTestProvider(t, "github", "github.com")
	userID := newGitTestUser(t, "git-revoke@multica.ai")

	recorder := httptest.NewRecorder()
	testHandler.GenerateGitIdentity(recorder, gitRequest(t, http.MethodPost, "/api/me/git-identities",
		fmt.Sprintf(`{"provider_id":%q,"request_id":"req-1"}`, providerID), userID))
	var created r2dgit.PublicIdentity
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode identity: %v", err)
	}

	req := gitRequest(t, http.MethodPost, "/api/me/git-identities/"+created.ID+"/revoke", "", userID)
	req = testutil.WithURLParams(req, "identityId", created.ID)
	recorder = httptest.NewRecorder()
	testHandler.RevokeGitIdentity(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	recorder = httptest.NewRecorder()
	testHandler.ListGitIdentities(recorder, gitRequest(t, http.MethodGet, "/api/me/git-identities", "", userID))
	var profile r2dgit.Profile
	if err := json.Unmarshal(recorder.Body.Bytes(), &profile); err != nil {
		t.Fatalf("decode profile: %v", err)
	}
	if len(profile.Identities) != 1 {
		t.Fatalf("profile holds %d identities, want 1", len(profile.Identities))
	}
	if profile.Identities[0].State != r2dgit.Revoked {
		t.Fatalf("state = %q, want %q", profile.Identities[0].State, r2dgit.Revoked)
	}
	if profile.Identities[0].Active {
		t.Fatal("a revoked identity must not be active")
	}
}

func TestVerifyGitIdentityMakesTheKeyActive(t *testing.T) {
	installGitService(t, &gitTestVerifier{login: "octocat"})
	providerID := newGitTestProvider(t, "github", "github.com")
	userID := newGitTestUser(t, "git-verify@multica.ai")

	recorder := httptest.NewRecorder()
	testHandler.GenerateGitIdentity(recorder, gitRequest(t, http.MethodPost, "/api/me/git-identities",
		fmt.Sprintf(`{"provider_id":%q,"request_id":"req-1"}`, providerID), userID))
	var created r2dgit.PublicIdentity
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode identity: %v", err)
	}

	req := gitRequest(t, http.MethodPost,
		fmt.Sprintf("/api/me/git-identities/%s/%d/verify", created.ID, created.Generation), "", userID)
	req = testutil.WithURLParams(req, "identityId", created.ID, "generation", fmt.Sprintf("%d", created.Generation))
	recorder = httptest.NewRecorder()
	testHandler.VerifyGitIdentity(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("verify status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var verified r2dgit.PublicIdentity
	if err := json.Unmarshal(recorder.Body.Bytes(), &verified); err != nil {
		t.Fatalf("decode identity: %v", err)
	}
	if verified.State != r2dgit.Ready {
		t.Fatalf("state = %q, want %q", verified.State, r2dgit.Ready)
	}
	if verified.Login != "octocat" {
		t.Fatalf("login = %q, want %q", verified.Login, "octocat")
	}
	if !verified.Active {
		t.Fatal("a verified key must be the active generation")
	}
}

func TestGitIdentityEndpointsAreUnavailableWithoutCustody(t *testing.T) {
	previous := testHandler.GitSecurity
	testHandler.GitSecurity = nil
	t.Cleanup(func() { testHandler.GitSecurity = previous })

	recorder := httptest.NewRecorder()
	testHandler.ListGitIdentities(recorder, gitRequest(t, http.MethodGet, "/api/me/git-identities", "", uuid.NewString()))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	if code := gitErrorCode(t, recorder); code != "git_service_unavailable" {
		t.Fatalf("code = %q, want %q", code, "git_service_unavailable")
	}
}
