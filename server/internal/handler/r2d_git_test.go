package handler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/middleware"
	"github.com/multica-ai/multica/server/internal/r2dgit"
	"github.com/multica-ai/multica/server/internal/service"
	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"golang.org/x/crypto/ssh"
)

type gitFakeWorker struct {
	mu        sync.Mutex
	calls     int
	outage    bool
	stored    map[string][]byte
	destroyed map[string]bool
	login     string
	accountID string
	storeHook func()
}

func (f *gitFakeWorker) Generate(context.Context) (r2dgit.KeyMaterial, error) {
	f.mu.Lock()
	f.calls++
	seed := byte(f.calls)
	f.mu.Unlock()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	defer clear(private)
	public, _ := ssh.NewPublicKey(private.Public())
	block, _ := ssh.MarshalPrivateKey(private, "")
	defer clear(block.Bytes)
	return r2dgit.KeyMaterial{PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))), PrivateKey: pem.EncodeToMemory(block)}, nil
}
func (f *gitFakeWorker) Store(_ context.Context, ref string, k r2dgit.KeyMaterial) (int, error) {
	if f.storeHook != nil {
		f.storeHook()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.outage {
		return 0, r2dgit.ErrUnavailable
	}
	if _, ok := f.stored[ref]; ok {
		return 0, r2dgit.ErrConflict
	}
	f.stored[ref] = append([]byte(nil), k.PrivateKey...)
	return 1, nil
}
func (f *gitFakeWorker) DestroyAll(_ context.Context, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.outage {
		return r2dgit.ErrUnavailable
	}
	if _, ok := f.stored[ref]; !ok {
		return r2dgit.ErrUnavailable
	}
	f.destroyed[ref] = true
	clear(f.stored[ref])
	return nil
}
func (f *gitFakeWorker) Verify(_ context.Context, p r2dgit.Provider, ref, id string, generation uint64) (r2dgit.Verification, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.outage || f.destroyed[ref] || len(f.stored[ref]) == 0 || len(p.HostPins) == 0 {
		return r2dgit.Verification{}, r2dgit.ErrUnavailable
	}
	return r2dgit.Verification{IdentityID: id, ProviderID: p.ID, Generation: generation, Login: f.login, AccountID: f.accountID, HostPinned: true, VerifiedAt: time.Now()}, nil
}

type gitHTTPFixture struct {
	h                                                                                                                   *Handler
	router                                                                                                              http.Handler
	worker                                                                                                              *gitFakeWorker
	user, other, workspace, resourceWorkspace, project, issue, provider, repo, agent, child, runtime, token, otherToken string
}

func newGitHTTPFixture(t *testing.T) *gitHTTPFixture {
	t.Helper()
	if testPool == nil {
		t.Skip("local database required")
	}
	f := &gitHTTPFixture{}
	suffix := uuid.NewString()
	f.user = dbfx.User(t, "Git A", "git-a-"+suffix+"@fixture.invalid")
	f.other = dbfx.User(t, "Git B", "git-b-"+suffix+"@fixture.invalid")
	f.workspace = dbfx.Workspace(t, "Execution team", "exec-"+suffix)
	f.resourceWorkspace = dbfx.Workspace(t, "Resource team", "resource-"+suffix)
	dbfx.Member(t, f.workspace, f.user, "member")
	dbfx.Member(t, f.workspace, f.other, "member")
	dbfx.Member(t, f.resourceWorkspace, testUserID, "owner")
	f.project = dbfx.Insert(t, "project", testutil.Cols{"workspace_id": f.resourceWorkspace, "title": "Shared protected fixture"})
	f.issue = dbfx.Issue(t, "Protected fixture", testutil.Cols{"workspace_id": f.resourceWorkspace, "project_id": f.project})
	f.runtime = dbfx.Runtime(t, "Synthetic protected runner", testutil.Cols{"workspace_id": f.workspace})
	f.agent = dbfx.Agent(t, "Admin-owned shared agent", f.runtime, testutil.Cols{"workspace_id": f.workspace, "permission_mode": "public_to"})
	f.child = dbfx.Agent(t, "Admin-owned child agent", f.runtime, testutil.Cols{"workspace_id": f.workspace, "permission_mode": "public_to"})
	for _, agent := range []string{f.agent, f.child} {
		dbfx.Insert(t, "agent_invocation_target", testutil.Cols{"agent_id": agent, "target_type": "workspace", "target_id": f.workspace, "created_by": testUserID})
	}
	f.provider = dbfx.Insert(t, "r2d_git_provider", testutil.Cols{"id": uuid.NewString(), "label": "Synthetic GitHub", "kind": "github", "host": "git.fixture.invalid", "host_pins": testutil.Raw(`'["fixture-pin"]'::jsonb`), "enabled": true})
	f.repo = dbfx.Insert(t, "r2d_git_repository", testutil.Cols{"id": uuid.NewString(), "project_id": f.project, "provider_id": f.provider, "canonical_repository": "fixtures/repo", "allow_write": true, "write_refs": testutil.Raw(`'["refs/heads/task/fixture"]'::jsonb`)})
	h := *testHandler
	h.GitSecurity = r2dgit.NewService(testPool, testPool)
	f.h = &h
	f.worker = &gitFakeWorker{stored: map[string][]byte{}, destroyed: map[string]bool{}, login: "synthetic-account", accountID: "synthetic-immutable-id"}
	h.GitSecurity.Generator = f.worker
	h.GitSecurity.Custody = f.worker
	h.GitSecurity.Verifier = f.worker
	if err := h.GitSecurity.SetProjectGrant(context.Background(), testUserID, f.project, "user", f.user, "member"); err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	r.Use(middleware.Auth(h.Queries, auth.NewPATCache(nil), nil, nil))
	h.MountGitAccountRoutes(r)
	r.Post("/api/auth/cli-token", h.IssueCliToken)
	f.router = r
	user, err := h.Queries.GetUser(context.Background(), util.MustParseUUID(f.user))
	if err != nil {
		t.Fatal(err)
	}
	f.token, err = h.issueJWT(user)
	if err != nil {
		t.Fatal(err)
	}
	other, err := h.Queries.GetUser(context.Background(), util.MustParseUUID(f.other))
	if err != nil {
		t.Fatal(err)
	}
	f.otherToken, err = h.issueJWT(other)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		for _, fixtureUser := range []string{f.user, f.other} {
			for _, query := range []string{
				`DELETE FROM r2d_git_output_input WHERE output_id IN(SELECT id FROM r2d_git_output WHERE context_id IN(SELECT id FROM r2d_git_run_context WHERE authorizing_user_id=$1)) OR input_id IN(SELECT id FROM r2d_git_output WHERE context_id IN(SELECT id FROM r2d_git_run_context WHERE authorizing_user_id=$1))`,
				`DELETE FROM r2d_git_source_quarantine WHERE kind='audience' AND subject_id=$1`,
				`DELETE FROM r2d_git_output WHERE context_id IN (SELECT id FROM r2d_git_run_context WHERE authorizing_user_id=$1)`,
				`DELETE FROM task_token WHERE task_id IN (SELECT task_id FROM r2d_git_run_context WHERE authorizing_user_id=$1)`,
				`DELETE FROM agent_task_queue WHERE id IN (SELECT task_id FROM r2d_git_run_context WHERE authorizing_user_id=$1)`,
				`DELETE FROM r2d_git_run_grant WHERE context_id IN (SELECT id FROM r2d_git_run_context WHERE authorizing_user_id=$1)`,
				`DELETE FROM r2d_git_run_context WHERE authorizing_user_id=$1`,
				`DELETE FROM r2d_git_key_job WHERE user_id=$1`,
				`DELETE FROM r2d_git_key WHERE identity_id IN (SELECT id FROM r2d_git_identity WHERE user_id=$1)`,
				`DELETE FROM r2d_git_identity WHERE user_id=$1`,
				`DELETE FROM r2d_git_security_event WHERE user_id=$1`,
			} {
				_, _ = testPool.Exec(ctx, query, fixtureUser)
			}
		}
		_, _ = testPool.Exec(ctx, `DELETE FROM r2d_git_security_event WHERE subject_id=$1`, f.project)
		_, _ = testPool.Exec(ctx, `DELETE FROM r2d_git_security_event WHERE subject_id IN ($1,$2)`, f.workspace, f.resourceWorkspace)
		_, _ = testPool.Exec(ctx, `DELETE FROM r2d_git_project_grant WHERE project_id=$1`, f.project)
		_, _ = testPool.Exec(ctx, `DELETE FROM r2d_git_project_policy WHERE project_id=$1`, f.project)
		_, _ = testPool.Exec(ctx, `DELETE FROM r2d_git_source_quarantine WHERE kind='workspace' AND subject_id IN($1,$2)`, f.workspace, f.resourceWorkspace)
		_, _ = testPool.Exec(ctx, `DELETE FROM r2d_git_source_quarantine WHERE kind='audience' AND subject_id=$1 AND NOT EXISTS(SELECT 1 FROM member m JOIN r2d_git_source_quarantine q ON q.kind='workspace' AND q.subject_id=m.workspace_id WHERE m.user_id=$1)`, testUserID)
	})
	return f
}

// The recorder cannot block. Real socket deadline enforcement is tested with
// an actual HTTP server; no production response adapter gets this test method.
type gitMemoryDeadlineWriter struct{ http.ResponseWriter }

func (gitMemoryDeadlineWriter) SetWriteDeadline(time.Time) error { return nil }
func (w gitMemoryDeadlineWriter) FlushError() error {
	return http.NewResponseController(w.ResponseWriter).Flush()
}
func (w gitMemoryDeadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (f *gitHTTPFixture) call(t *testing.T, token, method, path string, body any, status int) *testutil.Response {
	t.Helper()
	r := testutil.WithHeaders(testutil.JSONRequest(method, path, body), "Authorization", "Bearer "+token, "X-Workspace-ID", f.workspace)
	return testutil.Call(t, func(w http.ResponseWriter, r *http.Request) { f.router.ServeHTTP(gitMemoryDeadlineWriter{w}, r) }, r).Want(status)
}
func (f *gitHTTPFixture) generate(t *testing.T, requestID string) r2dgit.PublicIdentity {
	t.Helper()
	var out r2dgit.PublicIdentity
	f.call(t, f.token, "POST", "/api/me/git-identities", map[string]any{"provider_id": f.provider, "request_id": requestID, "consent_project_ids": []string{f.project}}, 201).JSON(&out)
	return out
}
func (f *gitHTTPFixture) ready(t *testing.T) r2dgit.PublicIdentity {
	t.Helper()
	key := f.generate(t, uuid.NewString())
	var out r2dgit.PublicIdentity
	f.call(t, f.token, "POST", fmt.Sprintf("/api/me/git-identities/%s/%d/verify", key.ID, key.Generation), nil, 200).JSON(&out)
	return out
}
func (f *gitHTTPFixture) runRequest() r2dgit.RunRequest {
	return r2dgit.RunRequest{AgentID: f.agent, IssueID: f.issue, RepositoryID: f.repo, Operations: []r2dgit.Operation{r2dgit.Read}}
}

func TestR2DGitProfileDurableLifecycleOwnerAndSecretBoundaries(t *testing.T) {
	f := newGitHTTPFixture(t)
	request := uuid.NewString()
	key := f.generate(t, request)
	if key.State != r2dgit.PendingVerification || key.Active || key.PublicKey == "" {
		t.Fatalf("unsafe pending key: %+v", key)
	}
	replayed := f.generate(t, request)
	if replayed.Generation != key.Generation || f.worker.calls != 1 {
		t.Fatal("duplicate request generated another key")
	}
	f.call(t, f.token, "POST", "/api/me/git-identities", map[string]any{"provider_id": f.provider, "request_id": uuid.NewString()}, 409)
	f.call(t, f.otherToken, "POST", fmt.Sprintf("/api/me/git-identities/%s/%d/verify", key.ID, key.Generation), nil, 404)
	f.call(t, f.otherToken, "POST", "/api/me/git-identities/"+key.ID+"/revoke", nil, 404)
	var foreign r2dgit.Profile
	f.call(t, f.otherToken, "GET", "/api/me/git-identities", nil, 200).JSON(&foreign)
	if len(foreign.Identities) != 0 {
		t.Fatal("B received A's identities")
	}
	f.call(t, f.token, "POST", fmt.Sprintf("/api/me/git-identities/%s/%d/verify", key.ID, key.Generation), nil, 200).JSON(&key)
	if !key.Active {
		t.Fatal("verified first generation inactive")
	}
	rotation := f.generate(t, uuid.NewString())
	f.call(t, f.token, "POST", fmt.Sprintf("/api/me/git-identities/%s/%d/activate", rotation.ID, rotation.Generation), nil, 409)
	f.call(t, f.token, "POST", fmt.Sprintf("/api/me/git-identities/%s/%d/verify", rotation.ID, rotation.Generation), nil, 200)
	f.call(t, f.token, "POST", fmt.Sprintf("/api/me/git-identities/%s/%d/activate", rotation.ID, rotation.Generation), nil, 200)
	var profile r2dgit.Profile
	response := f.call(t, f.token, "GET", "/api/me/git-identities", nil, 200).JSON(&profile)
	active := 0
	for _, k := range profile.Identities {
		if k.Active {
			active++
		}
		if k.Generation == key.Generation && k.State != r2dgit.Revoked {
			t.Fatal("old generation usable after activation")
		}
	}
	if active != 1 {
		t.Fatal("rotation has multiple/no active keys")
	}
	for _, secret := range []string{"internal_secret_ref", "PRIVATE KEY", "token_hash"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatal("secret in profile response")
		}
	}
	f.worker.outage = true
	f.call(t, f.token, "POST", "/api/me/git-identities/"+key.ID+"/revoke", nil, 200)
	f.call(t, f.token, "GET", "/api/me/git-identities", nil, 200).JSON(&profile)
	for _, k := range profile.Identities {
		if k.Active || k.State != r2dgit.Revoked || !k.CleanupPending {
			t.Fatal("outage bypassed local revoke", k)
		}
	}
	f.worker.outage = false
	f.call(t, f.token, "POST", "/api/me/git-identities/"+key.ID+"/cleanup", nil, 200)
	f.call(t, f.token, "POST", fmt.Sprintf("/api/me/git-identities/%s/%d/activate", rotation.ID, rotation.Generation), nil, 409)
}

func TestR2DGitAuthenticationCSRFAndExchangeCannotCreateConsent(t *testing.T) {
	f := newGitHTTPFixture(t)
	payload := map[string]any{"provider_id": f.provider, "request_id": uuid.NewString()}
	req := testutil.WithHeaders(testutil.JSONRequest("POST", "/api/me/git-identities", payload), "X-User-ID", f.user, "X-Actor-Source", "member")
	testutil.Call(t, f.router.ServeHTTP, req).Want(401)
	user, _ := f.h.Queries.GetUser(context.Background(), util.MustParseUUID(f.user))
	old, _ := f.h.issueJWTWithAuthentication(user, time.Now().Add(-time.Hour))
	f.call(t, old, "POST", "/api/me/git-identities", payload, 403)
	f.call(t, f.token, "POST", "/api/me/git-identities", map[string]any{"provider_id": f.provider, "request_id": uuid.NewString(), "user_id": f.other}, 400)
	pat := "mul_synthetic_git_auth_fixture_" + uuid.NewString()
	dbfx.Insert(t, "personal_access_token", testutil.Cols{"user_id": f.user, "name": "Synthetic PAT", "token_hash": auth.HashToken(pat), "token_prefix": "mul_synthetic"})
	f.call(t, pat, "POST", "/api/me/git-identities", payload, 403)
	var exchanged struct {
		Token string `json:"token"`
	}
	f.call(t, pat, "POST", "/api/auth/cli-token", nil, 200).JSON(&exchanged)
	f.call(t, exchanged.Token, "POST", "/api/me/git-identities", payload, 403)
	f.call(t, exchanged.Token, "POST", "/api/me/git-runs", f.runRequest(), 403)
	var oldExchange struct {
		Token string `json:"token"`
	}
	f.call(t, old, "POST", "/api/auth/cli-token", nil, 200).JSON(&oldExchange)
	f.call(t, oldExchange.Token, "POST", "/api/me/git-identities", payload, 403)
	cookies := httptest.NewRecorder()
	if err := auth.SetAuthCookies(cookies, f.token); err != nil {
		t.Fatal(err)
	}
	for _, csrf := range []bool{false, true} {
		r := testutil.JSONRequest("POST", "/api/me/git-identities", payload)
		for _, cookie := range cookies.Result().Cookies() {
			r.AddCookie(cookie)
			if csrf && cookie.Name == auth.SessionCSRFCookieName {
				r.Header.Set(auth.CSRFHeaderName, cookie.Value)
			}
		}
		expected := 403
		if csrf {
			expected = 201
		}
		testutil.Call(t, f.router.ServeHTTP, r).Want(expected)
	}
}

func TestR2DGitImmutableRootChildAndCurrentPolicy(t *testing.T) {
	f := newGitHTTPFixture(t)
	f.ready(t)
	f.call(t, f.otherToken, "POST", "/api/me/git-runs", f.runRequest(), 404)
	var root r2dgit.RunInfo
	f.call(t, f.token, "POST", "/api/me/git-runs", f.runRequest(), 201).JSON(&root)
	if root.Context.Binding.OriginatorUserID != f.user || root.Context.Binding.ExecutionWorkspaceID != f.workspace || root.Context.Binding.ResourceWorkspaceID != f.resourceWorkspace || root.ExecutionAvailable {
		t.Fatal("wrong cross-workspace immutable scope", root)
	}
	f.call(t, f.otherToken, "GET", "/api/me/git-runs/"+root.Context.ID, nil, 404)
	if _, err := testPool.Exec(context.Background(), `UPDATE r2d_git_run_context SET spec=jsonb_set(spec,'{binding,originator_user_id}',to_jsonb($2::text)) WHERE id=$1`, root.Context.ID, f.other); err == nil {
		t.Fatal("DB allowed immutable principal substitution")
	}
	_, err := testPool.Exec(context.Background(), `UPDATE agent_task_queue SET status='running' WHERE id=$1`, root.Context.Binding.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	token := "mat_synthetic_child_" + uuid.NewString()
	_, err = f.h.Queries.CreateTaskToken(context.Background(), db.CreateTaskTokenParams{TaskID: util.MustParseUUID(root.Context.Binding.TaskID), AgentID: util.MustParseUUID(f.agent), WorkspaceID: util.MustParseUUID(f.workspace), UserID: util.MustParseUUID(testUserID), TokenHash: auth.HashToken(token), ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	request := f.runRequest()
	request.AgentID = f.child
	f.call(t, f.token, "POST", "/api/git-runs/"+root.Context.ID+"/children", request, 403)
	var child r2dgit.RunInfo
	f.call(t, token, "POST", "/api/git-runs/"+root.Context.ID+"/children", request, 201).JSON(&child)
	if child.Context.Binding.OriginatorUserID != f.user || child.Context.ParentID != root.Context.ID || child.Context.AttemptID == root.Context.AttemptID {
		t.Fatal("child borrowed agent/token owner's human or attempt")
	}
	request.Operations = []r2dgit.Operation{r2dgit.Write}
	request.WriteRefs = []string{"refs/heads/task/fixture"}
	f.call(t, token, "POST", "/api/git-runs/"+root.Context.ID+"/children", request, 404)
	_, _ = testPool.Exec(context.Background(), `UPDATE agent_task_queue SET status='completed' WHERE id=$1`, root.Context.Binding.TaskID)
	f.call(t, f.token, "GET", "/api/me/git-runs/"+child.Context.ID, nil, 200)
	f.call(t, f.token, "POST", "/api/me/git-runs/"+root.Context.ID+"/revoke", nil, 200)
	f.call(t, f.token, "GET", "/api/me/git-runs/"+child.Context.ID, nil, 409)
}

func TestR2DGitProvisionCrashAndRevokeRaceReconcile(t *testing.T) {
	f := newGitHTTPFixture(t)
	// Persist an intent and emulate a worker that died after custody accepted it.
	f.worker.storeHook = func() { panic("synthetic worker crash") }
	func() {
		defer func() {
			if recover() == nil {
				t.Error("crash fixture did not interrupt worker")
			}
		}()
		_, _ = f.h.GitSecurity.Generate(context.Background(), f.user, f.provider, uuid.NewString(), []string{f.project})
	}()
	f.worker.storeHook = nil
	var profile r2dgit.Profile
	f.call(t, f.token, "GET", "/api/me/git-identities", nil, 200).JSON(&profile)
	key := profile.Identities[0]
	f.call(t, f.token, "POST", "/api/me/git-identities/"+key.ID+"/revoke", nil, 200)
	f.call(t, f.token, "POST", "/api/me/git-identities/"+key.ID+"/cleanup", nil, 409)
	var ref string
	dbfx.QueryRow(t, `SELECT internal_secret_ref FROM r2d_git_key WHERE identity_id=$1`, key.ID).Scan(&ref)
	f.worker.stored[ref] = []byte("synthetic previously accepted custody bytes")
	dbfx.Exec(t, `UPDATE r2d_git_key_job SET lease_until=now()-interval '1 minute' WHERE identity_id=$1 AND kind='provision'`, key.ID)
	// New service instance represents process restart; metadata is in PostgreSQL.
	restarted := r2dgit.NewService(testPool, testPool)
	restarted.Custody = f.worker
	if err := restarted.Cleanup(context.Background(), f.user, key.ID); err != nil {
		t.Fatal(err)
	}
	f.call(t, f.token, "GET", "/api/me/git-identities", nil, 200).JSON(&profile)
	if profile.Identities[0].State != r2dgit.Revoked || profile.Identities[0].CleanupPending {
		t.Fatal("crash reconciliation revived or stranded generation")
	}
}

func TestR2DGitConcurrentDuplicateAndActivationRevocation(t *testing.T) {
	f := newGitHTTPFixture(t)
	ctx := context.Background()
	request := uuid.NewString()
	type result struct {
		key r2dgit.PublicIdentity
		err error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			key, err := f.h.GitSecurity.Generate(ctx, f.user, f.provider, request, []string{f.project})
			results <- result{key, err}
		}()
	}
	a, b := <-results, <-results
	if a.err != nil || b.err != nil || a.key.ID != b.key.ID || a.key.Generation != b.key.Generation || f.worker.calls != 1 {
		t.Fatalf("duplicate generation was not idempotent: errors %v / %v, calls %d", a.err, b.err, f.worker.calls)
	}
	if _, err := f.h.GitSecurity.Verify(ctx, f.user, a.key.ID, a.key.Generation); err != nil {
		t.Fatal(err)
	}
	next := f.generate(t, uuid.NewString())
	if _, err := f.h.GitSecurity.Verify(ctx, f.user, next.ID, next.Generation); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 2)
	go func() { _, err := f.h.GitSecurity.Activate(ctx, f.user, next.ID, next.Generation); finished <- err }()
	go func() { finished <- f.h.GitSecurity.Revoke(ctx, f.user, next.ID) }()
	for range 2 {
		if err := <-finished; err != nil && !errors.Is(err, r2dgit.ErrIdentity) {
			t.Fatal(err)
		}
	}
	var active, ready int
	if err := testPool.QueryRow(ctx, `SELECT active_generation,(SELECT count(*) FROM r2d_git_key WHERE identity_id=$1 AND state='ready') FROM r2d_git_identity WHERE id=$1`, next.ID).Scan(&active, &ready); err != nil {
		t.Fatal(err)
	}
	if active != 0 || ready != 0 {
		t.Fatal("concurrent activation revived revoked family")
	}
}

func TestR2DGitStableAccountRenameAndSubstitution(t *testing.T) {
	f := newGitHTTPFixture(t)
	f.ready(t)
	next := f.generate(t, uuid.NewString())
	f.worker.mu.Lock()
	f.worker.login = "renamed-synthetic-account"
	f.worker.mu.Unlock()
	var verified r2dgit.PublicIdentity
	f.call(t, f.token, "POST", fmt.Sprintf("/api/me/git-identities/%s/%d/verify", next.ID, next.Generation), nil, 200).JSON(&verified)
	if verified.Login != "renamed-synthetic-account" {
		t.Fatal("login snapshot did not update")
	}
	f.call(t, f.token, "POST", fmt.Sprintf("/api/me/git-identities/%s/%d/activate", next.ID, next.Generation), nil, 200)
	foreign := f.generate(t, uuid.NewString())
	f.worker.mu.Lock()
	f.worker.accountID = "foreign-immutable-id"
	f.worker.mu.Unlock()
	f.call(t, f.token, "POST", fmt.Sprintf("/api/me/git-identities/%s/%d/verify", foreign.ID, foreign.Generation), nil, 409)
	f.call(t, f.token, "POST", fmt.Sprintf("/api/me/git-identities/%s/%d/activate", foreign.ID, foreign.Generation), nil, 409)
}

func TestR2DGitPolicyRevocationWhileAdmissionWaits(t *testing.T) {
	for _, operation := range []string{"manager", "root"} {
		t.Run(operation, func(t *testing.T) {
			f := newGitHTTPFixture(t)
			f.ready(t)
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if operation == "manager" {
				if err := f.h.GitSecurity.SetProjectGrant(ctx, testUserID, f.project, "user", f.user, "manager"); err != nil {
					t.Fatal(err)
				}
			}
			blocker, err := testPool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback(context.Background())
			if _, err := blocker.Exec(ctx, `SELECT project_id FROM r2d_git_project_policy WHERE project_id=$1 FOR UPDATE`, f.project); err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() {
				if operation == "manager" {
					finished <- f.h.GitSecurity.SetProjectGrant(ctx, f.user, f.project, "user", f.other, "member")
				} else {
					_, err := f.h.GitSecurity.EnqueueHuman(ctx, f.user, f.workspace, f.runRequest())
					finished <- err
				}
			}()
			// Observe the actual blocked backend instead of relying on a sleep.
			for {
				var waiting bool
				if err := testPool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%r2d_git_project_policy%' AND pid<>pg_backend_pid())`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				select {
				case err := <-finished:
					t.Fatalf("operation failed before lock: %v", err)
				case <-ctx.Done():
					t.Fatal("operation did not wait for policy lock")
				case <-time.After(5 * time.Millisecond):
				}
			}
			if _, err := blocker.Exec(ctx, `DELETE FROM r2d_git_project_grant WHERE project_id=$1 AND subject_kind='user' AND subject_id=$2`, f.project, f.user); err != nil {
				t.Fatal(err)
			}
			if _, err := blocker.Exec(ctx, `UPDATE r2d_git_project_policy SET epoch=epoch+1 WHERE project_id=$1`, f.project); err != nil {
				t.Fatal(err)
			}
			if err := blocker.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-finished; !errors.Is(err, r2dgit.ErrScope) {
				t.Fatalf("revoked authority admitted after waiting: %v", err)
			}
			var grants, runs int
			if err := testPool.QueryRow(ctx, `SELECT (SELECT count(*) FROM r2d_git_project_grant WHERE project_id=$1 AND subject_id=$2),(SELECT count(*) FROM r2d_git_run_context WHERE authorizing_user_id=$3)`, f.project, f.other, f.user).Scan(&grants, &runs); err != nil {
				t.Fatal(err)
			}
			if grants != 0 || runs != 0 {
				t.Fatal("rejected operation left authorized rows")
			}
		})
	}
}

func TestR2DGitCurrentLifecycleAndRevokedProject(t *testing.T) {
	f := newGitHTTPFixture(t)
	f.ready(t)
	var root r2dgit.RunInfo
	f.call(t, f.token, "POST", "/api/me/git-runs", f.runRequest(), 201).JSON(&root)
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `UPDATE r2d_git_run_context SET state='completed' WHERE id=$1`, root.Context.ID); err != nil {
		t.Fatal(err)
	}
	f.call(t, f.token, "GET", "/api/me/git-runs/"+root.Context.ID, nil, 404)
	if _, err := testPool.Exec(ctx, `UPDATE r2d_git_run_context SET state='active' WHERE id=$1`, root.Context.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.h.GitSecurity.SetProjectGrant(ctx, testUserID, f.project, "user", f.user, ""); err != nil {
		t.Fatal(err)
	}
	f.call(t, f.token, "GET", "/api/me/git-runs/"+root.Context.ID, nil, 404)
}

func TestR2DGitClaimFinalizeStartDenyAndLegacyControl(t *testing.T) {
	f := newGitHTTPFixture(t)
	ctx := context.Background()
	for _, source := range []string{"issue", "chat", "quick_create", "lineage", "sealed", "legacy"} {
		t.Run(source, func(t *testing.T) {
			generation := time.Now().UTC().Truncate(time.Microsecond)
			cols := testutil.Cols{"runtime_id": f.runtime, "status": "dispatched", "dispatched_at": generation}
			switch source {
			case "issue":
				cols["issue_id"] = f.issue
			case "chat":
				cols["chat_session_id"] = dbfx.ChatSession(t, f.agent, testutil.Cols{"workspace_id": f.workspace, "project_id": f.project})
			case "quick_create":
				cols["context"] = fmt.Sprintf(`{"project_id":%q}`, f.project)
			case "lineage":
				cols["retry_of_task_id"] = dbfx.Task(t, f.agent, testutil.Cols{"runtime_id": f.runtime, "issue_id": f.issue})
			case "legacy":
				cols["chat_session_id"] = dbfx.ChatSession(t, f.agent, testutil.Cols{"workspace_id": f.workspace})
			}
			id := ""
			if source == "sealed" {
				f.ready(t)
				run, err := f.h.GitSecurity.EnqueueHuman(ctx, f.user, f.workspace, f.runRequest())
				if err != nil {
					t.Fatal(err)
				}
				id = run.Context.Binding.TaskID
				if _, err := testPool.Exec(ctx, `UPDATE agent_task_queue SET status='dispatched',dispatched_at=$2,issue_id=NULL WHERE id=$1`, id, generation); err != nil {
					t.Fatal(err)
				}
			} else {
				id = dbfx.Task(t, f.agent, cols)
			}
			task, err := f.h.Queries.GetAgentTask(ctx, util.MustParseUUID(id))
			if err != nil {
				t.Fatal(err)
			}
			protected, err := f.h.Queries.IsR2DGitProtectedTask(ctx, task.ID)
			if err != nil || !protected.Valid || protected.Bool != (source != "legacy") {
				t.Fatalf("protection resolution: %v %v", protected, err)
			}
			runtime, err := f.h.Queries.GetAgentRuntime(ctx, util.MustParseUUID(f.runtime))
			if err != nil {
				t.Fatal(err)
			}
			req := newDaemonTokenRequest("POST", "/claim", nil, f.workspace, "synthetic-claim")
			_, _, _, _, _, failure := f.h.buildClaimedTaskResponse(req, &task, runtime, f.runtime, f.workspace)
			if source == "legacy" {
				if failure != nil {
					t.Fatalf("ordinary claim rejected: %+v", failure)
				}
			} else if failure == nil {
				t.Fatal("protected claim leaked response")
			}
			tokenHash := "synthetic-finalize-" + id
			_, err = f.h.TaskService.FinalizeTaskClaim(ctx, task, db.CreateTaskTokenParams{TokenHash: tokenHash, TaskID: task.ID, AgentID: task.AgentID, WorkspaceID: util.MustParseUUID(f.workspace), UserID: util.MustParseUUID(f.user), ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}}, nil, false, nil, nil)
			if source == "legacy" {
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					_, _ = testPool.Exec(context.Background(), `DELETE FROM task_token WHERE token_hash=$1`, tokenHash)
				})
			} else {
				var denied *service.ClaimDeliveryAuthzError
				if !errors.As(err, &denied) || denied.Detail != "git_runtime_ineligible" {
					t.Fatalf("protected finalize not denied: %v", err)
				}
				var count int
				if err := testPool.QueryRow(ctx, `SELECT count(*) FROM task_token WHERE token_hash=$1`, tokenHash).Scan(&count); err != nil || count != 0 {
					t.Fatal("protected finalize created a token", err)
				}
				// The claim builder tombstones denied deliveries. Reset only the
				// synthetic queue row to exercise the independent start guard.
				if _, err := testPool.Exec(ctx, `UPDATE agent_task_queue SET status='dispatched',dispatched_at=$2 WHERE id=$1`, id, generation); err != nil {
					t.Fatal(err)
				}
			}
			_, err = f.h.TaskService.StartTaskForClaim(ctx, db.LockAgentTaskStartClaimParams{ID: task.ID, RuntimeID: util.MustParseUUID(f.runtime), DispatchedAt: pgtype.Timestamptz{Time: generation, Valid: true}})
			if source == "legacy" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "git_runtime_ineligible") {
				t.Fatalf("protected start accepted: %v", err)
			}
			if source != "legacy" {
				if _, err := f.h.TaskService.StartTask(ctx, task.ID); err == nil || !strings.Contains(err.Error(), "git_runtime_ineligible") {
					t.Fatalf("legacy protected start accepted: %v", err)
				}
				// The protected chat and ordinary chat controls both pass the
				// existing daemon workspace gate and reach the legacy {} branch.
				if source == "chat" {
					request := withURLParam(newDaemonTokenRequest("POST", "/start", map[string]any{}, f.workspace, "synthetic-legacy-start"), "taskId", id)
					testutil.Call(t, f.h.StartTask, request).Want(http.StatusInternalServerError)
				}
				var status string
				var supplements int
				if err := testPool.QueryRow(ctx, `SELECT status,(SELECT count(*) FROM task_supplement_capability WHERE task_id=$1) FROM agent_task_queue WHERE id=$1`, id).Scan(&status, &supplements); err != nil {
					t.Fatal(err)
				}
				if status != "dispatched" || supplements != 0 {
					t.Fatal("denied legacy start changed execution state")
				}
			} else {
				if _, err := testPool.Exec(ctx, `UPDATE agent_task_queue SET status='dispatched',started_at=NULL WHERE id=$1`, id); err != nil {
					t.Fatal(err)
				}
				request := withURLParam(newDaemonTokenRequest("POST", "/start", map[string]any{}, f.workspace, "synthetic-ordinary-legacy-start"), "taskId", id)
				testutil.Call(t, f.h.StartTask, request).Want(http.StatusOK)
			}
		})
	}
}

func TestR2DGitMigrationsRoundTrip(t *testing.T) {
	if testPool == nil {
		t.Skip("local database required")
	}
	ctx := context.Background()
	conn, err := testPool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	schema := "gitsec_fixture_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := conn.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = conn.Exec(ctx, `SET search_path TO public`)
		_, _ = conn.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`)
	}()
	if _, err := conn.Exec(ctx, `SET search_path TO `+schema); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob("../../migrations/9001*.up.sql")
	if err != nil || len(files) != 30 {
		t.Fatalf("migration inventory: %d %v", len(files), err)
	}
	sort.Strings(files)
	run := func(path string) {
		t.Helper()
		sql, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = conn.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("%s: %v", filepath.Base(path), err)
		}
	}
	for _, path := range files {
		run(path)
	}
	for i := len(files) - 1; i >= 0; i-- {
		run(strings.Replace(files[i], ".up.sql", ".down.sql", 1))
	}
	for _, path := range files {
		run(path)
	}
	_, err = conn.Exec(ctx, `INSERT INTO r2d_git_identity(id,user_id,provider_id) VALUES($1,$2,$3)`, uuid.NewString(), uuid.NewString(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
}

func TestR2DGitProtectionQueryCollapsesDAGAndDeniesCycles(t *testing.T) {
	f := newGitHTTPFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	left, right := "", ""
	for range 12 {
		cols := testutil.Cols{"runtime_id": f.runtime}
		if left != "" {
			cols["parent_task_id"] = left
			cols["retry_of_task_id"] = right
		}
		left, right = dbfx.Task(t, f.agent, cols), dbfx.Task(t, f.agent, cols)
	}
	protected, err := f.h.Queries.IsR2DGitProtectedTask(ctx, util.MustParseUUID(left))
	if err != nil || !protected.Valid || protected.Bool {
		t.Fatalf("convergent unprotected DAG: %v %v", protected, err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE agent_task_queue SET parent_task_id=$2 WHERE id=$1`, left, right); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE agent_task_queue SET parent_task_id=$2 WHERE id=$1`, right, left); err != nil {
		t.Fatal(err)
	}
	protected, err = f.h.Queries.IsR2DGitProtectedTask(ctx, util.MustParseUUID(left))
	if err != nil || !protected.Valid || !protected.Bool {
		t.Fatalf("lineage cycle did not fail closed: %v %v", protected, err)
	}
}

func TestR2DGitWorkspaceDeletionRevokesChainsAndPreservesHumanKeys(t *testing.T) {
	lockRollupSingleton(t)
	for _, scope := range []string{"execution", "resource"} {
		t.Run(scope, func(t *testing.T) {
			f := newGitHTTPFixture(t)
			dbfx.Member(t, f.workspace, testUserID, "owner")
			key := f.ready(t)
			ctx := context.Background()
			if err := f.h.GitSecurity.SetProjectGrant(ctx, testUserID, f.project, "workspace", f.workspace, "member"); err != nil {
				t.Fatal(err)
			}
			root, err := f.h.GitSecurity.EnqueueHuman(ctx, f.user, f.workspace, f.runRequest())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := testPool.Exec(ctx, `UPDATE agent_task_queue SET status='running' WHERE id=$1`, root.Context.Binding.TaskID); err != nil {
				t.Fatal(err)
			}
			request := f.runRequest()
			request.AgentID = f.child
			child, err := f.h.GitSecurity.EnqueueChild(ctx, root.Context.ID, root.Context.Binding.TaskID, f.agent, f.workspace, request)
			if err != nil {
				t.Fatal(err)
			}
			workspace := f.workspace
			if scope == "resource" {
				workspace = f.resourceWorkspace
			}
			req := withURLParam(newRequest("DELETE", "/api/workspaces/"+workspace, nil), "id", workspace)
			testutil.Call(t, f.h.DeleteWorkspace, req).Want(http.StatusNoContent)
			var activeContexts, activeGrants, policies, repositories, teamGrants int
			if err := testPool.QueryRow(ctx, `SELECT (SELECT count(*) FROM r2d_git_run_context WHERE root_id=$1 AND state<>'revoked'),(SELECT count(*) FROM r2d_git_run_grant WHERE context_id IN ($1,$2) AND state<>'revoked'),(SELECT count(*) FROM r2d_git_project_policy WHERE project_id=$3),(SELECT count(*) FROM r2d_git_repository WHERE project_id=$3),(SELECT count(*) FROM r2d_git_project_grant WHERE subject_kind='workspace' AND subject_id=$4)`, root.Context.ID, child.Context.ID, f.project, workspace).Scan(&activeContexts, &activeGrants, &policies, &repositories, &teamGrants); err != nil {
				t.Fatal(err)
			}
			if activeContexts != 0 || activeGrants != 0 || teamGrants != 0 {
				t.Fatal("deleted workspace retained active authorization")
			}
			want := 1
			if scope == "resource" {
				want = 0
			}
			if policies != want || repositories != want {
				t.Fatalf("foreign resource ownership changed: policy=%d repository=%d", policies, repositories)
			}
			profile, err := f.h.GitSecurity.Profile(ctx, f.user)
			if err != nil {
				t.Fatal(err)
			}
			if len(profile.Identities) != 1 || profile.Identities[0].ID != key.ID || !profile.Identities[0].Active || profile.Identities[0].State != r2dgit.Ready {
				t.Fatal("workspace deletion destroyed a human-owned key")
			}
			f.call(t, f.token, "GET", "/api/me/git-runs/"+child.Context.ID, nil, 409)
		})
	}
}
