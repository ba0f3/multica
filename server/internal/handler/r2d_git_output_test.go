package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/r2dgit"
	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

type outputFixtureProof struct {
	allowed    map[string]bool
	operations []r2dgit.BoundOperation
	hook       func()
}

func (p *outputFixtureProof) ProveRepository(_ context.Context, op r2dgit.BoundOperation) error {
	p.operations = append(p.operations, op)
	if p.hook != nil {
		p.hook()
	}
	if !p.allowed[op.UserID] {
		return errors.New("synthetic provider denied")
	}
	return nil
}
func syntheticTaskToken(t *testing.T, f *gitHTTPFixture, taskID string) string {
	t.Helper()
	token := "mat_synthetic_output_" + uuid.NewString()
	_, err := f.h.Queries.CreateTaskToken(context.Background(), db.CreateTaskTokenParams{TaskID: util.MustParseUUID(taskID), AgentID: util.MustParseUUID(f.agent), WorkspaceID: util.MustParseUUID(f.workspace), UserID: util.MustParseUUID(testUserID), TokenHash: auth.HashToken(token), ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestR2DGitRestrictedOutputRouterAndCurrentReader(t *testing.T) {
	f := newGitHTTPFixture(t)
	f.ready(t)
	ctx := context.Background()
	root, err := f.h.GitSecurity.EnqueueHuman(ctx, f.user, f.workspace, f.runRequest())
	if err != nil {
		t.Fatal(err)
	}
	dbfx.Exec(t, `UPDATE agent_task_queue SET status='running' WHERE id=$1`, root.Context.Binding.TaskID)
	token := syntheticTaskToken(t, f, root.Context.Binding.TaskID)
	proof := &outputFixtureProof{allowed: map[string]bool{f.user: true, f.other: false}}
	f.h.GitSecurity.OutputProof = proof
	const source = "synthetic A-only source: never publish this as a comment"
	path := "/api/git-runs/" + root.Context.ID + "/outputs"
	f.call(t, f.token, http.MethodPost, path, map[string]string{"kind": "diff", "content": source}, 403)
	f.call(t, token, http.MethodPost, path, map[string]any{"kind": "diff", "content": source, "classification": []string{f.project}}, 400)
	var receipt struct {
		ID string `json:"id"`
	}
	f.call(t, token, http.MethodPost, path, map[string]string{"kind": "diff", "content": source}, 201).JSON(&receipt)
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM r2d_git_output WHERE id=$1`, receipt.ID)
	})
	if _, err := testPool.Exec(ctx, `UPDATE r2d_git_output SET classification='[]' WHERE id=$1`, receipt.ID); err == nil {
		t.Fatal("classification was mutable")
	}
	read := "/api/me/git-outputs/" + receipt.ID
	if w := f.call(t, f.token, http.MethodGet, read, nil, 200); w.Body.String() != source || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("owner restricted download failed")
	}
	before := len(proof.operations)
	f.call(t, f.otherToken, http.MethodGet, read, nil, 404)
	if len(proof.operations) != before {
		t.Fatal("unauthorized reader reached provider")
	}
	if err := f.h.GitSecurity.SetProjectGrant(ctx, testUserID, f.project, "user", f.other, "member"); err != nil {
		t.Fatal(err)
	}
	bKey, err := f.h.GitSecurity.Generate(ctx, f.other, f.provider, uuid.NewString(), []string{f.project})
	if err != nil {
		t.Fatal(err)
	}
	f.worker.login, f.worker.accountID = "synthetic-b", "synthetic-account-b"
	if _, err := f.h.GitSecurity.Verify(ctx, f.other, bKey.ID, bKey.Generation); err != nil {
		t.Fatal(err)
	}
	if err := f.h.GitSecurity.SetProjectGrant(ctx, testUserID, f.project, "user", f.other, "viewer"); err != nil {
		t.Fatal(err)
	}
	if w := f.call(t, f.otherToken, http.MethodGet, read, nil, 503); strings.Contains(w.Body.String(), source) {
		t.Fatal("progress-only viewer received source")
	}
	proof.allowed[f.other] = true
	if w := f.call(t, f.otherToken, http.MethodGet, read, nil, 200); w.Body.String() != source {
		t.Fatal("authorized B failed own-key read")
	}
	op := proof.operations[len(proof.operations)-1]
	if op.UserID != f.other || op.IdentityID != bKey.ID || op.Generation != bKey.Generation {
		t.Fatalf("reader borrowed originator/agent-owner key: %+v", op)
	}
	proof.hook = func() {
		proof.hook = nil
		if err := f.h.GitSecurity.SetProjectGrant(ctx, testUserID, f.project, "user", f.other, ""); err != nil {
			t.Fatal(err)
		}
	}
	f.call(t, f.otherToken, http.MethodGet, read, nil, 404)
	// Normal completion retains classification and current reader checks.
	dbfx.Exec(t, `UPDATE agent_task_queue SET status='completed' WHERE id=$1`, root.Context.Binding.TaskID)
	dbfx.Exec(t, `UPDATE r2d_git_run_context SET state='completed' WHERE id=$1`, root.Context.ID)
	f.call(t, f.token, http.MethodGet, read, nil, 200)
	if err := f.h.GitSecurity.RevokeRoot(ctx, f.user, root.Context.ID); err != nil {
		t.Fatal(err)
	}
	f.call(t, f.token, http.MethodGet, read, nil, 409)
}

func TestR2DGitProtectedTaskCannotPublishViaGenericRoutes(t *testing.T) {
	f := newGitHTTPFixture(t)
	f.ready(t)
	root, err := f.h.GitSecurity.EnqueueHuman(context.Background(), f.user, f.workspace, f.runRequest())
	if err != nil {
		t.Fatal(err)
	}
	dbfx.Exec(t, `UPDATE agent_task_queue SET status='running' WHERE id=$1`, root.Context.Binding.TaskID)
	token := syntheticTaskToken(t, f, root.Context.Binding.TaskID)
	reached := 0
	router := f.router.(*chi.Mux)
	for _, path := range []string{"/api/issues/fixture/comments", "/api/attachments", "/api/mcp", "/ws", "/api/search"} {
		for _, method := range []string{http.MethodPost, http.MethodGet} {
			router.MethodFunc(method, path, func(w http.ResponseWriter, r *http.Request) { reached++; w.WriteHeader(202) })
		}
		for _, method := range []string{http.MethodPost, http.MethodGet} {
			f.call(t, token, method, path, map[string]string{"content": "synthetic source"}, 403)
		}
	}
	f.call(t, token, http.MethodPost, "/api/auth/cli-token", nil, 403)
	if reached != 0 {
		t.Fatal("protected token reached a generic sink")
	}
	issue := dbfx.Issue(t, "ordinary output control", testutil.Cols{"workspace_id": f.workspace})
	ordinary := dbfx.Task(t, f.agent, testutil.Cols{"runtime_id": f.runtime, "issue_id": issue, "status": "running"})
	ordinaryToken := syntheticTaskToken(t, f, ordinary)
	f.call(t, ordinaryToken, http.MethodPost, "/api/issues/fixture/comments", map[string]string{"content": "ordinary"}, 202)
	if reached != 1 {
		t.Fatal("ordinary task control was blocked")
	}
	f.call(t, ordinaryToken, http.MethodPost, "/api/git-runs/"+root.Context.ID+"/outputs", map[string]string{"kind": "diff", "content": "forged"}, 404)
	for _, tc := range []struct {
		call http.HandlerFunc
		body any
	}{
		{f.h.ReportTaskProgress, map[string]any{"summary": "synthetic source", "step": 1, "total": 1}},
		{f.h.CompleteTask, map[string]string{"output": "synthetic source"}},
		{f.h.FailTask, map[string]string{"error": "synthetic source"}},
		{f.h.AckTaskCancelled, map[string]string{"branch_name": "synthetic source", "durable_work_dir": "synthetic source", "error_message": "synthetic source"}},
		{f.h.PinTaskSession, map[string]string{"session_id": "synthetic source", "work_dir": "synthetic source"}},
		{f.h.ClaimTaskSupplement, map[string]string{}},
		{f.h.AckTaskSupplement, map[string]any{"delivered": true}},
		{f.h.ListTaskMessages, nil},
		{f.h.MarkTaskWaitingLocalDirectory, map[string]string{"reason": "synthetic source"}},
		{f.h.ReportTaskUsage, map[string]any{"usage": []map[string]string{{"provider": "synthetic source", "model": "synthetic source"}}}},
		{f.h.ReportTaskMessages, map[string]any{"messages": []map[string]string{{"role": "assistant", "content": "synthetic source"}}}},
	} {
		r := withURLParam(newDaemonTokenRequest(http.MethodPost, "/report", tc.body, f.resourceWorkspace, "synthetic-daemon"), "taskId", root.Context.Binding.TaskID)
		testutil.Call(t, tc.call, r).Want(403)
	}
	var status string
	var count int
	dbfx.QueryRow(t, `SELECT status FROM agent_task_queue WHERE id=$1`, root.Context.Binding.TaskID).Scan(&status)
	dbfx.QueryRow(t, `SELECT count(*) FROM task_message WHERE task_id=$1`, root.Context.Binding.TaskID).Scan(&count)
	if status != "running" || count != 0 {
		t.Fatalf("generic reports persisted output: status=%s messages=%d", status, count)
	}
	var leaked bool
	dbfx.QueryRow(t, `SELECT session_id IS NOT NULL OR work_dir IS NOT NULL OR result IS NOT NULL OR error IS NOT NULL FROM agent_task_queue WHERE id=$1`, root.Context.Binding.TaskID).Scan(&leaked)
	if leaked {
		t.Fatal("protected session/result columns changed")
	}
	withPluginsV1Flag(t, f.h, true)
	for _, call := range []http.HandlerFunc{f.h.InvokeAgentPluginHook, f.h.ResolvePluginMCPCredential} {
		r := withURLParam(newDaemonTokenRequest(http.MethodPost, "/plugin", map[string]string{"installation_id": "fixture", "hook_key": "fixture", "input": "synthetic source"}, f.resourceWorkspace, "synthetic-daemon"), "id", root.Context.Binding.TaskID)
		testutil.Call(t, call, r).Want(403)
		r = withURLParam(newDaemonTokenRequest(http.MethodPost, "/plugin", nil, f.workspace, "synthetic-daemon"), "id", ordinary)
		testutil.Call(t, call, r).Want(400)
	}
}

func TestR2DGitDurableJournalRejectsRestartReplay(t *testing.T) {
	f := newGitHTTPFixture(t)
	id := uuid.NewString()
	t.Cleanup(func() { _, _ = testPool.Exec(context.Background(), `DELETE FROM r2d_git_operation WHERE id=$1`, id) })
	op := r2dgit.BoundOperation{UserID: f.user, ContextID: uuid.NewString(), TaskID: uuid.NewString(), AttemptID: uuid.NewString(), ProviderID: f.provider, RepositoryID: f.repo, IdentityID: uuid.NewString(), Generation: 1, Operation: r2dgit.Read}
	j := r2dgit.SQLJournal{DB: testPool}
	if fresh, err := j.Begin(context.Background(), id, op); !fresh || err != nil {
		t.Fatalf("journal intent: %t %v", fresh, err)
	}
	restarted := r2dgit.SQLJournal{DB: testPool}
	if fresh, err := restarted.Begin(context.Background(), id, op); fresh || err != nil {
		t.Fatal("pending operation replayed after restart")
	}
	if err := restarted.Complete(context.Background(), id, "indeterminate"); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Complete(context.Background(), id, "succeeded"); err == nil {
		t.Fatal("indeterminate outcome overwritten")
	}
	loaded, outcome, err := restarted.Lookup(context.Background(), id)
	if err != nil || loaded != op || outcome != "indeterminate" {
		t.Fatalf("restart lookup changed immutable intent: %+v %s %v", loaded, outcome, err)
	}
	op.UserID = f.other
	spec, _ := json.Marshal(op)
	if _, err := testPool.Exec(context.Background(), `UPDATE r2d_git_operation SET spec=$2 WHERE id=$1`, id, spec); err == nil {
		t.Fatal("audit principal was mutable")
	}
}

func TestR2DGitWriteRegistryChecksCurrentOperationAndExactRef(t *testing.T) {
	for _, name := range []string{"positive", "read-only", "foreign-ref", "default-ref", "foreign-user", "generation", "provider-disabled", "revoked", "consent"} {
		t.Run(name, func(t *testing.T) {
			f := newGitHTTPFixture(t)
			identity := f.ready(t)
			ctx := context.Background()
			op := r2dgit.BoundOperation{UserID: f.user, ProviderID: f.provider, RepositoryID: f.repo, IdentityID: identity.ID, Generation: identity.Generation, Operation: r2dgit.Write, Ref: "refs/heads/task/fixture"}
			exec := func(sql string, args ...any) {
				if _, err := testPool.Exec(ctx, sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "read-only":
				exec(`UPDATE r2d_git_repository SET allow_write=false WHERE id=$1`, f.repo)
			case "foreign-ref":
				op.Ref = "refs/heads/task/other"
			case "default-ref":
				op.Ref = "refs/heads/main"
			case "foreign-user":
				op.UserID = f.other
			case "generation":
				op.Generation++
			case "provider-disabled":
				exec(`UPDATE r2d_git_provider SET enabled=false WHERE id=$1`, f.provider)
			case "revoked":
				if err := f.h.GitSecurity.Revoke(ctx, f.user, identity.ID); err != nil {
					t.Fatal(err)
				}
			case "consent":
				exec(`UPDATE r2d_git_key SET consent_project_ids='[]' WHERE identity_id=$1`, identity.ID)
			}
			target, err := f.h.GitSecurity.ResolveGitOperation(ctx, op)
			if name == "positive" {
				if err != nil || target.Repository != "fixtures/repo" || target.Fingerprint != identity.Fingerprint {
					t.Fatalf("positive registry: %+v %v", target, err)
				}
			} else if err == nil {
				t.Fatal("registry bypass", name)
			}
		})
	}
}

func TestR2DGitHistoricalOutputRejectsChangedOriginAndAncestor(t *testing.T) {
	for _, change := range []string{"rotate", "revoke", "membership", "project_role", "parent_runtime", "parent_invocation", "parent_project"} {
		t.Run(change, func(t *testing.T) {
			f := newGitHTTPFixture(t)
			key := f.ready(t)
			ctx := context.Background()
			if err := f.h.GitSecurity.SetProjectGrant(ctx, testUserID, f.project, "user", f.other, "member"); err != nil {
				t.Fatal(err)
			}
			b, err := f.h.GitSecurity.Generate(ctx, f.other, f.provider, uuid.NewString(), []string{f.project})
			if err != nil {
				t.Fatal(err)
			}
			f.worker.login, f.worker.accountID = "synthetic-b", "synthetic-account-b"
			if _, err = f.h.GitSecurity.Verify(ctx, f.other, b.ID, b.Generation); err != nil {
				t.Fatal(err)
			}
			f.worker.login, f.worker.accountID = "synthetic-account", "synthetic-immutable-id"
			root, err := f.h.GitSecurity.EnqueueHuman(ctx, f.user, f.workspace, f.runRequest())
			if err != nil {
				t.Fatal(err)
			}
			dbfx.Exec(t, `UPDATE agent_task_queue SET status='running' WHERE id=$1`, root.Context.Binding.TaskID)
			request := f.runRequest()
			request.AgentID = f.child
			// A distinct issue lets the test mutate only the ancestor project binding.
			request.IssueID = dbfx.Issue(t, "child protected output", testutil.Cols{"workspace_id": f.resourceWorkspace, "project_id": f.project})
			child, err := f.h.GitSecurity.EnqueueChild(ctx, root.Context.ID, root.Context.Binding.TaskID, f.agent, f.workspace, request)
			if err != nil {
				t.Fatal(err)
			}
			dbfx.Exec(t, `UPDATE agent_task_queue SET status='running' WHERE id=$1`, child.Context.Binding.TaskID)
			id, err := f.h.GitSecurity.StoreOutput(ctx, child.Context.ID, child.Context.Binding.TaskID, f.child, f.workspace, "artifact", []byte("synthetic descendant source"))
			if err != nil {
				t.Fatal(err)
			}
			dbfx.Exec(t, `UPDATE agent_task_queue SET status='completed' WHERE id IN ($1,$2)`, root.Context.Binding.TaskID, child.Context.Binding.TaskID)
			dbfx.Exec(t, `UPDATE r2d_git_run_context SET state='completed' WHERE root_id=$1`, root.Context.ID)
			proof := &outputFixtureProof{allowed: map[string]bool{f.user: true, f.other: true}}
			f.h.GitSecurity.OutputProof = proof
			for _, reader := range []string{f.user, f.other} {
				if body, err := f.h.GitSecurity.ReadOutput(ctx, reader, id); err != nil || len(body) == 0 {
					t.Fatalf("historical positive control %s: %v", reader, err)
				}
			}
			switch change {
			case "rotate":
				next, err := f.h.GitSecurity.Generate(ctx, f.user, f.provider, uuid.NewString(), []string{f.project})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = f.h.GitSecurity.Verify(ctx, f.user, next.ID, next.Generation); err != nil {
					t.Fatal(err)
				}
				if _, err = f.h.GitSecurity.Activate(ctx, f.user, next.ID, next.Generation); err != nil {
					t.Fatal(err)
				}
			case "revoke":
				if err := f.h.GitSecurity.Revoke(ctx, f.user, key.ID); err != nil {
					t.Fatal(err)
				}
			case "membership":
				dbfx.Exec(t, `DELETE FROM member WHERE user_id=$1 AND workspace_id=$2`, f.user, f.workspace)
			case "project_role":
				if err := f.h.GitSecurity.SetProjectGrant(ctx, testUserID, f.project, "user", f.user, "viewer"); err != nil {
					t.Fatal(err)
				}
			case "parent_runtime":
				other := dbfx.Runtime(t, "changed parent runtime", testutil.Cols{"workspace_id": f.workspace})
				dbfx.Exec(t, `UPDATE agent SET runtime_id=$2 WHERE id=$1`, f.agent, other)
			case "parent_invocation":
				dbfx.Exec(t, `DELETE FROM agent_invocation_target WHERE agent_id=$1`, f.agent)
			case "parent_project":
				dbfx.Exec(t, `UPDATE issue SET project_id=NULL WHERE id=$1`, f.issue)
			}
			before := len(proof.operations)
			for _, reader := range []string{f.user, f.other} {
				if body, err := f.h.GitSecurity.ReadOutput(ctx, reader, id); err == nil || len(body) != 0 {
					t.Fatalf("%s retained source after %s: %v", reader, change, err)
				}
			}
			if len(proof.operations) != before {
				t.Fatal("revoked lineage reached provider")
			}
		})
	}
}

func TestR2DGitVerificationRegistryReconnectRequiresExplicitActivation(t *testing.T) {
	f := newGitHTTPFixture(t)
	old := f.ready(t)
	ctx := context.Background()
	if err := f.h.GitSecurity.Revoke(ctx, f.user, old.ID); err != nil {
		t.Fatal(err)
	}
	next, err := f.h.GitSecurity.Generate(ctx, f.user, f.provider, uuid.NewString(), []string{f.project})
	if err != nil {
		t.Fatal(err)
	}
	var ref string
	dbfx.QueryRow(t, `SELECT internal_secret_ref FROM r2d_git_key WHERE identity_id=$1 AND generation=$2`, next.ID, next.Generation).Scan(&ref)
	fingerprint, err := f.h.GitSecurity.ResolveGitVerification(ctx, f.provider, next.ID, next.Generation, ref)
	if err != nil || fingerprint != next.Fingerprint {
		t.Fatalf("new pending key could not verify after revoke: %v", err)
	}
	if _, err := f.h.GitSecurity.ResolveGitVerification(ctx, f.provider, next.ID, old.Generation, ref); err == nil {
		t.Fatal("generation substitution accepted")
	}
	if _, err := f.h.GitSecurity.Verify(ctx, f.user, next.ID, next.Generation); err != nil {
		t.Fatal(err)
	}
	var revoked bool
	var active uint64
	dbfx.QueryRow(t, `SELECT revoked,active_generation FROM r2d_git_identity WHERE id=$1`, next.ID).Scan(&revoked, &active)
	if !revoked || active != 0 {
		t.Fatal("verification silently reactivated revoked identity")
	}
	if _, err := f.h.GitSecurity.Activate(ctx, f.user, next.ID, next.Generation); err != nil {
		t.Fatal(err)
	}
	dbfx.QueryRow(t, `SELECT revoked,active_generation FROM r2d_git_identity WHERE id=$1`, next.ID).Scan(&revoked, &active)
	if revoked || active != next.Generation {
		t.Fatal("explicit activation failed")
	}
}

type outputAuditDatabase struct {
	r2dgit.Database
	fail     string
	prepared func()
}

func (d outputAuditDatabase) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "INSERT INTO r2d_git_security_event") && len(args) >= 4 {
		if args[3] == d.fail {
			return pgconn.CommandTag{}, errors.New("synthetic audit unavailable")
		}
		if args[3] == "restricted_output_read_prepared" && d.prepared != nil {
			d.prepared()
		}
	}
	return d.Database.Exec(ctx, sql, args...)
}
func TestR2DGitOutputAuditFailureAndLateRevocationDenyDelivery(t *testing.T) {
	for _, mode := range []string{"intent", "prepared", "late_revocation"} {
		t.Run(mode, func(t *testing.T) {
			f := newGitHTTPFixture(t)
			key := f.ready(t)
			ctx := context.Background()
			run, err := f.h.GitSecurity.EnqueueHuman(ctx, f.user, f.workspace, f.runRequest())
			if err != nil {
				t.Fatal(err)
			}
			dbfx.Exec(t, `UPDATE agent_task_queue SET status='running' WHERE id=$1`, run.Context.Binding.TaskID)
			id, err := f.h.GitSecurity.StoreOutput(ctx, run.Context.ID, run.Context.Binding.TaskID, f.agent, f.workspace, "diff", []byte("synthetic audit guarded source"))
			if err != nil {
				t.Fatal(err)
			}
			proof := &outputFixtureProof{allowed: map[string]bool{f.user: true}}
			f.h.GitSecurity.OutputProof = proof
			if body, err := f.h.GitSecurity.ReadOutput(ctx, f.user, id); err != nil || len(body) == 0 {
				t.Fatalf("positive control: %v", err)
			}
			wrapper := outputAuditDatabase{Database: testPool}
			if mode == "late_revocation" {
				wrapper.prepared = func() {
					if err := f.h.GitSecurity.Revoke(ctx, f.user, key.ID); err != nil {
						t.Fatal(err)
					}
				}
			} else {
				wrapper.fail = "restricted_output_read_" + mode
			}
			f.h.GitSecurity.Store.DB = wrapper
			before := len(proof.operations)
			if body, err := f.h.GitSecurity.ReadOutput(ctx, f.user, id); err == nil || len(body) != 0 {
				t.Fatalf("returned source after %s: %v", mode, err)
			}
			if mode == "intent" && len(proof.operations) != before {
				t.Fatal("provider reached before durable audit intent")
			}
		})
	}
}

func TestR2DGitWriteJournalPersistsExactMutationAfterRestart(t *testing.T) {
	f := newGitHTTPFixture(t)
	f.ready(t)
	ctx := context.Background()
	dbfx.Exec(t, `UPDATE r2d_git_repository SET allow_write=true,write_refs='["refs/heads/task/fixture"]' WHERE id=$1`, f.repo)
	request := f.runRequest()
	request.Operations = []r2dgit.Operation{r2dgit.Read, r2dgit.Write}
	request.WriteRefs = []string{"refs/heads/task/fixture"}
	run, err := f.h.GitSecurity.EnqueueHuman(ctx, f.user, f.workspace, request)
	if err != nil {
		t.Fatal(err)
	}
	dbfx.Exec(t, `UPDATE agent_task_queue SET status='running' WHERE id=$1`, run.Context.Binding.TaskID)
	id := uuid.NewString()
	t.Cleanup(func() { _, _ = testPool.Exec(context.Background(), `DELETE FROM r2d_git_operation WHERE id=$1`, id) })
	op := r2dgit.BoundOperation{UserID: f.user, ContextID: run.Context.ID, TaskID: run.Context.Binding.TaskID, AttemptID: run.Context.AttemptID, RootID: run.Context.RootID, GrantID: run.Grant.ID, ProviderID: f.provider, RepositoryID: f.repo, IdentityID: run.Grant.IdentityID, Generation: run.Grant.CredentialGeneration, PolicyEpoch: run.Context.PolicyEpoch, GrantEpoch: run.Grant.Epoch, Operation: r2dgit.Write, Ref: "refs/heads/task/fixture", OldObject: strings.Repeat("a", 40), NewObject: strings.Repeat("b", 40), PackDigest: strings.Repeat("c", 64)}
	j := r2dgit.SQLJournal{DB: testPool}
	forged := op
	forged.AttemptID = uuid.NewString()
	if fresh, err := j.Begin(ctx, "forged-"+id, forged); err == nil || fresh {
		t.Fatal("unbound write intent accepted")
	}
	if fresh, err := j.Begin(ctx, id, op); !fresh || err != nil {
		t.Fatal("mutation intent", fresh, err)
	}
	reconstructed := r2dgit.SQLJournal{DB: testPool}
	got, state, err := reconstructed.Lookup(ctx, id)
	if err != nil || got != op || state != "pending" {
		t.Fatalf("mutation intent changed after restart: %+v %s %v", got, state, err)
	}
	if fresh, err := reconstructed.Begin(ctx, id, op); fresh || err != nil {
		t.Fatal("uncertain mutation replayed after restart")
	}
	if err := reconstructed.Complete(ctx, id, "indeterminate"); err != nil {
		t.Fatal(err)
	}
	got, state, err = reconstructed.Lookup(ctx, id)
	if err != nil || got != op || state != "indeterminate" {
		t.Fatal("mutation uncertainty not durable")
	}
	if err := reconstructed.Complete(ctx, id, "succeeded"); err == nil {
		t.Fatal("observation could erase original uncertainty")
	}
}
