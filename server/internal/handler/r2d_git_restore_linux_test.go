//go:build linux

package handler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/multica-ai/multica/server/internal/r2dgit"
	"github.com/multica-ai/multica/server/internal/testutil"
)

func gitRestoreFixture(t *testing.T, f *gitHTTPFixture) *r2dgit.RestoreGuard {
	t.Helper()
	ctx := context.Background()
	// Reconciliation deliberately invalidates the whole synthetic instance.
	// Never run this destructive fixture alongside another DB suite.
	var foreign int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM r2d_git_identity WHERE user_id NOT IN($1,$2)`, f.user, f.other).Scan(&foreign); err != nil || foreign != 0 {
		t.Fatalf("foreign protected fixture present: %d %v", foreign, err)
	}
	prior := map[string]bool{}
	rows, err := testPool.Query(ctx, `SELECT kind||':'||subject_id::text FROM r2d_git_source_quarantine`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			t.Fatal(err)
		}
		prior[key] = true
	}
	rows.Close()
	w, err := r2dgit.CreateFileRestoreWitness(filepath.Join(t.TempDir(), "witness.json"))
	if err != nil {
		t.Fatal(err)
	}
	g := &r2dgit.RestoreGuard{ID: w.ID, Witness: w}
	if err := r2dgit.InitializeRestoreGuard(ctx, f.h.GitSecurity.Store, g); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Remove the anchor first so ordinary fixture teardown is not authority work.
		dbfx.Exec(t, `DELETE FROM r2d_git_restore_checkpoint`)
		f.h.GitSecurity.Store.Restore = nil
		g.Close()
		rows, err := testPool.Query(ctx, `SELECT kind,subject_id::text FROM r2d_git_source_quarantine`)
		if err != nil {
			t.Error(err)
			return
		}
		var extra [][2]string
		for rows.Next() {
			var pair [2]string
			if err := rows.Scan(&pair[0], &pair[1]); err != nil {
				t.Error(err)
			}
			if !prior[pair[0]+":"+pair[1]] {
				extra = append(extra, pair)
			}
		}
		rows.Close()
		for _, pair := range extra {
			dbfx.Exec(t, `DELETE FROM r2d_git_source_quarantine WHERE kind=$1 AND subject_id=$2`, pair[0], pair[1])
		}
	})
	return g
}

func TestR2DGitS5RestoreRollbackAndFreshApprovals(t *testing.T) {
	f := newGitHTTPFixture(t)
	f.ready(t)
	ctx := context.Background()
	s := f.h.GitSecurity
	project2 := dbfx.Insert(t, "project", testutil.Cols{"workspace_id": f.resourceWorkspace, "title": "second restored project"})
	if err := s.SetProjectGrant(ctx, testUserID, project2, "user", f.other, "manager"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		dbfx.Exec(t, `DELETE FROM r2d_git_project_grant WHERE project_id=$1`, project2)
		dbfx.Exec(t, `DELETE FROM r2d_git_project_policy WHERE project_id=$1`, project2)
	})
	for _, action := range []string{"assignment_classified", "restore_execution_approved", "operator_runtime_accepted"} {
		dbfx.Exec(t, `INSERT INTO r2d_git_security_event(id,user_id,subject_id,action,details) VALUES($1,$2,$3,$4,'{}')`, uuid.NewString(), f.user, f.issue, action)
	}
	var run r2dgit.RunInfo
	f.call(t, f.token, "POST", "/api/me/git-runs", f.runRequest(), 201).JSON(&run)
	g := gitRestoreFixture(t, f)
	checkpoint, err := g.Witness.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Current(ctx, run.Context, run.Grant); err != nil {
		t.Fatal("fresh restore guard denied", err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM member WHERE workspace_id=$1 AND user_id=$2`, f.workspace, f.user); err == nil {
		t.Fatal("legacy offboarding bypassed witness")
	}
	if err := s.MutateAuthority(ctx, func(db r2dgit.Database) error {
		_, err := db.Exec(ctx, `DELETE FROM member WHERE workspace_id=$1 AND user_id=$2`, f.workspace, f.user)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if rights, err := s.Current(ctx, run.Context, run.Grant); err == nil && rights.ActiveHuman {
		t.Fatal("offboarded originator retained run")
	}
	// Synthetic restore: DB authority and checkpoint roll back; external witness stays ahead.
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, stmt := range []string{`SET LOCAL multica.git_authority_mutation='witnessed'`} {
		if _, err = tx.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO member(workspace_id,user_id,role) VALUES($1,$2,'member')`, f.workspace, f.user); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE r2d_git_restore_checkpoint SET checkpoint=$1`, checkpoint); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.CheckSourceState(ctx); err == nil {
		t.Fatal("restored DB revived authority")
	}
	f.call(t, f.token, "GET", "/api/me/git-identities", nil, 503)
	s.Store.Restore = nil
	if err = s.CheckSourceState(ctx); err == nil {
		t.Fatal("missing witness selected legacy mode")
	}
	s.Store.Restore = g
	// An entirely new independent bootstrap cannot replace the existing anchor.
	w2, err := r2dgit.CreateFileRestoreWitness(filepath.Join(t.TempDir(), "witness.json"))
	if err != nil {
		t.Fatal(err)
	}
	g2 := &r2dgit.RestoreGuard{ID: w2.ID, Witness: w2}
	defer g2.Close()
	if err = r2dgit.InitializeRestoreGuard(ctx, s.Store, g2); err == nil {
		t.Fatal("second bootstrap replaced trust anchor")
	}
	if err = s.ReconcileRestoredDatabase(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.CheckSourceState(ctx); err != nil {
		t.Fatal("reconciled checkpoint mismatch", err)
	}
	if _, err = s.Current(ctx, run.Context, run.Grant); err == nil {
		t.Fatal("reconcile revived old root")
	}
	var unsafe int
	if err = testPool.QueryRow(ctx, `SELECT count(*) FROM r2d_git_run_context WHERE id=$1 AND state='active'`, run.Context.ID).Scan(&unsafe); err != nil || unsafe != 0 {
		t.Fatal("old root remained active", err)
	}
	if err = s.SetProjectGrant(ctx, testUserID, f.project, "user", f.user, "manager"); err == nil {
		t.Fatal("restored workspace owner self-approved")
	}
	op := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{84}, 32))
	cp, _ := g.Witness.Current(ctx)
	a := r2dgit.RestoreGovernanceApproval{ProjectID: f.project, WorkspaceID: f.resourceWorkspace, Checkpoint: cp, Managers: []string{f.user}}
	a.Signature = ed25519.Sign(op, r2dgit.RestoreGovernanceBytes(a))
	if err = s.ApproveRestoredProject(ctx, a, op.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if err = s.ApproveRestoredProject(ctx, a, op.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("replayed governance approval")
	}
	cp, _ = g.Witness.Current(ctx)
	a2 := r2dgit.RestoreGovernanceApproval{ProjectID: project2, WorkspaceID: f.resourceWorkspace, Checkpoint: cp, Managers: []string{f.other}}
	a2.Signature = ed25519.Sign(op, r2dgit.RestoreGovernanceBytes(a2))
	if err = s.ApproveRestoredProject(ctx, a2, op.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	if err = s.SetProjectGrant(ctx, f.user, project2, "user", f.user, "manager"); err == nil {
		t.Fatal("project approval broadened into another project's governance")
	}
	if err = s.SetProjectGrant(ctx, f.other, f.project, "user", f.other, "manager"); err == nil {
		t.Fatal("second project manager governed first project")
	}
	if err = testPool.QueryRow(ctx, `SELECT count(*) FROM r2d_git_security_event WHERE user_id=$1 AND action IN ('assignment_classified','restore_execution_approved','operator_runtime_accepted')`, f.user).Scan(&unsafe); err != nil || unsafe != 0 {
		t.Fatal("old trusted approvals survived restore", err)
	}
	// Fresh project rights alone cannot reuse restored execution authority.
	fresh := f.ready(t)
	f.call(t, f.token, "POST", fmt.Sprintf("/api/me/git-identities/%s/%d/activate", fresh.ID, fresh.Generation), nil, 200)
	f.call(t, f.token, "POST", "/api/me/git-runs", f.runRequest(), 409)
	cp, _ = g.Witness.Current(ctx)
	e := r2dgit.RestoreExecutionApproval{ID: uuid.NewString(), Checkpoint: cp, UserID: f.user, WorkspaceID: f.workspace, AgentID: f.agent, RuntimeID: f.runtime, ProjectID: f.project, ExpiresAt: time.Now().Add(30 * time.Minute)}
	e.Signature = ed25519.Sign(op, r2dgit.RestoreExecutionBytes(e))
	if err = s.ApproveRestoredExecution(ctx, e, op.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	var freshRun r2dgit.RunInfo
	f.call(t, f.token, "POST", "/api/me/git-runs", f.runRequest(), 201).JSON(&freshRun)
	cp, _ = g.Witness.Current(ctx)
	e2 := e
	e2.ID = uuid.NewString()
	e2.Checkpoint = cp
	e2.AgentID = f.child
	e2.ExpiresAt = time.Now().Add(55 * time.Minute)
	e2.Signature = ed25519.Sign(op, r2dgit.RestoreExecutionBytes(e2))
	if err = s.ApproveRestoredExecution(ctx, e2, op.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	request2 := f.runRequest()
	request2.AgentID = f.child
	run2, err := s.EnqueueHuman(ctx, f.user, f.workspace, request2)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.MutateAuthority(ctx, func(db r2dgit.Database) error {
		_, err := db.Exec(ctx, `UPDATE agent_task_queue SET status='running' WHERE id IN($1,$2)`, freshRun.Context.Binding.TaskID, run2.Context.Binding.TaskID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s.OutputProof = &outputFixtureProof{allowed: map[string]bool{f.user: true}}
	output1, err := s.StoreOutput(ctx, freshRun.Context.ID, freshRun.Context.Binding.TaskID, f.agent, f.workspace, "artifact", []byte("synthetic restored A"))
	if err != nil {
		t.Fatal(err)
	}
	output2, err := s.StoreOutput(ctx, run2.Context.ID, run2.Context.Binding.TaskID, f.child, f.workspace, "artifact", []byte("synthetic restored B"))
	if err != nil {
		t.Fatal(err)
	}
	derived, err := s.StoreOutputFromInputs(ctx, run2.Context.ID, run2.Context.Binding.TaskID, f.child, f.workspace, "artifact", []byte("synthetic restored union"), []string{output1})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.MutateAuthority(ctx, func(db r2dgit.Database) error {
		_, err := db.Exec(ctx, `UPDATE agent_task_queue SET status='completed' WHERE id IN($1,$2)`, freshRun.Context.Binding.TaskID, run2.Context.Binding.TaskID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadOutput(ctx, f.user, derived); err != nil {
		t.Fatal("fresh union denied", err)
	}
	clock := s.Now
	s.Now = func() time.Time { return clock().Add(31 * time.Minute) }
	if _, err = s.ReadOutput(ctx, f.user, output2); err != nil {
		t.Fatal("unexpired originator output denied", err)
	}
	for _, id := range []string{output1, derived} {
		if _, err = s.ReadOutput(ctx, f.user, id); err == nil {
			t.Fatal("expired originator execution approval retained historical/union output")
		}
	}
	s.Now = clock
	if blocked, err := s.ReaderlessSourceBlocked(ctx); err != nil || !blocked {
		t.Fatal("reapproval declassified history", err)
	}
	// Even a well-formed second anchor makes the instance ambiguous and unavailable.
	dbfx.Exec(t, `INSERT INTO r2d_git_restore_checkpoint(id,checkpoint) VALUES($1,$2)`, uuid.NewString(), uuid.NewString())
	if err = s.CheckSourceState(ctx); err == nil {
		t.Fatal("ambiguous anchor accepted")
	}
}

func TestR2DGitS5RestoreReadUsesFreshIndependentPool(t *testing.T) {
	f := newGitHTTPFixture(t)
	g := gitRestoreFixture(t, f)
	ctx := context.Background()
	tx, err := testPool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var old string
	if err = tx.QueryRow(ctx, `SELECT checkpoint::text FROM r2d_git_restore_checkpoint`).Scan(&old); err != nil {
		t.Fatal(err)
	}
	if err = f.h.GitSecurity.MutateAuthority(ctx, func(db r2dgit.Database) error { _, err := db.Exec(ctx, `SELECT 1`); return err }); err != nil {
		t.Fatal(err)
	}
	var stillOld string
	if err = tx.QueryRow(ctx, `SELECT checkpoint::text FROM r2d_git_restore_checkpoint`).Scan(&stillOld); err != nil || old != stillOld {
		t.Fatal("not a stale caller snapshot", err)
	}
	// All caller-pool connections can be held; verifier uses its own single pool.
	conns := []interface{ Release() }{}
	for i := int32(0); i < testPool.Config().MaxConns-1; i++ {
		c, err := testPool.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	defer func() {
		for _, c := range conns {
			c.Release()
		}
	}()
	checkCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err = f.h.GitSecurity.CheckSourceState(checkCtx); err != nil {
		t.Fatal("caller pool exhaustion blocked verifier", err)
	}
	if cp, err := g.Witness.Current(ctx); err != nil || cp == old {
		t.Fatal("write did not advance witness", err)
	}
}

type pausedRestoreWitness struct {
	r2dgit.RestoreWitness
	advanced chan struct{}
	release  chan struct{}
	cancel   context.CancelFunc
}

func (w pausedRestoreWitness) Locked(ctx context.Context, fn func(string, func(string) error) error) error {
	return w.RestoreWitness.Locked(ctx, func(current string, advance func(string) error) error {
		return fn(current, func(next string) error {
			if err := advance(next); err != nil {
				return err
			}
			close(w.advanced)
			w.cancel()
			select {
			case <-w.release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	})
}
func TestR2DGitS5RestoreCommitSurvivesCallerCancelAndSerializesReaders(t *testing.T) {
	f := newGitHTTPFixture(t)
	g := gitRestoreFixture(t, f)
	base := g.Witness
	request, cancel := context.WithCancel(context.Background())
	defer cancel()
	paused := pausedRestoreWitness{RestoreWitness: base, advanced: make(chan struct{}), release: make(chan struct{}), cancel: cancel}
	g.Witness = paused
	done := make(chan error, 1)
	go func() {
		done <- f.h.GitSecurity.MutateAuthority(request, func(db r2dgit.Database) error { _, err := db.Exec(request, `SELECT 1`); return err })
	}()
	select {
	case <-paused.advanced:
	case <-time.After(time.Second):
		t.Fatal("writer did not advance witness")
	}
	read := make(chan error, 1)
	go func() { read <- f.h.GitSecurity.CheckSourceState(context.Background()) }()
	select {
	case err := <-read:
		t.Fatalf("reader observed uncommitted checkpoint: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(paused.release)
	if err := <-done; err != nil {
		t.Fatal("caller cancellation broke durable finalization", err)
	}
	if err := <-read; err != nil {
		t.Fatal("normal writer looked like restore", err)
	}
	g.Witness = base
	if err := f.h.GitSecurity.CheckSourceState(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type pausedReadFinalization struct {
	r2dgit.RestoreWitness
	calls   atomic.Int32
	paused  chan struct{}
	release chan struct{}
}

func (w *pausedReadFinalization) Locked(ctx context.Context, fn func(string, func(string) error) error) error {
	if w.calls.Add(1) == 2 {
		close(w.paused)
		select {
		case <-w.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return w.RestoreWitness.Locked(ctx, fn)
}
func TestR2DGitS5RestoreReadonlySnapshotCannotOutliveCommittedOffboarding(t *testing.T) {
	f := newGitHTTPFixture(t)
	f.ready(t)
	ctx := context.Background()
	run, err := f.h.GitSecurity.EnqueueHuman(ctx, f.user, f.workspace, f.runRequest())
	if err != nil {
		t.Fatal(err)
	}
	g := gitRestoreFixture(t, f)
	base := g.Witness
	paused := &pausedReadFinalization{RestoreWitness: base, paused: make(chan struct{}), release: make(chan struct{})}
	g.Witness = paused
	type result struct {
		rights r2dgit.CurrentRights
		err    error
	}
	done := make(chan result, 1)
	go func() {
		rights, err := f.h.GitSecurity.Current(ctx, run.Context, run.Grant)
		done <- result{rights, err}
	}()
	select {
	case <-paused.paused:
	case <-time.After(time.Second):
		t.Fatal("authorization did not reach finalization")
	}
	if err := f.h.GitSecurity.MutateAuthority(ctx, func(db r2dgit.Database) error {
		_, err := db.Exec(ctx, `DELETE FROM member WHERE workspace_id=$1 AND user_id=$2`, f.workspace, f.user)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	close(paused.release)
	got := <-done
	if got.err == nil && got.rights.ActiveHuman {
		t.Fatal("stale authorization survived committed offboarding")
	}
	g.Witness = base
	if err := f.h.GitSecurity.CheckSourceState(ctx); err != nil {
		t.Fatal("normal concurrency was misdiagnosed as DB restore", err)
	}
}
