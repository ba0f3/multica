package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/multica-ai/multica/server/internal/r2dgit"
	"github.com/multica-ai/multica/server/internal/testutil"
	"testing"
)

func TestR2DGitS5OutputUnionRetainsEveryOriginAndReader(t *testing.T) {
	f := newGitHTTPFixture(t)
	s := f.h.GitSecurity
	ctx := context.Background()
	project := dbfx.Insert(t, "project", testutil.Cols{"workspace_id": f.resourceWorkspace, "title": "Synthetic second source"})
	issue := dbfx.Issue(t, "Second source", testutil.Cols{"workspace_id": f.resourceWorkspace, "project_id": project})
	repo := dbfx.Insert(t, "r2d_git_repository", testutil.Cols{"id": uuid.NewString(), "project_id": project, "provider_id": f.provider, "canonical_repository": "fixtures/second"})
	for _, user := range []string{f.user, f.other} {
		if err := s.SetProjectGrant(ctx, testUserID, project, "user", user, "member"); err != nil {
			t.Fatal(err)
		}
	}
	for _, user := range []string{f.user, f.other} {
		projects := []string{project}
		if user == f.user {
			projects = append(projects, f.project)
		}
		key, err := s.Generate(ctx, user, f.provider, uuid.NewString(), projects)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.Verify(ctx, user, key.ID, key.Generation); err != nil {
			t.Fatal(err)
		}
	}
	a, err := s.EnqueueHuman(ctx, f.user, f.workspace, f.runRequest())
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.EnqueueHuman(ctx, f.other, f.workspace, r2dgit.RunRequest{AgentID: f.agent, IssueID: issue, RepositoryID: repo, Operations: []r2dgit.Operation{r2dgit.Read}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		dbfx.Exec(t, `DELETE FROM r2d_git_output_input WHERE output_id IN(SELECT id FROM r2d_git_output WHERE context_id=$1) OR input_id IN(SELECT id FROM r2d_git_output WHERE context_id=$1)`, b.Context.ID)
		dbfx.Exec(t, `DELETE FROM r2d_git_output WHERE context_id=$1`, b.Context.ID)
		dbfx.Exec(t, `DELETE FROM agent_task_queue WHERE id=$1`, b.Context.Binding.TaskID)
		dbfx.Exec(t, `DELETE FROM r2d_git_run_grant WHERE context_id=$1`, b.Context.ID)
		dbfx.Exec(t, `DELETE FROM r2d_git_run_context WHERE id=$1`, b.Context.ID)
		dbfx.Exec(t, `DELETE FROM r2d_git_project_grant WHERE project_id=$1`, project)
		dbfx.Exec(t, `DELETE FROM r2d_git_project_policy WHERE project_id=$1`, project)
	})
	dbfx.Exec(t, `UPDATE agent_task_queue SET status='running' WHERE id IN($1,$2)`, a.Context.Binding.TaskID, b.Context.Binding.TaskID)
	s.OutputProof = &outputFixtureProof{allowed: map[string]bool{f.user: true, f.other: true}}
	input, err := s.StoreOutput(ctx, b.Context.ID, b.Context.Binding.TaskID, f.agent, f.workspace, "artifact", []byte("synthetic second source"))
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.Repeat([]byte("synthetic derived source\n"), 2000)
	output, err := s.StoreOutputFromInputs(ctx, a.Context.ID, a.Context.Binding.TaskID, f.agent, f.workspace, "artifact", body, []string{input})
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	dbfx.QueryRow(t, `SELECT classification FROM r2d_git_output WHERE id=$1`, output).Scan(&raw)
	var sources []r2dgit.OutputSource
	if json.Unmarshal(raw, &sources) != nil || len(sources) != 2 || sources[0].ContextID == "" || sources[1].ContextID == "" {
		t.Fatal("lost source union", string(raw))
	}
	got, err := s.ReadOutput(ctx, f.user, output)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatal("authorized union read", err)
	}
	if _, err = s.ReadOutput(ctx, f.other, output); err == nil {
		t.Fatal("one-source reader accessed union")
	}
	if _, err = s.StoreOutputFromInputs(ctx, a.Context.ID, a.Context.Binding.TaskID, f.agent, f.workspace, "artifact", body, []string{input, input}); err == nil {
		t.Fatal("duplicate input admitted")
	}
	if _, err = s.StoreOutputFromInputs(ctx, a.Context.ID, a.Context.Binding.TaskID, f.agent, f.workspace, "artifact", body, []string{uuid.NewString()}); err == nil {
		t.Fatal("missing input admitted")
	}
	// Rights to one source cannot be replaced by rights to the destination source.
	if err = s.SetProjectGrant(ctx, testUserID, project, "user", f.user, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadOutput(ctx, f.user, output); err == nil {
		t.Fatal("revoked source grant ignored")
	}
	if err = s.SetProjectGrant(ctx, testUserID, project, "user", f.user, "member"); err != nil {
		t.Fatal(err)
	}
	// The original B context is retained even though A authored the derived output.
	sink := &gitDeliveryMemorySink{afterFirst: func() {
		if err := s.RevokeRoot(ctx, f.other, b.Context.ID); err != nil {
			t.Error(err)
		}
	}}
	if err = s.DeliverOutput(ctx, f.user, output, sink); err == nil || sink.Len() != 16384 {
		t.Fatalf("source revocation did not stop union stream: %d %v", sink.Len(), err)
	}
	// Removing provenance cannot silently declassify a derived record, even when
	// the same reader still has its destination grant.
	dbfx.Exec(t, `DELETE FROM r2d_git_output_input WHERE output_id=$1`, output)
	if _, err = s.ReadOutput(ctx, f.user, output); err == nil {
		t.Fatal("deleted dependency declassified output")
	}
	// A fabricated cycle is refused rather than followed or flattened away.
	dbfx.Exec(t, `INSERT INTO r2d_git_output_input(output_id,input_id) VALUES($1,$1)`, output)
	if _, err = s.ReadOutput(ctx, f.user, output); err == nil {
		t.Fatal("provenance cycle admitted")
	}
}
