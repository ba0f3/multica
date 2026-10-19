package r2dgit

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/multica-ai/multica/server/pkg/dbid"
)

type RunRequest struct {
	AgentID      string      `json:"agent_id"`
	IssueID      string      `json:"issue_id"`
	RepositoryID string      `json:"repository_id"`
	Operations   []Operation `json:"operations"`
	WriteRefs    []string    `json:"write_refs"`
}
type RunInfo struct {
	Context            ContextSpec `json:"context"`
	Grant              GrantSpec   `json:"grant"`
	ExecutionAvailable bool        `json:"execution_available"`
}

func loadTaskBinding(ctx context.Context, db Database, taskID string) (TaskBinding, string, error) {
	var b TaskBinding
	var status string
	err := db.QueryRow(ctx, `SELECT t.id::text,t.agent_id::text,t.runtime_id::text,a.workspace_id::text,p.workspace_id::text,p.id::text,
 COALESCE(t.originator_user_id::text,''),COALESCE(t.originator_source,''),COALESCE(t.delegated_from_task_id::text,''),t.status
 FROM agent_task_queue t JOIN agent a ON a.id=t.agent_id AND a.runtime_id=t.runtime_id AND a.archived_at IS NULL
 JOIN agent_runtime runtime ON runtime.id=t.runtime_id AND runtime.workspace_id=a.workspace_id
 JOIN issue i ON i.id=t.issue_id JOIN project p ON p.id=i.project_id AND p.workspace_id=i.workspace_id WHERE t.id=$1`, taskID).Scan(&b.TaskID, &b.AgentID, &b.RuntimeID, &b.ExecutionWorkspaceID, &b.ResourceWorkspaceID, &b.ProjectID, &b.OriginatorUserID, &b.OriginatorSource, &b.ParentTaskID, &status)
	return b, status, err
}

func resolveNewBinding(ctx context.Context, tx pgx.Tx, user, workspace string, request RunRequest, now time.Time) (TaskBinding, error) {
	var b TaskBinding
	var invocable bool
	err := tx.QueryRow(ctx, `SELECT a.id::text,a.runtime_id::text,a.workspace_id::text,p.id::text,p.workspace_id::text,
 (a.owner_id=$1 OR (a.permission_mode='public_to' AND EXISTS(SELECT 1 FROM agent_invocation_target target WHERE target.agent_id=a.id AND
 ((target.target_type='member' AND target.target_id=$1) OR (target.target_type='workspace' AND target.target_id=a.workspace_id)))))
 FROM agent a JOIN agent_runtime runtime ON runtime.id=a.runtime_id AND runtime.workspace_id=a.workspace_id
 JOIN issue i ON i.id=$3 JOIN project p ON p.id=i.project_id AND p.workspace_id=i.workspace_id
 WHERE a.id=$2 AND a.workspace_id=$4 AND a.archived_at IS NULL AND EXISTS(SELECT 1 FROM member m WHERE m.workspace_id=a.workspace_id AND m.user_id=$1 AND m.role IN ('owner','admin','member'))`, user, request.AgentID, request.IssueID, workspace).Scan(&b.AgentID, &b.RuntimeID, &b.ExecutionWorkspaceID, &b.ProjectID, &b.ResourceWorkspaceID, &invocable)
	if err != nil || !invocable {
		return b, ErrScope
	}
	rank, err := projectRole(ctx, tx, user, b.ProjectID)
	if err != nil || rank < 2 {
		return b, ErrScope
	}
	b.OriginatorUserID = user
	if !restoredExecutionAllowed(ctx, tx, b, now) {
		return b, ErrRevoked
	}
	return b, nil
}

func grantFor(ctx context.Context, tx pgx.Tx, run RunSecurityContext, request RunRequest, now time.Time) (GrantSpec, error) {
	var g GrantSpec
	var read, write bool
	var refs, consent []byte
	var revoked bool
	var state string
	err := tx.QueryRow(ctx, `SELECT repo.id::text,repo.provider_id::text,identity.id::text,identity.active_generation,repo.epoch,repo.allow_read,repo.allow_write,repo.write_refs,identity.revoked,key.state,key.consent_project_ids
 FROM r2d_git_repository repo JOIN r2d_git_provider provider ON provider.id=repo.provider_id AND provider.enabled
 JOIN r2d_git_identity identity ON identity.provider_id=repo.provider_id AND identity.user_id=$1
 JOIN r2d_git_key key ON key.identity_id=identity.id AND key.generation=identity.active_generation
 WHERE repo.id=$2 AND repo.project_id=$3 AND repo.protected FOR SHARE OF repo,identity,key`, run.spec.Binding.OriginatorUserID, request.RepositoryID, run.spec.Binding.ProjectID).Scan(&g.RepositoryID, &g.ProviderID, &g.IdentityID, &g.CredentialGeneration, &g.Epoch, &read, &write, &refs, &revoked, &state, &consent)
	if err != nil || revoked || state != "ready" || !read {
		return g, ErrScope
	}
	var allowedRefs, projects []string
	if json.Unmarshal(refs, &allowedRefs) != nil || json.Unmarshal(consent, &projects) != nil {
		return g, ErrScope
	}
	allowedProject := false
	for _, p := range projects {
		if p == run.spec.Binding.ProjectID {
			allowedProject = true
		}
	}
	if !allowedProject {
		return g, ErrScope
	}
	for _, op := range request.Operations {
		if op == Write && !write {
			return g, ErrScope
		}
	}
	for _, ref := range request.WriteRefs {
		found := false
		for _, allowed := range allowedRefs {
			if allowed == ref {
				found = true
			}
		}
		if !found {
			return g, ErrScope
		}
	}
	g.ID = uuid.NewString()
	g.ContextID = run.spec.ID
	g.Operations = append([]Operation(nil), request.Operations...)
	g.WriteRefs = append([]string(nil), request.WriteRefs...)
	g.IssuedAt = now
	g.ExpiresAt = run.spec.ExpiresAt
	return g, nil
}

func persistRun(ctx context.Context, tx pgx.Tx, run RunSecurityContext, grant RepositoryGrant, issueID, kind string) error {
	if err := quarantineScopes(ctx, tx, []string{run.spec.Binding.ExecutionWorkspaceID, run.spec.Binding.ResourceWorkspaceID}, []string{run.spec.Binding.OriginatorUserID}); err != nil {
		return err
	}
	b := run.spec.Binding
	params := db.CreateAgentTaskParams{ID: util.MustParseUUID(b.TaskID), AgentID: util.MustParseUUID(b.AgentID), RuntimeID: util.MustParseUUID(b.RuntimeID), IssueID: util.MustParseUUID(issueID), OriginatorUserID: util.MustParseUUID(b.OriginatorUserID), AccountableUserID: util.MustParseUUID(b.OriginatorUserID), OriginatorSource: pgtype.Text{String: b.OriginatorSource, Valid: true}, ForceFreshSession: pgtype.Bool{Bool: true, Valid: true}}
	if b.ParentTaskID != "" {
		params.DelegatedFromTaskID = util.MustParseUUID(b.ParentTaskID)
	}
	if _, err := db.New(tx).CreateAgentTask(ctx, params); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO r2d_git_run_context(id,task_id,root_id,parent_id,authorizing_user_id,spec,derivation) VALUES($1,$2,$3,$4,$5,$6,$7)`, run.spec.ID, b.TaskID, run.spec.RootID, nullID(run.spec.ParentID), b.OriginatorUserID, encode(run.spec), kind); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO r2d_git_run_grant(id,context_id,identity_id,spec) VALUES($1,$2,$3,$4)`, grant.spec.ID, run.spec.ID, grant.spec.IdentityID, encode(grant.spec)); err != nil {
		return err
	}
	return event(ctx, tx, b.OriginatorUserID, run.spec.ID, "run_authorized")
}
func nullID(id string) any {
	if id == "" {
		return nil
	}
	return id
}

func lockRunWorkspaces(ctx context.Context, tx pgx.Tx, b TaskBinding) error {
	rows, err := tx.Query(ctx, `SELECT id FROM workspace WHERE id IN ($1,$2) ORDER BY id FOR SHARE`, b.ExecutionWorkspaceID, b.ResourceWorkspaceID)
	if err != nil {
		return err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		count++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	want := 2
	if b.ExecutionWorkspaceID == b.ResourceWorkspaceID {
		want = 1
	}
	if count != want {
		return ErrScope
	}
	return nil
}

// EnqueueHuman is a distinct, non-coalescing admission path. The handler must
// supply a proven human session; no caller-supplied originator is accepted.
// Task + context + grant + audit commit together. Claim remains denied until the
// complete execution boundary is available, even for self-advertised runtimes.
func (s *Service) EnqueueHuman(ctx context.Context, user, executionWorkspace string, request RunRequest) (RunInfo, error) {
	var out RunInfo
	err := s.Store.transaction(ctx, func(tx pgx.Tx) error {
		binding, err := resolveNewBinding(ctx, tx, user, executionWorkspace, request, s.Now())
		if err != nil {
			return err
		}
		if err := lockRunWorkspaces(ctx, tx, binding); err != nil {
			return err
		}
		var epoch uint64
		if err := tx.QueryRow(ctx, `SELECT epoch FROM r2d_git_project_policy WHERE project_id=$1 AND workspace_id=$2 FOR SHARE`, binding.ProjectID, binding.ResourceWorkspaceID).Scan(&epoch); err != nil {
			return ErrScope
		}
		rank, err := projectRole(ctx, tx, user, binding.ProjectID)
		if err != nil || rank < 2 {
			return ErrScope
		}
		binding.TaskID = util.UUIDToString(dbid.NewV7())
		binding.OriginatorSource = "direct_human"
		now := s.Now().UTC()
		run, err := NewHumanRoot(uuid.NewString(), uuid.NewString(), user, binding, epoch, now, now.Add(time.Hour))
		if err != nil {
			return err
		}
		spec, err := grantFor(ctx, tx, run, request, now)
		if err != nil {
			return err
		}
		grant, err := NewGrant(run, spec, now)
		if err != nil {
			return err
		}
		if err := persistRun(ctx, tx, run, grant, request.IssueID, "human"); err != nil {
			return err
		}
		out = RunInfo{Context: run.Spec(), Grant: grant.Spec()}
		return nil
	})
	return out, err
}

func loadRun(ctx context.Context, db Database, id string, now time.Time) (RunSecurityContext, RepositoryGrant, error) {
	type entry struct {
		spec        ContextSpec
		kind, state string
	}
	var chain []entry
	seen := map[string]bool{}
	for id != "" {
		if seen[id] || len(chain) > MaxDelegationDepth {
			return RunSecurityContext{}, RepositoryGrant{}, ErrPrincipal
		}
		seen[id] = true
		var raw []byte
		var e entry
		if err := db.QueryRow(ctx, `SELECT spec,derivation,state FROM r2d_git_run_context WHERE id=$1`, id).Scan(&raw, &e.kind, &e.state); err != nil {
			return RunSecurityContext{}, RepositoryGrant{}, err
		}
		if json.Unmarshal(raw, &e.spec) != nil || e.spec.ID != id || e.state == "revoked" {
			return RunSecurityContext{}, RepositoryGrant{}, ErrRevoked
		}
		chain = append(chain, e)
		id = e.spec.ParentID
	}
	if len(chain) == 0 {
		return RunSecurityContext{}, RepositoryGrant{}, ErrScope
	}
	var run RunSecurityContext
	for i := len(chain) - 1; i >= 0; i-- {
		e := chain[i]
		var reconstructed RunSecurityContext
		var err error
		if i == len(chain)-1 {
			if e.kind != "human" {
				return run, RepositoryGrant{}, ErrPrincipal
			}
			reconstructed, err = NewHumanRoot(e.spec.ID, e.spec.AttemptID, e.spec.Binding.OriginatorUserID, e.spec.Binding, e.spec.PolicyEpoch, e.spec.IssuedAt, e.spec.ExpiresAt)
		} else {
			if e.kind != "delegation" && e.kind != "retry" {
				return run, RepositoryGrant{}, ErrPrincipal
			}
			reconstructed, err = Derive(run, e.spec.ID, e.spec.AttemptID, e.spec.Binding, Derivation(e.kind), e.spec.IssuedAt, e.spec.ExpiresAt)
		}
		if err != nil || reconstructed.spec != e.spec {
			return run, RepositoryGrant{}, ErrPrincipal
		}
		run = reconstructed
	}
	if !run.valid(now) {
		return run, RepositoryGrant{}, ErrRevoked
	}
	var previous RepositoryGrant
	for i := len(chain) - 1; i >= 0; i-- {
		var raw []byte
		var state string
		var spec GrantSpec
		if err := db.QueryRow(ctx, `SELECT spec,state FROM r2d_git_run_grant WHERE context_id=$1`, chain[i].spec.ID).Scan(&raw, &state); err != nil {
			return run, RepositoryGrant{}, err
		}
		if json.Unmarshal(raw, &spec) != nil || state != "active" {
			return run, RepositoryGrant{}, ErrRevoked
		}
		part := RunSecurityContext{spec: chain[i].spec}
		var g RepositoryGrant
		var err error
		if i == len(chain)-1 {
			g, err = NewGrant(part, spec, spec.IssuedAt)
		} else {
			g, err = NarrowGrant(previous, part, spec, spec.IssuedAt)
		}
		if err != nil {
			return run, RepositoryGrant{}, err
		}
		previous = g
	}
	if _, err := validateGrant(run, previous.spec, now); err != nil {
		return run, previous, err
	}
	return run, previous, nil
}

func (s *Service) GetRun(ctx context.Context, user, id string) (RunInfo, error) {
	var owned bool
	if err := s.Store.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM r2d_git_run_context WHERE id=$1 AND authorizing_user_id=$2)`, id, user).Scan(&owned); err != nil {
		return RunInfo{}, err
	}
	if !owned {
		return RunInfo{}, ErrScope
	}
	r, g, err := loadRun(ctx, s.Store.DB, id, s.Now())
	if err != nil {
		return RunInfo{}, err
	}
	if r.spec.Binding.OriginatorUserID != user {
		return RunInfo{}, ErrScope
	}
	c, err := s.Current(ctx, r.spec, g.spec)
	if err != nil || !currentIssuable(c, r, g) {
		return RunInfo{}, ErrScope
	}
	return RunInfo{Context: r.Spec(), Grant: g.Spec()}, nil
}
func currentIssuable(c CurrentRights, r RunSecurityContext, g RepositoryGrant) bool {
	return c.Binding == r.spec.Binding && c.ActiveHuman && c.ProjectContribute && c.ProjectRead && c.RepositoryRead && c.ContextActive && c.RootActive && c.GrantActive && c.IdentityReady && c.PolicyEpoch == r.spec.PolicyEpoch && c.GrantEpoch == g.spec.Epoch && c.CredentialGeneration == g.spec.CredentialGeneration
}

// EnqueueChild accepts the authenticated task token's exact parent task/agent/
// workspace. Mutable X-User-ID, agent owner and body IDs never choose the human.
func (s *Service) EnqueueChild(ctx context.Context, parentID, tokenTask, tokenAgent, tokenWorkspace string, request RunRequest) (RunInfo, error) {
	var out RunInfo
	err := s.Store.transaction(ctx, func(tx pgx.Tx) error {
		parent, pg, err := loadRun(ctx, tx, parentID, s.Now())
		if err != nil {
			return err
		}
		b := parent.spec.Binding
		if b.TaskID != tokenTask || b.AgentID != tokenAgent || b.ExecutionWorkspaceID != tokenWorkspace {
			return ErrPrincipal
		}
		if err := lockRunWorkspaces(ctx, tx, b); err != nil {
			return err
		}
		// Serialize child admission with root cancellation and project policy
		// revocation. Re-read authoritative facts after waiting for these locks.
		if _, err := tx.Exec(ctx, `SELECT id FROM r2d_git_run_context WHERE root_id=$1 ORDER BY id FOR SHARE`, parent.spec.RootID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT project_id FROM r2d_git_project_policy WHERE project_id=$1 FOR SHARE`, b.ProjectID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT id FROM agent_task_queue WHERE id=$1 FOR SHARE`, tokenTask); err != nil {
			return err
		}
		actual, status, err := loadTaskBinding(ctx, tx, tokenTask)
		if err != nil || actual != b || (status != "running" && status != "dispatched") {
			return ErrPrincipal
		}
		c, err := s.currentIn(ctx, tx, parent.spec, pg.spec)
		if err != nil || !currentIssuable(c, parent, pg) {
			return ErrScope
		}
		childBinding, err := resolveNewBinding(ctx, tx, b.OriginatorUserID, tokenWorkspace, request, s.Now())
		if err != nil {
			return err
		}
		childBinding.TaskID = util.UUIDToString(dbid.NewV7())
		childBinding.ParentTaskID = b.TaskID
		childBinding.OriginatorSource = "delegation"
		now := s.Now().UTC()
		child, err := Derive(parent, uuid.NewString(), uuid.NewString(), childBinding, Delegation, now, parent.spec.ExpiresAt)
		if err != nil {
			return err
		}
		spec, err := grantFor(ctx, tx, child, request, now)
		if err != nil {
			return err
		}
		// grantFor locks the current identity/key. A rotation or revocation
		// committed while admission waited must invalidate the parent grant.
		c, err = s.currentIn(ctx, tx, parent.spec, pg.spec)
		if err != nil || !currentIssuable(c, parent, pg) {
			return ErrScope
		}
		grant, err := NarrowGrant(pg, child, spec, now)
		if err != nil {
			return err
		}
		if err := persistRun(ctx, tx, child, grant, request.IssueID, "delegation"); err != nil {
			return err
		}
		out = RunInfo{Context: child.Spec(), Grant: grant.Spec()}
		return nil
	})
	return out, err
}

// Current implements the S0 Authority using a fresh consistent authoritative
// snapshot. There is intentionally no certified runtime yet: Runtime remains
// ineligible, regardless of advertised daemon capabilities.
func (s *Service) Current(ctx context.Context, spec ContextSpec, grant GrantSpec) (CurrentRights, error) {
	var out CurrentRights
	err := s.Store.readOnly(ctx, func(tx pgx.Tx) error {
		out = CurrentRights{}
		var err error
		out, err = s.currentIn(ctx, tx, spec, grant)
		return err
	})
	return out, err
}
func (s *Service) currentIn(ctx context.Context, db Database, spec ContextSpec, grant GrantSpec) (CurrentRights, error) {
	var c CurrentRights
	if err := s.checkRestore(ctx, db); err != nil {
		return c, err
	}
	r, g, err := loadRun(ctx, db, spec.ID, s.Now())
	if err != nil {
		return c, err
	}
	if r.spec != spec || !reflect.DeepEqual(g.spec, grant) {
		return c, ErrPrincipal
	}
	c.Binding, _, err = loadTaskBinding(ctx, db, spec.Binding.TaskID)
	if err != nil {
		return c, err
	}
	var status string
	if err := db.QueryRow(ctx, `SELECT status FROM agent_task_queue WHERE id=$1`, spec.Binding.TaskID).Scan(&status); err != nil {
		return c, err
	}
	// A normally completed ancestor may have live children; cancelled/failed
	// roots revoke every descendant, even if their context row was untouched.
	chain := append(append([]ContextSpec{}, r.ancestors...), r.spec)
	for index, ancestor := range chain {
		if !restoredExecutionAllowed(ctx, db, ancestor.Binding, s.Now()) {
			return c, ErrRevoked
		}
		binding, _, err := loadTaskBinding(ctx, db, ancestor.Binding.TaskID)
		if err != nil || binding != ancestor.Binding {
			return c, ErrPrincipal
		}
		var state string
		if err := db.QueryRow(ctx, `SELECT status FROM agent_task_queue WHERE id=$1`, ancestor.Binding.TaskID).Scan(&state); err != nil {
			return c, err
		}
		explicitRetry := index+1 < len(chain) && r.derivations[chain[index+1].ID] == Retry
		if state == "cancelled" || (state == "failed" && !explicitRetry) {
			return c, ErrRevoked
		}
	}
	c.ActiveHuman = activeHuman(ctx, db, spec.Binding.OriginatorUserID)
	var invocable bool
	if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent a JOIN member m ON m.workspace_id=a.workspace_id AND m.user_id=$1 AND m.role IN ('owner','admin','member') WHERE a.id=$2 AND a.workspace_id=$3 AND (a.owner_id=$1 OR (a.permission_mode='public_to' AND EXISTS(SELECT 1 FROM agent_invocation_target t WHERE t.agent_id=a.id AND ((t.target_type='member' AND t.target_id=$1) OR (t.target_type='workspace' AND t.target_id=a.workspace_id))))))`, spec.Binding.OriginatorUserID, spec.Binding.AgentID, spec.Binding.ExecutionWorkspaceID).Scan(&invocable); err != nil {
		return c, err
	}
	c.ActiveHuman = c.ActiveHuman && invocable && restoredExecutionAllowed(ctx, db, spec.Binding, s.Now())
	rank, err := projectRole(ctx, db, spec.Binding.OriginatorUserID, spec.Binding.ProjectID)
	if err != nil {
		return c, err
	}
	c.ProjectRead = rank >= 1
	c.ProjectContribute = rank >= 2
	var contextState string
	if err := db.QueryRow(ctx, `SELECT state FROM r2d_git_run_context WHERE id=$1`, spec.ID).Scan(&contextState); err != nil {
		return c, err
	}
	c.ContextActive = contextState == "active" && (status == "queued" || status == "dispatched" || status == "running")
	c.RootActive = true
	c.GrantActive = true
	if err := db.QueryRow(ctx, `SELECT epoch FROM r2d_git_project_policy WHERE project_id=$1 AND workspace_id=$2`, spec.Binding.ProjectID, spec.Binding.ResourceWorkspaceID).Scan(&c.PolicyEpoch); err != nil {
		return c, err
	}
	var consent []byte
	var state string
	var revoked bool
	var owner string
	err = db.QueryRow(ctx, `SELECT i.user_id::text,i.active_generation,i.revoked,k.state,k.consent_project_ids FROM r2d_git_identity i JOIN r2d_git_key k ON k.identity_id=i.id AND k.generation=i.active_generation WHERE i.id=$1 AND i.provider_id=$2`, grant.IdentityID, grant.ProviderID).Scan(&owner, &c.CredentialGeneration, &revoked, &state, &consent)
	if err != nil {
		return c, err
	}
	var projects []string
	if json.Unmarshal(consent, &projects) != nil {
		return c, ErrScope
	}
	for _, p := range projects {
		if p == spec.Binding.ProjectID {
			c.IdentityReady = state == "ready" && !revoked && owner == spec.Binding.OriginatorUserID
		}
	}
	var refs []byte
	err = db.QueryRow(ctx, `SELECT r.provider_id::text,r.id::text,r.epoch,r.allow_read,r.allow_write,r.write_refs FROM r2d_git_repository r JOIN r2d_git_provider p ON p.id=r.provider_id AND p.enabled WHERE r.id=$1 AND r.project_id=$2 AND r.protected`, grant.RepositoryID, spec.Binding.ProjectID).Scan(&c.ProviderID, &c.RepositoryID, &c.GrantEpoch, &c.RepositoryRead, &c.RepositoryWrite, &refs)
	if err != nil {
		return c, err
	}
	if json.Unmarshal(refs, &c.AllowedWriteRefs) != nil {
		return c, ErrScope
	}
	c.IdentityID = grant.IdentityID
	return c, nil
}

func (s *Service) RevokeRoot(ctx context.Context, user, id string) error {
	return s.Store.transaction(ctx, func(tx pgx.Tx) error {
		var root string
		if err := tx.QueryRow(ctx, `SELECT root_id::text FROM r2d_git_run_context WHERE id=$1 AND authorizing_user_id=$2`, id, user).Scan(&root); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE r2d_git_run_context SET state='revoked' WHERE root_id=$1`, root); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE r2d_git_run_grant SET state='revoked' WHERE context_id IN (SELECT id FROM r2d_git_run_context WHERE root_id=$1)`, root); err != nil {
			return err
		}
		return event(ctx, tx, user, root, "root_revoked")
	})
}

var _ Authority = (*Service)(nil)
