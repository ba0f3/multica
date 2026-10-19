package r2dgit

import (
	"context"
	"encoding/json"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type RepositoryProver interface {
	ProveRepository(context.Context, BoundOperation) error
}
type OutputSource struct {
	ContextID    string `json:"context_id,omitempty"`
	ProjectID    string `json:"project_id"`
	ProviderID   string `json:"provider_id"`
	RepositoryID string `json:"repository_id"`
}

// StoreOutput accepts content only from the exact authenticated task. Source
// classification is generated from sealed grants, never the payload or headers.
// It emits no narrative event, notification, comment, search row or public URL.
func (s *Service) StoreOutput(ctx context.Context, contextID, taskID, agentID, workspaceID, kind string, body []byte) (string, error) {
	return s.StoreOutputFromInputs(ctx, contextID, taskID, agentID, workspaceID, kind, body, nil)
}

// StoreOutputFromInputs is trusted application composition, not a workload
// selector. Every input adds its entire immutable provenance; the destination's
// own sealed source can never be removed. The public task endpoint takes no IDs.
func (s *Service) StoreOutputFromInputs(ctx context.Context, contextID, taskID, agentID, workspaceID, kind string, body []byte, inputs []string) (string, error) {
	if len(body) == 0 || len(body) > 1<<20 || (kind != "transcript" && kind != "tool" && kind != "diff" && kind != "artifact") {
		return "", ErrScope
	}
	if len(inputs) > 8 {
		return "", ErrScope
	}
	var origin string
	if s.Store.DB.QueryRow(ctx, `SELECT authorizing_user_id::text FROM r2d_git_run_context WHERE id=$1`, contextID).Scan(&origin) != nil {
		return "", ErrScope
	}
	inputPlans := make([]outputPlan, len(inputs))
	seenInputs := map[string]bool{}
	for i, input := range inputs {
		if seenInputs[input] || uuid.Validate(input) != nil {
			return "", ErrScope
		}
		seenInputs[input] = true
		raw, err := s.ReadOutput(ctx, origin, input)
		clear(raw)
		if err != nil {
			return "", err
		}
		inputPlans[i], err = s.readOutputPlan(ctx, origin, input)
		if err != nil {
			return "", err
		}
	}
	nodes := 1
	var bounded func(outputPlan, int) bool
	bounded = func(plan outputPlan, depth int) bool {
		nodes++
		if depth > 8 || nodes > 64 {
			return false
		}
		for _, child := range plan.Inputs {
			if !bounded(child, depth+1) {
				return false
			}
		}
		return true
	}
	for _, plan := range inputPlans {
		if !bounded(plan, 1) {
			return "", ErrScope
		}
	}
	var id string
	err := s.Store.transaction(ctx, func(tx pgx.Tx) error {
		r, g, err := s.lockOutputRun(ctx, tx, contextID)
		if err != nil {
			return err
		}
		b := r.spec.Binding
		if b.TaskID != taskID || b.AgentID != agentID || b.ExecutionWorkspaceID != workspaceID {
			return ErrPrincipal
		}
		var status string
		var count int
		if tx.QueryRow(ctx, `SELECT status FROM agent_task_queue WHERE id=$1`, taskID).Scan(&status) != nil || status != "running" {
			return ErrRevoked
		}
		if tx.QueryRow(ctx, `SELECT count(*) FROM r2d_git_run_grant WHERE context_id=$1`, contextID).Scan(&count) != nil || count != 1 {
			return ErrScope
		}
		id = uuid.NewString()
		classification := []OutputSource{{ContextID: r.spec.ID, ProjectID: b.ProjectID, ProviderID: g.spec.ProviderID, RepositoryID: g.spec.RepositoryID}}
		seen := map[OutputSource]bool{classification[0]: true}
		for i, input := range inputs {
			current, err := s.outputPlan(ctx, tx, origin, input)
			if err != nil || !reflect.DeepEqual(inputPlans[i], current) {
				return ErrRevoked
			}
			for _, access := range current.Access {
				if !seen[access.Source] {
					seen[access.Source] = true
					classification = append(classification, access.Source)
				}
			}
		}
		if len(classification) > 64 {
			return ErrScope
		}
		if _, err := tx.Exec(ctx, `INSERT INTO r2d_git_output(id,context_id,classification,kind,body) VALUES($1,$2,$3,$4,$5)`, id, contextID, encode(classification), kind, body); err != nil {
			return err
		}
		for _, input := range inputs {
			if _, err := tx.Exec(ctx, `INSERT INTO r2d_git_output_input(output_id,input_id) VALUES($1,$2)`, id, input); err != nil {
				return err
			}
		}
		return event(ctx, tx, b.OriginatorUserID, id, "restricted_output_stored")
	})
	return id, err
}

// lockOutputRun serializes source-classified writes and private lifecycle transitions.
func (s *Service) lockOutputRun(ctx context.Context, tx pgx.Tx, contextID string) (RunSecurityContext, RepositoryGrant, error) {
	r, g, err := loadRun(ctx, tx, contextID, s.Now())
	if err != nil {
		return RunSecurityContext{}, RepositoryGrant{}, err
	}
	b := r.spec.Binding
	if err := lockRunWorkspaces(ctx, tx, b); err != nil {
		return RunSecurityContext{}, RepositoryGrant{}, err
	}
	var ignored string
	if tx.QueryRow(ctx, `SELECT project_id::text FROM r2d_git_project_policy WHERE project_id=$1 FOR SHARE`, b.ProjectID).Scan(&ignored) != nil {
		return RunSecurityContext{}, RepositoryGrant{}, ErrScope
	}
	if tx.QueryRow(ctx, `SELECT id::text FROM r2d_git_identity WHERE id=$1 FOR SHARE`, g.spec.IdentityID).Scan(&ignored) != nil {
		return RunSecurityContext{}, RepositoryGrant{}, ErrIdentity
	}
	rows, err := tx.Query(ctx, `SELECT t.id FROM agent_task_queue t JOIN r2d_git_run_context c ON c.task_id=t.id WHERE c.root_id=$1 ORDER BY t.id FOR UPDATE OF t`, r.spec.RootID)
	if err != nil {
		return RunSecurityContext{}, RepositoryGrant{}, err
	}
	for rows.Next() {
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return RunSecurityContext{}, RepositoryGrant{}, err
	}
	if tx.QueryRow(ctx, `SELECT id::text FROM r2d_git_run_context WHERE id=$1 AND state<>'revoked' FOR SHARE`, r.spec.RootID).Scan(&ignored) != nil {
		return RunSecurityContext{}, RepositoryGrant{}, ErrRevoked
	}
	c, err := s.currentIn(ctx, tx, r.spec, g.spec)
	if err != nil {
		return RunSecurityContext{}, RepositoryGrant{}, err
	}
	if !c.ActiveHuman || !c.ProjectRead || !c.ProjectContribute || !c.RepositoryRead || !c.ContextActive || !c.RootActive || !c.GrantActive || !c.IdentityReady || c.Binding != b || c.PolicyEpoch != r.spec.PolicyEpoch || c.GrantEpoch != g.spec.Epoch || c.CredentialGeneration != g.spec.CredentialGeneration || c.IdentityID != g.spec.IdentityID || c.ProviderID != g.spec.ProviderID || c.RepositoryID != g.spec.RepositoryID {
		return RunSecurityContext{}, RepositoryGrant{}, ErrRevoked
	}

	return r, g, nil
}

type outputAccess struct {
	Source                           OutputSource
	Operation                        BoundOperation
	PolicyEpoch, RepoEpoch, KeyEpoch uint64
	Provider                         Provider
	Fingerprint                      string
}
type outputPlan struct {
	ContextID, Kind, RootID string
	Binding                 TaskBinding
	Access                  []outputAccess
	InputIDs                []string
	Inputs                  []outputPlan
}

func (s *Service) outputPlan(ctx context.Context, db Database, user, id string) (outputPlan, error) {
	nodes := 0
	return s.outputPlanGraph(ctx, db, user, id, map[string]bool{}, 0, &nodes)
}
func (s *Service) outputPlanGraph(ctx context.Context, db Database, user, id string, path map[string]bool, depth int, nodes *int) (outputPlan, error) {
	var plan outputPlan
	(*nodes)++
	if depth > 8 || *nodes > 64 || path[id] {
		return plan, ErrScope
	}
	path[id] = true
	defer delete(path, id)
	if err := s.checkRestore(ctx, db); err != nil {
		return plan, err
	}
	if !activeHuman(ctx, db, user) {
		return plan, ErrPrincipal
	}
	var classification, spec []byte
	if err := db.QueryRow(ctx, `SELECT o.context_id::text,o.kind,o.classification,c.spec FROM r2d_git_output o JOIN r2d_git_run_context c ON c.id=o.context_id WHERE o.id=$1`, id).Scan(&plan.ContextID, &plan.Kind, &classification, &spec); err != nil {
		return plan, ErrScope
	}
	var sources []OutputSource
	var run ContextSpec
	if json.Unmarshal(classification, &sources) != nil || len(sources) == 0 || len(sources) > 64 || json.Unmarshal(spec, &run) != nil || run.ID != plan.ContextID {
		return plan, ErrScope
	}
	plan.RootID, plan.Binding = run.RootID, run.Binding
	var valid bool
	var lineage []byte
	if err := db.QueryRow(ctx, `WITH RECURSIVE chain AS (
 SELECT c.*,0 AS depth FROM r2d_git_run_context c WHERE c.id=$1
 UNION ALL SELECT p.*,chain.depth+1 FROM chain JOIN r2d_git_run_context p ON p.id=chain.parent_id WHERE chain.depth<16
 ) SELECT COALESCE(bool_and(chain.state<>'revoked' AND COALESCE((t.status NOT IN ('cancelled','failed') OR (t.status='failed' AND EXISTS(SELECT 1 FROM chain retry_child WHERE retry_child.parent_id=chain.id AND retry_child.derivation='retry'))),false)
 AND COALESCE(g.state='active' AND NOT identity.revoked AND identity.user_id=chain.authorizing_user_id AND identity.active_generation=(g.spec->>'credential_generation')::bigint AND key.state='ready',false)
 AND (SELECT count(*) FROM r2d_git_run_grant all_grants WHERE all_grants.context_id=chain.id)=1),false)
 AND COALESCE(bool_or(chain.id=chain.root_id AND chain.parent_id IS NULL),false)
 AND NOT COALESCE(bool_or(chain.depth=16 AND chain.parent_id IS NOT NULL),true),jsonb_agg(chain.spec ORDER BY chain.depth)
 FROM chain LEFT JOIN agent_task_queue t ON t.id=chain.task_id
 LEFT JOIN r2d_git_run_grant g ON g.context_id=chain.id
 LEFT JOIN r2d_git_identity identity ON identity.id=g.identity_id
 LEFT JOIN r2d_git_key key ON key.identity_id=identity.id AND key.generation=identity.active_generation`, plan.ContextID).Scan(&valid, &lineage); err != nil || !valid {
		return plan, ErrRevoked
	}
	var ancestors []ContextSpec
	if json.Unmarshal(lineage, &ancestors) != nil || len(ancestors) == 0 || len(ancestors) > MaxDelegationDepth+1 {
		return plan, ErrRevoked
	}
	for _, ancestor := range ancestors {
		if ancestor.RootID != run.RootID || ancestor.Binding.OriginatorUserID != run.Binding.OriginatorUserID || !outputOriginCurrent(ctx, db, ancestor.Binding, s.Now()) {
			return plan, ErrRevoked
		}
	}
	var grantRaw []byte
	var grant GrantSpec
	if db.QueryRow(ctx, `SELECT spec FROM r2d_git_run_grant WHERE context_id=$1`, plan.ContextID).Scan(&grantRaw) != nil || json.Unmarshal(grantRaw, &grant) != nil {
		return plan, ErrScope
	}
	ownSource := OutputSource{ContextID: run.ID, ProjectID: run.Binding.ProjectID, ProviderID: grant.ProviderID, RepositoryID: grant.RepositoryID}
	expected := map[OutputSource]bool{ownSource: true}
	rows, err := db.Query(ctx, `SELECT input_id::text FROM r2d_git_output_input WHERE output_id=$1 ORDER BY input_id LIMIT 9`, id)
	if err != nil {
		return plan, err
	}
	for rows.Next() {
		var input string
		if rows.Scan(&input) != nil {
			rows.Close()
			return plan, ErrScope
		}
		plan.InputIDs = append(plan.InputIDs, input)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(plan.InputIDs) > 8 {
		return plan, ErrScope
	}
	// Earlier immutable single-source rows already bind their context separately.
	// This compatibility applies only to those exact sealed triples, never a
	// derived row or unknown generic historical content.
	if len(sources) == 1 && len(plan.InputIDs) == 0 && sources[0].ContextID == "" {
		delete(expected, ownSource)
		ownSource.ContextID = ""
		expected[ownSource] = true
	}
	for _, input := range plan.InputIDs {
		child, err := s.outputPlanGraph(ctx, db, user, input, path, depth+1, nodes)
		if err != nil {
			return plan, err
		}
		plan.Inputs = append(plan.Inputs, child)
		for _, a := range child.Access {
			expected[a.Source] = true
		}
	}
	if len(sources) != len(expected) {
		return plan, ErrScope
	}
	seen := map[OutputSource]bool{}
	for _, source := range sources {
		if seen[source] || !nonempty(source.ProjectID, source.ProviderID, source.RepositoryID) || !expected[source] {
			return plan, ErrScope
		}
		seen[source] = true
		rank, err := projectRole(ctx, db, user, source.ProjectID)
		if err != nil || rank < 1 {
			return plan, ErrScope
		}
		a := outputAccess{Source: source, Operation: BoundOperation{UserID: user, ContextID: plan.ContextID, TaskID: run.Binding.TaskID, AttemptID: run.AttemptID, ProviderID: source.ProviderID, RepositoryID: source.RepositoryID, Operation: Read}}
		err = db.QueryRow(ctx, `SELECT p.epoch,r.epoch,i.id::text,i.active_generation,i.epoch,k.fingerprint FROM r2d_git_project_policy p
 JOIN r2d_git_repository r ON r.project_id=p.project_id AND r.id=$3 AND r.provider_id=$4 AND r.protected AND r.allow_read
 JOIN r2d_git_identity i ON i.provider_id=r.provider_id AND i.user_id=$1 AND NOT i.revoked
 JOIN r2d_git_key k ON k.identity_id=i.id AND k.generation=i.active_generation AND k.state='ready' AND k.consent_project_ids @> jsonb_build_array(p.project_id::text)
 JOIN project live ON live.id=p.project_id AND live.workspace_id=p.workspace_id
 WHERE p.project_id=$2`, user, source.ProjectID, source.RepositoryID, source.ProviderID).Scan(&a.PolicyEpoch, &a.RepoEpoch, &a.Operation.IdentityID, &a.Operation.Generation, &a.KeyEpoch, &a.Fingerprint)
		if err != nil {
			return plan, ErrScope
		}
		a.Provider, err = loadProvider(ctx, db, source.ProviderID)
		if err != nil {
			return plan, ErrScope
		}
		plan.Access = append(plan.Access, a)
	}
	return plan, nil
}

func outputOriginCurrent(ctx context.Context, db Database, b TaskBinding, now time.Time) bool {
	if !activeHuman(ctx, db, b.OriginatorUserID) {
		return false
	}
	binding, _, err := loadTaskBinding(ctx, db, b.TaskID)
	if err != nil || binding != b {
		return false
	}
	rank, err := projectRole(ctx, db, b.OriginatorUserID, b.ProjectID)
	if err != nil || rank < 2 {
		return false
	}
	var invoked bool
	err = db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent a JOIN member m ON m.workspace_id=a.workspace_id AND m.user_id=$1 AND m.role IN ('owner','admin','member') WHERE a.id=$2 AND a.workspace_id=$3 AND (a.owner_id=$1 OR (a.permission_mode='public_to' AND EXISTS(SELECT 1 FROM agent_invocation_target t WHERE t.agent_id=a.id AND ((t.target_type='member' AND t.target_id=$1) OR (t.target_type='workspace' AND t.target_id=a.workspace_id))))))`, b.OriginatorUserID, b.AgentID, b.ExecutionWorkspaceID).Scan(&invoked)
	return err == nil && invoked && restoredExecutionAllowed(ctx, db, b, now)
}

func (s *Service) readOutputPlan(ctx context.Context, user, id string) (outputPlan, error) {
	var plan outputPlan
	err := s.Store.readOnly(ctx, func(tx pgx.Tx) error {
		plan = outputPlan{}
		var err error
		plan, err = s.outputPlan(ctx, tx, user, id)
		return err
	})
	return plan, err
}

// ReadOutput rechecks all current source permissions and the reader's OWN live
// provider identity for every delivery, including historical/cached output.
func (s *Service) ReadOutput(ctx context.Context, user, id string) ([]byte, error) {
	if s.OutputProof == nil {
		return nil, ErrUnavailable
	}
	before, err := s.readOutputPlan(ctx, user, id)
	if err != nil {
		return nil, err
	}
	if event(ctx, s.Store.DB, user, id, "restricted_output_read_intent") != nil {
		return nil, ErrAudit
	}
	deny := func(cause error) ([]byte, error) {
		auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		if event(auditCtx, s.Store.DB, user, id, "restricted_output_read_denied") != nil {
			return nil, ErrAudit
		}
		return nil, cause
	}
	for _, access := range before.Access {
		if s.OutputProof.ProveRepository(ctx, access.Operation) != nil {
			return deny(ErrProvider)
		}
	}
	var body []byte
	err = s.Store.readOnly(ctx, func(tx pgx.Tx) error {
		clear(body)
		body = nil
		after, err := s.outputPlan(ctx, tx, user, id)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(before, after) {
			return ErrRevoked
		}
		return tx.QueryRow(ctx, `SELECT body FROM r2d_git_output WHERE id=$1`, id).Scan(&body)
	})
	if err != nil {
		clear(body)
		return deny(err)
	}
	final, err := s.readOutputPlan(ctx, user, id)
	if err != nil || !reflect.DeepEqual(before, final) || ctx.Err() != nil {
		clear(body)
		return deny(ErrRevoked)
	}
	if event(ctx, s.Store.DB, user, id, "restricted_output_read_prepared") != nil {
		clear(body)
		return deny(ErrAudit)
	}
	final, err = s.readOutputPlan(ctx, user, id)
	if err != nil || !reflect.DeepEqual(before, final) || ctx.Err() != nil {
		clear(body)
		return deny(ErrRevoked)
	}
	return body, nil
}
