// Package r2dgit defines the protected Git boundary. It has no ambient credential
// or workspace-membership fallback. Production adapters are deliberately absent
// until the project's current ACL and durable side-table prerequisites exist.
package r2dgit

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/multica-ai/multica/server/pkg/protocol"
)

const Capability = protocol.DaemonCapabilityR2DGitSecurityV1
const MaxDelegationDepth = 16
const MaxLeaseTTL = 5 * time.Minute

var (
	ErrPrincipal   = errors.New("git_principal_unproven")
	ErrScope       = errors.New("git_repo_forbidden")
	ErrRevoked     = errors.New("git_grant_revoked")
	ErrRuntime     = errors.New("git_runtime_ineligible")
	ErrUnavailable = errors.New("git_policy_unavailable")
)

type Operation string

const (
	Read  Operation = "read"
	Write Operation = "write"
)

// TaskBinding must be loaded from authoritative task/agent/issue/project rows,
// never headers, task environment, agent ownership or accountable_user_id.
// ExecutionWorkspaceID owns the agent; ResourceWorkspaceID owns the project.
type TaskBinding struct {
	TaskID               string `json:"task_id"`
	AgentID              string `json:"agent_id"`
	RuntimeID            string `json:"runtime_id"`
	ExecutionWorkspaceID string `json:"execution_workspace_id"`
	ResourceWorkspaceID  string `json:"resource_workspace_id"`
	ProjectID            string `json:"project_id"`
	OriginatorUserID     string `json:"originator_user_id"`
	OriginatorSource     string `json:"originator_source"`
	ParentTaskID         string `json:"parent_task_id"`
}

func (b TaskBinding) valid() bool {
	return nonempty(b.TaskID, b.AgentID, b.RuntimeID, b.ExecutionWorkspaceID,
		b.ResourceWorkspaceID, b.ProjectID, b.OriginatorUserID)
}

func nonempty(values ...string) bool {
	for _, v := range values {
		if v == "" || strings.TrimSpace(v) != v || strings.ContainsAny(v, "\x00\r\n") {
			return false
		}
	}
	return true
}

// ContextSpec contains no secrets. Constructors seal a value copy; accessors
// return copies so a caller cannot substitute an originator after issuance.
type ContextSpec struct {
	ID          string      `json:"id"`
	AttemptID   string      `json:"attempt_id"`
	RootID      string      `json:"root_id"`
	ParentID    string      `json:"parent_id"`
	Binding     TaskBinding `json:"binding"`
	PolicyEpoch uint64      `json:"policy_epoch"`
	IssuedAt    time.Time   `json:"issued_at"`
	ExpiresAt   time.Time   `json:"expires_at"`
	Depth       int         `json:"depth"`
}

type RunSecurityContext struct {
	spec        ContextSpec
	ancestors   []ContextSpec
	derivations map[string]Derivation
}

func (r RunSecurityContext) Spec() ContextSpec { return r.spec }

// NewHumanRoot accepts an authenticated human principal resolved by the server.
// A direct_human label by itself is not evidence of an authenticated request.
func NewHumanRoot(id, attemptID, humanID string, b TaskBinding, epoch uint64, now, expires time.Time) (RunSecurityContext, error) {
	if !b.valid() || !nonempty(humanID) || humanID != b.OriginatorUserID || b.OriginatorSource != "direct_human" || b.ParentTaskID != "" {
		return RunSecurityContext{}, ErrPrincipal
	}
	r := RunSecurityContext{spec: ContextSpec{ID: id, AttemptID: attemptID, RootID: id, Binding: b, PolicyEpoch: epoch, IssuedAt: now, ExpiresAt: expires}}
	if !r.valid(now) {
		return RunSecurityContext{}, ErrScope
	}
	return r, nil
}

func (r RunSecurityContext) valid(now time.Time) bool {
	s := r.spec
	if !nonempty(s.ID, s.AttemptID, s.RootID) || !s.Binding.valid() || s.PolicyEpoch == 0 || s.IssuedAt.IsZero() || s.ExpiresAt.IsZero() || now.Before(s.IssuedAt) || !now.Before(s.ExpiresAt) || s.Depth < 0 || s.Depth > MaxDelegationDepth {
		return false
	}
	if s.Depth == 0 {
		return s.RootID == s.ID && s.ParentID == "" && s.Binding.OriginatorSource == "direct_human" && s.Binding.ParentTaskID == ""
	}
	return nonempty(s.ParentID) && s.ID != s.ParentID && s.ID != s.RootID
}

type Derivation string

const (
	Delegation Derivation = "delegation"
	Retry      Derivation = "retry"
)

// Derive is structural validation only. Issuance must also authorize the parent
// online while it is active; validating an already-issued child may accept a
// normally completed parent. Each child/retry has a fresh context and attempt.
func Derive(parent RunSecurityContext, id, attemptID string, b TaskBinding, kind Derivation, now, expires time.Time) (RunSecurityContext, error) {
	p := parent.spec
	if !parent.valid(now) || !b.valid() || b.OriginatorUserID != p.Binding.OriginatorUserID || b.ProjectID != p.Binding.ProjectID || b.ExecutionWorkspaceID != p.Binding.ExecutionWorkspaceID || b.ResourceWorkspaceID != p.Binding.ResourceWorkspaceID {
		return RunSecurityContext{}, ErrPrincipal
	}
	if id == p.ID || id == p.RootID || attemptID == p.AttemptID || expires.After(p.ExpiresAt) {
		return RunSecurityContext{}, ErrScope
	}
	for _, ancestor := range parent.ancestors {
		if id == ancestor.ID || attemptID == ancestor.AttemptID {
			return RunSecurityContext{}, ErrScope
		}
		if kind == Delegation && b.TaskID == ancestor.Binding.TaskID {
			return RunSecurityContext{}, ErrPrincipal
		}
	}
	switch kind {
	case Delegation:
		if b.TaskID == p.Binding.TaskID || b.ParentTaskID != p.Binding.TaskID || (b.OriginatorSource != "delegation" && b.OriginatorSource != "comment_source") {
			return RunSecurityContext{}, ErrPrincipal
		}
	case Retry:
		fresh := p.Binding
		fresh.TaskID = b.TaskID
		fresh.ParentTaskID = p.Binding.TaskID
		fresh.OriginatorSource = "delegation"
		if b != p.Binding && (b != fresh || b.TaskID == p.Binding.TaskID) {
			return RunSecurityContext{}, ErrPrincipal
		}
	default:
		return RunSecurityContext{}, ErrPrincipal
	}
	r := RunSecurityContext{spec: ContextSpec{ID: id, AttemptID: attemptID, RootID: p.RootID, ParentID: p.ID, Binding: b, PolicyEpoch: p.PolicyEpoch, IssuedAt: now, ExpiresAt: expires, Depth: p.Depth + 1}, ancestors: append(append([]ContextSpec(nil), parent.ancestors...), p)}
	r.derivations = make(map[string]Derivation, len(parent.derivations)+1)
	for id, kind := range parent.derivations {
		r.derivations[id] = kind
	}
	r.derivations[id] = kind
	if !r.valid(now) {
		return RunSecurityContext{}, ErrScope
	}
	return r, nil
}

type GrantSpec struct {
	ID                   string      `json:"id"`
	ContextID            string      `json:"context_id"`
	ProviderID           string      `json:"provider_id"`
	RepositoryID         string      `json:"repository_id"`
	IdentityID           string      `json:"identity_id"`
	CredentialGeneration uint64      `json:"credential_generation"`
	Epoch                uint64      `json:"epoch"`
	Operations           []Operation `json:"operations"`
	WriteRefs            []string    `json:"write_refs"`
	IssuedAt             time.Time   `json:"issued_at"`
	ExpiresAt            time.Time   `json:"expires_at"`
}

type RepositoryGrant struct{ spec GrantSpec }

func copyGrant(s GrantSpec) GrantSpec {
	s.Operations = append([]Operation(nil), s.Operations...)
	s.WriteRefs = append([]string(nil), s.WriteRefs...)
	return s
}
func (g RepositoryGrant) Spec() GrantSpec { return copyGrant(g.spec) }

func NewGrant(run RunSecurityContext, s GrantSpec, now time.Time) (RepositoryGrant, error) {
	if run.spec.Depth != 0 {
		return RepositoryGrant{}, ErrScope
	}
	return validateGrant(run, s, now)
}

func validateGrant(run RunSecurityContext, s GrantSpec, now time.Time) (RepositoryGrant, error) {
	if !run.valid(now) || !nonempty(s.ID, s.ProviderID, s.RepositoryID, s.IdentityID) || s.ContextID != run.spec.ID || s.CredentialGeneration == 0 || s.Epoch == 0 || s.IssuedAt.Before(run.spec.IssuedAt) || now.Before(s.IssuedAt) || !now.Before(s.ExpiresAt) || s.ExpiresAt.After(run.spec.ExpiresAt) || len(s.Operations) == 0 {
		return RepositoryGrant{}, ErrScope
	}
	seen := map[Operation]bool{}
	for _, op := range s.Operations {
		if (op != Read && op != Write) || seen[op] {
			return RepositoryGrant{}, ErrScope
		}
		seen[op] = true
	}
	if seen[Write] != (len(s.WriteRefs) > 0) {
		return RepositoryGrant{}, ErrScope
	}
	refs := map[string]bool{}
	for _, ref := range s.WriteRefs {
		if !validWriteRef(ref) || refs[ref] {
			return RepositoryGrant{}, ErrScope
		}
		refs[ref] = true
	}
	return RepositoryGrant{copyGrant(s)}, nil
}

// V1 intentionally limits writes to exact task feature branches, with no glob,
// tags, deletion, force, default or protected-branch inference from the client.
func validWriteRef(ref string) bool {
	if len(ref) > 255 || !strings.HasPrefix(ref, "refs/heads/task/") || strings.HasSuffix(ref, "/") || strings.HasSuffix(ref, ".") || strings.Contains(ref, "..") || strings.Contains(ref, "@{") || strings.Contains(ref, "//") {
		return false
	}
	for _, c := range ref {
		if c <= 32 || c == 127 || strings.ContainsRune("~^:?*[\\", c) {
			return false
		}
	}
	for _, part := range strings.Split(ref, "/") {
		if part == "" || strings.HasPrefix(part, ".") || strings.HasSuffix(part, ".lock") {
			return false
		}
	}
	return true
}

func hasOp(s GrantSpec, op Operation) bool {
	for _, x := range s.Operations {
		if x == op {
			return true
		}
	}
	return false
}
func hasRef(s GrantSpec, ref string) bool {
	for _, x := range s.WriteRefs {
		if x == ref {
			return true
		}
	}
	return false
}

func NarrowGrant(parent RepositoryGrant, child RunSecurityContext, s GrantSpec, now time.Time) (RepositoryGrant, error) {
	p := parent.spec
	if child.spec.ParentID != p.ContextID || s.ID == p.ID || s.ProviderID != p.ProviderID || s.RepositoryID != p.RepositoryID || s.IdentityID != p.IdentityID || s.CredentialGeneration != p.CredentialGeneration || s.Epoch != p.Epoch || s.ExpiresAt.After(p.ExpiresAt) {
		return RepositoryGrant{}, ErrScope
	}
	for _, op := range s.Operations {
		if !hasOp(p, op) {
			return RepositoryGrant{}, ErrScope
		}
	}
	for _, ref := range s.WriteRefs {
		if !hasRef(p, ref) {
			return RepositoryGrant{}, ErrScope
		}
	}
	return validateGrant(child, s, now)
}

// RuntimeEvidence comes from the trusted runner registry/authenticated channel.
// A client-advertised capability alone never certifies an isolation boundary.
type RuntimeEvidence struct {
	RuntimeID, ChannelID       string
	Capabilities               []string
	OperatorApproved, Isolated bool
}

func (r RuntimeEvidence) eligible(runtimeID, channelID string) bool {
	if !r.OperatorApproved || !r.Isolated || !nonempty(channelID) || r.RuntimeID != runtimeID || r.ChannelID != channelID {
		return false
	}
	for _, c := range r.Capabilities {
		if c == Capability {
			return true
		}
	}
	return false
}

// CurrentRights is an online authoritative snapshot, not an LLM or caller
// assertion. Project permission must come from the reviewed project policy
// service (including explicit cross-workspace grants). Workspace membership,
// global-observer reads and agent ownership never imply protected source access.
type CurrentRights struct {
	Binding                                                                      TaskBinding
	ActiveHuman, ProjectRead, ProjectContribute, RepositoryRead, RepositoryWrite bool
	ContextActive, RootActive, GrantActive, IdentityReady                        bool
	PolicyEpoch, GrantEpoch, CredentialGeneration                                uint64
	ProviderID, RepositoryID, IdentityID                                         string
	AllowedWriteRefs                                                             []string
	Runtime                                                                      RuntimeEvidence
}

// Authority must validate durable context/attempt/grant identity and the entire
// root/parent chain, reject cycles, and read current membership/revocation in one
// consistent snapshot. Missing tables, facts or connectivity must return error.
type Authority interface {
	Current(context.Context, ContextSpec, GrantSpec) (CurrentRights, error)
}

type Authorizer struct{ Authority Authority }

func (a Authorizer) Authorize(ctx context.Context, run RunSecurityContext, grant RepositoryGrant, channelID string, op Operation, ref string, now time.Time) error {
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	if !run.valid(now) || grant.spec.ContextID != run.spec.ID {
		return ErrScope
	}
	if _, err := validateGrant(run, grant.spec, now); err != nil {
		return err
	}
	if !hasOp(grant.spec, op) || (op == Read && ref != "") || (op == Write && !hasRef(grant.spec, ref)) {
		return ErrScope
	}
	if a.Authority == nil {
		return ErrUnavailable
	}
	c, err := a.Authority.Current(ctx, run.Spec(), grant.Spec())
	if err != nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	if c.Binding != run.spec.Binding || !c.ActiveHuman {
		return ErrPrincipal
	}
	if !c.ContextActive || !c.RootActive || !c.GrantActive || !c.IdentityReady || c.PolicyEpoch != run.spec.PolicyEpoch || c.GrantEpoch != grant.spec.Epoch || c.CredentialGeneration != grant.spec.CredentialGeneration {
		return ErrRevoked
	}
	if !c.ProjectRead || !c.RepositoryRead || c.ProviderID != grant.spec.ProviderID || c.RepositoryID != grant.spec.RepositoryID || c.IdentityID != grant.spec.IdentityID {
		return ErrScope
	}
	if op == Write {
		if !c.ProjectContribute || !c.RepositoryWrite {
			return ErrScope
		}
		allowed := false
		for _, current := range c.AllowedWriteRefs {
			if current == ref {
				allowed = true
			}
		}
		if !allowed {
			return ErrScope
		}
	}
	if !c.Runtime.eligible(run.spec.Binding.RuntimeID, channelID) {
		return ErrRuntime
	}
	return nil
}
