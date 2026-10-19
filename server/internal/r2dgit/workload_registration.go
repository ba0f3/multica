package r2dgit

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sync"
	"time"
)

// WorkloadEnrollmentRequest is constructed by the trusted application from a
// sealed database run. It is never accepted from a workload or public endpoint.
type WorkloadEnrollmentRequest struct {
	Context          ContextSpec `json:"context"`
	Grant            GrantSpec   `json:"grant"`
	ChannelID        string      `json:"channel_id"`
	PolicyDigest     string      `json:"policy_digest"`
	IssueID          string      `json:"issue_id"`
	AssignmentDigest string      `json:"assignment_digest"`
	ExpiresAt        time.Time   `json:"expires_at"`
}

func hexDigest(value []byte) string { h := sha256.Sum256(value); return hex.EncodeToString(h[:]) }

// WorkloadRegistrationBytes defines the operator signature domain. An operator
// must certify actual containment before signing; configuration alone is not
// acceptance evidence. There is deliberately no production issuer here.
func WorkloadRegistrationBytes(r WorkloadEnrollmentRequest, certificateDER []byte, acceptanceID string) ([]byte, error) {
	pin := sha256.Sum256(certificateDER)
	b, err := json.Marshal(struct {
		Domain       string                    `json:"domain"`
		Request      WorkloadEnrollmentRequest `json:"request"`
		Certificate  string                    `json:"certificate_sha256"`
		AcceptanceID string                    `json:"acceptance_id"`
	}{"multica-protected-workload-v1", r, hex.EncodeToString(pin[:]), acceptanceID})
	return b, err
}

type WorkloadEnrollment struct {
	Certificate  tls.Certificate
	AcceptanceID string
	Signature    []byte
}

// WorkloadEnroller is an operator-controlled dependency. No live enrollment,
// ambient certificate lookup or self-registration route is installed.
type WorkloadEnroller interface {
	Enroll(context.Context, WorkloadEnrollmentRequest) (WorkloadEnrollment, error)
}

type registeredWorkloads struct {
	mu           sync.Mutex
	service      *Service
	now          func() time.Time
	key          ed25519.PublicKey
	entries      map[string]WorkloadEnrollmentRequest
	acceptanceID string
}

func (r *registeredWorkloads) register(request WorkloadEnrollmentRequest, enrollment WorkloadEnrollment) error {
	if r.acceptanceID != "" && enrollment.AcceptanceID != r.acceptanceID {
		return ErrRuntime
	}
	if len(enrollment.Certificate.Certificate) != 1 {
		return ErrRuntime
	}
	message, err := WorkloadRegistrationBytes(request, enrollment.Certificate.Certificate[0], enrollment.AcceptanceID)
	if err != nil {
		return ErrRuntime
	}
	if len(r.key) != ed25519.PublicKeySize || !nonempty(enrollment.AcceptanceID, request.ChannelID, request.PolicyDigest, request.IssueID, request.AssignmentDigest) || len(enrollment.Certificate.Certificate) != 1 || !r.now().Before(request.ExpiresAt) || request.ExpiresAt.After(r.now().Add(MaxLeaseTTL)) || !ed25519.Verify(r.key, message, enrollment.Signature) {
		return ErrRuntime
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[request.Context.ID]; exists {
		return ErrConflict
	}
	request.Grant.Operations = append([]Operation(nil), request.Grant.Operations...)
	request.Grant.WriteRefs = append([]string(nil), request.Grant.WriteRefs...)
	r.entries[request.Context.ID] = request
	return nil
}

func (r *registeredWorkloads) revoke(id string) {
	r.mu.Lock()
	delete(r.entries, id)
	r.mu.Unlock()
}

// Current adds only exact, signed runtime evidence to the authoritative current
// database rights. Service.Current itself remains ineligible in production.
func (r *registeredWorkloads) Current(ctx context.Context, spec ContextSpec, grant GrantSpec) (CurrentRights, error) {
	c, err := r.service.Current(ctx, spec, grant)
	if err != nil {
		return c, err
	}
	r.mu.Lock()
	entry, ok := r.entries[spec.ID]
	r.mu.Unlock()
	if !ok || entry.Context != spec || !reflect.DeepEqual(entry.Grant, grant) || !r.now().Before(entry.ExpiresAt) {
		return CurrentRights{}, ErrRuntime
	}
	if r.acceptanceID != "" {
		acceptance, err := r.service.runtimeAcceptance(ctx, r.acceptanceID, r.key)
		if err != nil || acceptance.RuntimeID != spec.Binding.RuntimeID || acceptance.PolicyDigest != entry.PolicyDigest {
			return CurrentRights{}, ErrRuntime
		}
	}
	var issue string
	if err := r.service.Store.DB.QueryRow(ctx, `SELECT issue_id::text FROM agent_task_queue WHERE id=$1`, spec.Binding.TaskID).Scan(&issue); err != nil || issue != entry.IssueID {
		return CurrentRights{}, ErrRevoked
	}
	c.Runtime = RuntimeEvidence{RuntimeID: spec.Binding.RuntimeID, ChannelID: entry.ChannelID, Capabilities: []string{Capability}, OperatorApproved: true, Isolated: true}
	return c, nil
}
