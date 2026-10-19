package r2dgit

import (
	"context"
	"errors"
	"time"
)

var (
	ErrProvider      = errors.New("git_provider_unavailable")
	ErrIndeterminate = errors.New("git_operation_indeterminate")
	ErrAudit         = errors.New("git_audit_unavailable")
)

// Lease is an in-process capability, not a serializable bearer credential.
// Wire token issuance/introspection needs a durable adapter and is not enabled.
type Lease struct {
	run       RunSecurityContext
	grant     RepositoryGrant
	channelID string
	operation Operation
	ref       string
	expires   time.Time
}

func IssueLease(ctx context.Context, a Authorizer, run RunSecurityContext, grant RepositoryGrant, channelID string, op Operation, ref string, now time.Time, ttl time.Duration) (Lease, error) {
	if ttl <= 0 || ttl > MaxLeaseTTL {
		return Lease{}, ErrScope
	}
	if err := a.Authorize(ctx, run, grant, channelID, op, ref, now); err != nil {
		return Lease{}, err
	}
	expires := now.Add(ttl)
	if grant.spec.ExpiresAt.Before(expires) {
		expires = grant.spec.ExpiresAt
	}
	return Lease{run: run, grant: grant, channelID: channelID, operation: op, ref: ref, expires: expires}, nil
}

// BoundOperation contains canonical registry IDs only. A trusted provider
// transport must resolve approved host pins/path and use this exact identity,
// without accepting a URL, argv, .git config or credential path from the agent.
type BoundOperation struct {
	UserID, ContextID, TaskID, AttemptID string
	ProviderID, RepositoryID, IdentityID string
	Generation                           uint64
	Operation                            Operation
	Ref                                  string
	OldObject, NewObject, PackDigest     string
	Reconciles, ObservedObject           string
	RootID, GrantID                      string
	PolicyEpoch, GrantEpoch              uint64
}

// ProviderTransport is outside the sandbox/key boundary. ProveRepository must
// contact the provider using the same key generation on EVERY operation, even a
// cache hit. Read must not execute in an agent-owned .git directory. The SSH read adapter is locally testable; production wiring remains disabled
// until runner isolation and complete delivery acceptance pass.
type ProviderTransport interface {
	ProveRepository(context.Context, BoundOperation) error
	Read(context.Context, BoundOperation) ([]byte, error)
}

// AuditJournal must persist intent before source delivery and reject duplicate
// operation IDs across restarts. A completed/indeterminate operation is reconciled
// by a separate path; it must never be blindly replayed.
type AuditJournal interface {
	Begin(context.Context, string, BoundOperation) (fresh bool, err error)
	Complete(context.Context, string, string) error
}

// Broker coordinates current authorization, provider proof, validation and audit.
// No production runtime is certified to issue a workload lease.
type Broker struct {
	Authorizer Authorizer
	Transport  ProviderTransport
	Journal    AuditJournal
	Now        func() time.Time
	Quarantine WriteQuarantine
}

func (b Broker) Read(ctx context.Context, lease Lease, authenticatedChannelID, operationID string) ([]byte, error) {
	return b.read(ctx, lease, authenticatedChannelID, operationID, func(ctx context.Context, op BoundOperation) ([]byte, error) { return b.Transport.Read(ctx, op) })
}

// RepositorySnapshot binds the validated pack to the authenticated advertised HEAD.
type RepositorySnapshot struct {
	Head string
	Pack []byte
}
type SnapshotTransport interface {
	ReadSnapshot(context.Context, BoundOperation) (RepositorySnapshot, error)
}

func (b Broker) ReadSnapshot(ctx context.Context, lease Lease, channel, operationID string) (RepositorySnapshot, error) {
	transport, ok := b.Transport.(SnapshotTransport)
	if !ok {
		return RepositorySnapshot{}, ErrUnavailable
	}
	var head string
	pack, err := b.read(ctx, lease, channel, operationID, func(ctx context.Context, op BoundOperation) ([]byte, error) {
		snapshot, err := transport.ReadSnapshot(ctx, op)
		if err != nil {
			clear(snapshot.Pack)
			return nil, err
		}
		if !objectID(snapshot.Head) || snapshot.Head == zeroObject || !packFraming(snapshot.Pack) {
			clear(snapshot.Pack)
			return nil, ErrProvider
		}
		head = snapshot.Head
		return snapshot.Pack, nil
	})
	if err != nil {
		return RepositorySnapshot{}, err
	}
	return RepositorySnapshot{Head: head, Pack: pack}, nil
}

func (b Broker) read(ctx context.Context, lease Lease, authenticatedChannelID, operationID string, read func(context.Context, BoundOperation) ([]byte, error)) ([]byte, error) {
	if b.Now == nil || b.Transport == nil || b.Journal == nil {
		return nil, ErrUnavailable
	}
	now := b.Now()
	if !nonempty(operationID) || authenticatedChannelID != lease.channelID || !now.Before(lease.expires) {
		return nil, ErrRevoked
	}
	if lease.operation != Read || lease.ref != "" {
		return nil, ErrScope
	}
	if err := b.Authorizer.Authorize(ctx, lease.run, lease.grant, authenticatedChannelID, Read, "", now); err != nil {
		return nil, err
	}
	if !b.Now().Before(lease.expires) {
		return nil, ErrRevoked
	}
	s, g := lease.run.spec, lease.grant.spec
	op := BoundOperation{UserID: s.Binding.OriginatorUserID, ContextID: s.ID, TaskID: s.Binding.TaskID, AttemptID: s.AttemptID, ProviderID: g.ProviderID, RepositoryID: g.RepositoryID, IdentityID: g.IdentityID, Generation: g.CredentialGeneration, Operation: Read}
	// Same-user live proof is required before even asking a transport for data.
	if err := b.Transport.ProveRepository(ctx, op); err != nil {
		return nil, ErrProvider
	}
	if !b.Now().Before(lease.expires) {
		return nil, ErrRevoked
	}
	fresh, err := b.Journal.Begin(ctx, operationID, op)
	if err != nil {
		return nil, ErrAudit
	}
	if !fresh {
		return nil, ErrIndeterminate
	}
	if !b.Now().Before(lease.expires) {
		_ = b.Journal.Complete(ctx, operationID, "denied")
		return nil, ErrRevoked
	}
	// Cover revocation during provider proof/audit. This is not a substitute
	// for cancellable streaming once a production transport is implemented.
	if err := b.Authorizer.Authorize(ctx, lease.run, lease.grant, authenticatedChannelID, Read, "", b.Now()); err != nil {
		if b.Journal.Complete(ctx, operationID, "denied") != nil {
			return nil, ErrAudit
		}
		return nil, err
	}
	if !b.Now().Before(lease.expires) {
		_ = b.Journal.Complete(ctx, operationID, "denied")
		return nil, ErrRevoked
	}
	data, err := read(ctx, op)
	if err != nil {
		clear(data)
		if b.Journal.Complete(ctx, operationID, "indeterminate") != nil {
			return nil, ErrAudit
		}
		return nil, ErrIndeterminate
	}
	if !b.Now().Before(lease.expires) {
		clear(data)
		_ = b.Journal.Complete(ctx, operationID, "denied")
		return nil, ErrRevoked
	}
	if err := b.Authorizer.Authorize(ctx, lease.run, lease.grant, authenticatedChannelID, Read, "", b.Now()); err != nil {
		clear(data)
		_ = b.Journal.Complete(ctx, operationID, "denied")
		return nil, err
	}
	if err := b.Journal.Complete(ctx, operationID, "succeeded"); err != nil {
		clear(data)
		return nil, ErrAudit
	}
	// Audit persistence can block too. Revalidate delivery after it completes;
	// an internal successful read is not permission to deliver bytes later.
	if err := b.Authorizer.Authorize(ctx, lease.run, lease.grant, authenticatedChannelID, Read, "", b.Now()); err != nil {
		clear(data)
		return nil, err
	}
	if !b.Now().Before(lease.expires) {
		clear(data)
		return nil, ErrRevoked
	}
	return data, nil
}
