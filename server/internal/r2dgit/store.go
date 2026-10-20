package r2dgit

import (
	"context"
	"time"
)

// Provider is an operator-approved Git provider instance. HostPins are the
// SSH host key fingerprints a connection to this provider must present.
type Provider struct {
	ID       string
	Label    string
	Kind     string
	Host     string
	Port     int
	HostPins []string
	Enabled  bool
}

// PublicProvider is the browser-visible projection of a provider. The pinned
// host keys stay server-side: a client has no reason to learn them.
type PublicProvider struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Kind  string `json:"kind"`
	Host  string `json:"host"`
	Port  int    `json:"port"`
}

// Identity is the stable handle of one user's Git credential on one provider.
type Identity struct {
	ID               string
	UserID           string
	ProviderID       string
	ActiveGeneration uint64
	Epoch            uint64
	Revoked          bool
}

// Key is one generation of an identity's key pair.
//
// InternalSecretRef points into the encrypted custody store. It never leaves
// the trusted boundary: it is not part of PublicIdentity and it is not
// rendered into any response.
type Key struct {
	IdentityID        string
	Generation        uint64
	PublicKey         string
	Fingerprint       string
	InternalSecretRef string
	State             KeyState
	AccountID         string
	Login             string
	VerifiedAt        *time.Time
	CleanupPending    bool
	Diagnostic        string
	ConsentProjectIDs []string
}

// Job is a durable lifecycle intent: a key that was provisioned, or a
// revoked key whose secret still has to be destroyed.
type Job struct {
	ID             string
	UserID         string
	IdentityID     string
	Generation     uint64
	Kind           string
	IdempotencyKey string
	State          string
	LastError      string
}

// Store is the persistence boundary of the credential service.
//
// Every method validates ownership in the query itself, so a caller cannot
// reach another user's credential by passing a foreign id.
type Store interface {
	ListProviders(ctx context.Context) ([]Provider, error)
	GetProvider(ctx context.Context, id string) (Provider, error)
	GetIdentityForUser(ctx context.Context, userID, providerID string) (Identity, error)
	ListIdentitiesForUser(ctx context.Context, userID string) ([]Identity, error)
	ListKeysForUser(ctx context.Context, userID string) ([]Key, error)
	GetKey(ctx context.Context, identityID string, generation uint64) (Key, error)
	CreateIdentity(ctx context.Context, identity Identity) (Identity, error)
	SetActiveGeneration(ctx context.Context, identityID string, generation uint64) (Identity, error)
	RevokeIdentity(ctx context.Context, identityID, userID string) (Identity, error)
	CreateKey(ctx context.Context, key Key) (Key, error)
	MarkKeyReady(ctx context.Context, identityID string, generation uint64, accountID, login string, verifiedAt time.Time) (Key, error)
	RevokeKey(ctx context.Context, identityID string, generation uint64) (Key, error)
	ClearCleanupPending(ctx context.Context, identityID string, generation uint64) (Key, error)
	CreateJob(ctx context.Context, job Job) (Job, error)
	GetJobByIdempotencyKey(ctx context.Context, idempotencyKey string) (Job, error)
	UpdateJobState(ctx context.Context, id, state, lastError string) (Job, error)
}
