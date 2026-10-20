package r2dgit

import (
	"context"
	"crypto/rand"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// DefaultSigningLeaseTTL bounds how long one attempt may hold a signing
// permission.
//
// A lease is short because it is a capability: the shorter it lives, the
// smaller the window in which a revoked key could still be used by a
// connection that was opened before the revocation.
const DefaultSigningLeaseTTL = 5 * time.Minute

// SigningLease is the permission to sign with one key on behalf of one
// task attempt.
//
// It carries the public key and nothing secret. The private key stays in
// the custody store and is only reachable through the lease id.
type SigningLease struct {
	LeaseID     string    `json:"lease_id"`
	PublicKey   string    `json:"public_key"`
	Fingerprint string    `json:"fingerprint"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// TaskOriginator resolves the human who authorized a task.
//
// The originator is the only value that may select a signing key. The
// runtime owner, the agent owner and the audit-only fallbacks are not
// principals: they say who is accountable, not who asked.
type TaskOriginator interface {
	TaskOriginator(ctx context.Context, taskID string) (string, error)
}

// signingLease is the server-side record of an issued lease.
type signingLease struct {
	LeaseID    string
	TaskID     string
	UserID     string
	IdentityID string
	Generation uint64
	ProviderID string
	ExpiresAt  time.Time
	// Revoked marks a lease whose key was withdrawn. The record is kept
	// so a later signature request is refused with the reason rather than
	// with "unknown lease".
	Revoked bool
}

// OpenSigningLease issues a signing permission for a task attempt.
//
// The key is chosen by the server: the task's originator decides which
// identity may be used, and the provider narrows it to one credential. The
// caller cannot name a user, an identity or a generation.
func (s *Service) OpenSigningLease(ctx context.Context, taskID, providerID string) (SigningLease, error) {
	if !s.available() || s.originators == nil {
		return SigningLease{}, ErrUnavailable
	}
	if strings.TrimSpace(taskID) == "" || strings.TrimSpace(providerID) == "" {
		return SigningLease{}, ErrScope
	}

	originator, err := s.originators.TaskOriginator(ctx, taskID)
	if err != nil {
		if err == ErrPrincipal {
			return SigningLease{}, ErrPrincipal
		}
		return SigningLease{}, err
	}
	if strings.TrimSpace(originator) == "" {
		return SigningLease{}, ErrPrincipal
	}

	provider, err := s.store.GetProvider(ctx, providerID)
	if err != nil {
		return SigningLease{}, ErrScope
	}
	if !provider.Enabled {
		return SigningLease{}, ErrScope
	}

	identity, err := s.store.GetIdentityForUser(ctx, originator, providerID)
	if err != nil {
		return SigningLease{}, ErrIdentity
	}
	if identity.Revoked {
		return SigningLease{}, ErrRevoked
	}
	if identity.ActiveGeneration == 0 {
		return SigningLease{}, ErrIdentity
	}
	key, err := s.store.GetKey(ctx, identity.ID, identity.ActiveGeneration)
	if err != nil {
		return SigningLease{}, ErrIdentity
	}
	if key.State != Ready {
		return SigningLease{}, ErrIdentity
	}

	now := s.now().UTC()
	s.pruneLeases(now)
	lease := &signingLease{
		LeaseID:    s.newID(),
		TaskID:     taskID,
		UserID:     originator,
		IdentityID: identity.ID,
		Generation: key.Generation,
		ProviderID: providerID,
		ExpiresAt:  now.Add(s.leaseTTL),
	}

	s.leaseMu.Lock()
	s.leases[lease.LeaseID] = lease
	s.leaseMu.Unlock()

	return SigningLease{
		LeaseID:     lease.LeaseID,
		PublicKey:   key.PublicKey,
		Fingerprint: key.Fingerprint,
		ExpiresAt:   lease.ExpiresAt,
	}, nil
}

// Sign signs data with the key a lease is bound to.
//
// The key is re-read before every signature: a lease that was issued before
// a revocation must stop working the moment the key is revoked, and a lease
// that outlives its key must not sign with a replacement generation.
func (s *Service) Sign(ctx context.Context, leaseID string, data []byte) ([]byte, error) {
	if !s.available() {
		return nil, ErrUnavailable
	}
	if strings.TrimSpace(leaseID) == "" {
		return nil, ErrScope
	}

	s.leaseMu.Lock()
	lease, ok := s.leases[leaseID]
	s.leaseMu.Unlock()
	if !ok {
		return nil, ErrScope
	}
	if !s.now().UTC().Before(lease.ExpiresAt) {
		return nil, ErrScope
	}
	if lease.Revoked {
		return nil, ErrRevoked
	}

	key, err := s.store.GetKey(ctx, lease.IdentityID, lease.Generation)
	if err != nil {
		return nil, ErrRevoked
	}
	if key.State != Ready {
		return nil, ErrRevoked
	}

	var signature []byte
	err = s.custody.WithSigner(ctx, key.InternalSecretRef, func(signer ssh.Signer) error {
		if signer == nil {
			return ErrIdentity
		}
		signed, signErr := signer.Sign(rand.Reader, data)
		if signErr != nil {
			return ErrUnavailable
		}
		signature = ssh.Marshal(signed)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(signature) == 0 {
		return nil, ErrUnavailable
	}
	return signature, nil
}

// RevokeSigningLeases marks every lease of an identity as revoked.
//
// It is called when a key is revoked so a revoked key stops signing even
// before a sign request re-reads the key's state. The records are kept
// until they expire so a later request is refused with the reason.
func (s *Service) RevokeSigningLeases(identityID string) {
	if s == nil {
		return
	}
	s.leaseMu.Lock()
	defer s.leaseMu.Unlock()
	for _, lease := range s.leases {
		if lease.IdentityID == identityID {
			lease.Revoked = true
		}
	}
}

// leaseCount reports how many leases are currently issued. It exists for
// tests and diagnostics, not for control flow.
func (s *Service) leaseCount() int {
	s.leaseMu.Lock()
	defer s.leaseMu.Unlock()
	return len(s.leases)
}

// pruneLeases drops leases that expired. It is called when a new lease is
// issued so the registry cannot grow without bound.
func (s *Service) pruneLeases(now time.Time) {
	s.leaseMu.Lock()
	defer s.leaseMu.Unlock()
	for id, lease := range s.leases {
		if !now.Before(lease.ExpiresAt) {
			delete(s.leases, id)
		}
	}
}
