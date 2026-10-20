package r2dgit

import (
	"context"
	"crypto/rand"
	"strconv"
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
	// DaemonID is the supervisor allowed to use the lease. A lease id alone
	// is not a credential: the daemon that opened it is the only caller.
	DaemonID  string
	ExpiresAt time.Time
	// Revoked marks a lease whose key was withdrawn. The record is kept
	// so a later signature request is refused with the reason rather than
	// with "unknown lease".
	Revoked bool
}

// RunIdentity is one usable Git credential of a task's execution user.
//
// The claim response carries these to the daemon so it can pick the provider
// whose host matches the repository it is about to clone. It never carries a
// secret.
type RunIdentity struct {
	ProviderID  string
	Host        string
	IdentityID  string
	Generation  uint64
	PublicKey   string
	Fingerprint string
}

// ReadyIdentities lists the verified Git credentials of a user.
//
// Only a key in the ready state is offered: an unverified key would make the
// runner fail after it has already started, and a revoked identity must never
// reach a run at all.
func (s *Service) ReadyIdentities(ctx context.Context, userID string) ([]RunIdentity, error) {
	if !s.available() {
		return nil, ErrUnavailable
	}
	if strings.TrimSpace(userID) == "" {
		return nil, ErrPrincipal
	}

	providers, err := s.store.ListProviders(ctx)
	if err != nil {
		return nil, err
	}
	hosts := make(map[string]string, len(providers))
	for _, provider := range providers {
		if provider.Enabled {
			hosts[provider.ID] = provider.Host
		}
	}

	identities, err := s.store.ListIdentitiesForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	keys, err := s.store.ListKeysForUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	bySlot := make(map[string]Key, len(keys))
	for _, key := range keys {
		bySlot[key.IdentityID+":"+strconv.FormatUint(key.Generation, 10)] = key
	}

	out := make([]RunIdentity, 0, len(identities))
	for _, identity := range identities {
		if identity.Revoked || identity.ActiveGeneration == 0 {
			continue
		}
		host, ok := hosts[identity.ProviderID]
		if !ok {
			continue
		}
		key, ok := bySlot[identity.ID+":"+strconv.FormatUint(identity.ActiveGeneration, 10)]
		if !ok || key.State != Ready || key.PublicKey == "" {
			continue
		}
		out = append(out, RunIdentity{
			ProviderID:  identity.ProviderID,
			Host:        host,
			IdentityID:  identity.ID,
			Generation:  key.Generation,
			PublicKey:   key.PublicKey,
			Fingerprint: key.Fingerprint,
		})
	}
	return out, nil
}

// OpenSigningLease issues a signing permission for a task attempt.
//
// The key is chosen by the server: the task's originator decides which
// identity may be used, and the provider narrows it to one credential. The
// caller cannot name a user, an identity or a generation.
func (s *Service) OpenSigningLease(ctx context.Context, taskID, providerID, daemonID string) (SigningLease, error) {
	if !s.available() || s.originators == nil {
		return SigningLease{}, ErrUnavailable
	}
	if strings.TrimSpace(taskID) == "" || strings.TrimSpace(providerID) == "" {
		return SigningLease{}, ErrScope
	}
	if strings.TrimSpace(daemonID) == "" {
		return SigningLease{}, ErrPrincipal
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
		DaemonID:   daemonID,
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
func (s *Service) Sign(ctx context.Context, leaseID, daemonID string, data []byte) ([]byte, error) {
	if !s.available() {
		return nil, ErrUnavailable
	}
	if strings.TrimSpace(leaseID) == "" || strings.TrimSpace(daemonID) == "" {
		return nil, ErrScope
	}

	now := s.now().UTC()
	s.leaseMu.Lock()
	lease, ok := s.leases[leaseID]
	if ok {
		// Read and update the mutable fields under the lock: a concurrent
		// revoke must not race this decision.
		if lease.DaemonID != daemonID {
			s.leaseMu.Unlock()
			return nil, ErrScope
		}
		if !now.Before(lease.ExpiresAt) {
			s.leaseMu.Unlock()
			return nil, ErrScope
		}
		if lease.Revoked {
			s.leaseMu.Unlock()
			return nil, ErrRevoked
		}
		// Slide the expiry: a long run keeps signing while it keeps
		// working, and the key state check below still stops it the
		// moment the credential is withdrawn.
		lease.ExpiresAt = now.Add(s.leaseTTL)
	}
	s.leaseMu.Unlock()
	if !ok {
		return nil, ErrScope
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

// revokeStaleLeases stops every lease of an identity that names a generation
// other than the active one.
//
// Rotating a key because it may be compromised is worthless if the previous
// generation keeps signing for the rest of its lease window.
func (s *Service) revokeStaleLeases(identityID string, activeGeneration uint64) {
	if s == nil {
		return
	}
	s.leaseMu.Lock()
	defer s.leaseMu.Unlock()
	for _, lease := range s.leases {
		if lease.IdentityID == identityID && lease.Generation != activeGeneration {
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
