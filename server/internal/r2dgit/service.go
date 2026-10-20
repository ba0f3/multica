package r2dgit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// PublicIdentity is the only credential representation a client may see.
//
// It carries no secret reference, no private key bytes and no provider token.
// A field that does not exist here cannot leak by accident.
type PublicIdentity struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	ProviderID        string     `json:"provider_id"`
	Generation        uint64     `json:"generation"`
	PublicKey         string     `json:"public_key"`
	Fingerprint       string     `json:"fingerprint"`
	State             KeyState   `json:"state"`
	AccountID         string     `json:"account_id,omitempty"`
	Login             string     `json:"login,omitempty"`
	VerifiedAt        *time.Time `json:"verified_at,omitempty"`
	Active            bool       `json:"active"`
	CleanupPending    bool       `json:"cleanup_pending"`
	Diagnostic        string     `json:"diagnostic,omitempty"`
	ConsentProjectIDs []string   `json:"consent_project_ids"`
}

// Profile is the account-scoped view of a user's Git credentials.
type Profile struct {
	Providers  []PublicProvider `json:"providers"`
	Identities []PublicIdentity `json:"identities"`
}

// Verifier proves that a stored key authenticates a provider account.
type Verifier interface {
	// Verify opens a pinned connection to the provider with the stored key
	// and returns the provider account the key belongs to. A successful SSH
	// login is not proof of repository permission and must not be reported
	// as such.
	Verify(ctx context.Context, provider Provider, secretRef string, generation uint64) (string, error)
}

// Service owns the credential lifecycle.
//
// It is the only component that decides which key a user may use. Every
// method takes the acting user id from the authenticated session; none of
// them accept a user id from the request body.
type Service struct {
	store    Store
	custody  EncryptedCustody
	verifier Verifier
	random   io.Reader
	now      func() time.Time
	newID    func() string

	// originators resolves the human who authorized a task. A signing lease
	// is bound to that human, never to the runtime owner.
	originators TaskOriginator
	// leaseTTL bounds how long one signing permission lives.
	leaseTTL time.Duration
	// leaseMu guards the lease registry below.
	leaseMu sync.Mutex
	// leases holds the issued signing permissions.
	//
	// The registry lives in the server's memory. A deployment that serves
	// the daemon from more than one server instance would need a shared
	// store here: a lease issued by one instance is not visible to the
	// other, so a signature request could fail with "unknown lease". The
	// failure is safe — it stops the signature rather than granting one.
	leases map[string]*signingLease
}

// NewService builds a credential service.
//
// A nil custody or verifier makes every credential operation unavailable:
// an unconfigured server must not create keys or pretend a verification
// succeeded.
func NewService(store Store, custody EncryptedCustody, verifier Verifier) *Service {
	service := &Service{
		store:    store,
		custody:  custody,
		verifier: verifier,
		random:   randomReader{},
		now:      time.Now,
		newID:    newRandomID,
		leaseTTL: DefaultSigningLeaseTTL,
		leases:   map[string]*signingLease{},
	}
	// A store that can resolve task originators also lets the service
	// issue signing leases.
	if originators, ok := store.(TaskOriginator); ok {
		service.originators = originators
	}
	return service
}

func (s *Service) available() bool {
	return s != nil && s.store != nil && s.custody != nil && s.verifier != nil
}

// Profile returns the caller's identities and the providers they may use.
func (s *Service) Profile(ctx context.Context, userID string) (Profile, error) {
	out := Profile{Providers: []PublicProvider{}, Identities: []PublicIdentity{}}
	if !s.available() {
		return out, ErrUnavailable
	}
	if strings.TrimSpace(userID) == "" {
		return out, ErrPrincipal
	}

	providers, err := s.store.ListProviders(ctx)
	if err != nil {
		return out, err
	}
	for _, provider := range providers {
		if !provider.Enabled {
			continue
		}
		out.Providers = append(out.Providers, PublicProvider{
			ID:    provider.ID,
			Label: provider.Label,
			Kind:  provider.Kind,
			Host:  provider.Host,
			Port:  provider.Port,
		})
	}

	keys, err := s.store.ListKeysForUser(ctx, userID)
	if err != nil {
		return out, err
	}
	identities, err := s.store.ListIdentitiesForUser(ctx, userID)
	if err != nil {
		return out, err
	}
	byIdentity := make(map[string]Identity, len(identities))
	for _, identity := range identities {
		byIdentity[identity.ID] = identity
	}
	for _, key := range keys {
		identity, ok := byIdentity[key.IdentityID]
		if !ok {
			continue
		}
		out.Identities = append(out.Identities, publicIdentity(identity, key))
	}
	return out, nil
}

// Generate creates the next key generation for a provider.
//
// The request is idempotent on requestID: a retried request returns the key
// the first attempt produced instead of creating a second one.
func (s *Service) Generate(ctx context.Context, userID, providerID, requestID string, consentProjectIDs []string) (PublicIdentity, error) {
	if !s.available() {
		return PublicIdentity{}, ErrUnavailable
	}
	if strings.TrimSpace(userID) == "" {
		return PublicIdentity{}, ErrPrincipal
	}
	if strings.TrimSpace(providerID) == "" || strings.TrimSpace(requestID) == "" {
		return PublicIdentity{}, ErrScope
	}

	provider, err := s.store.GetProvider(ctx, providerID)
	if err != nil {
		return PublicIdentity{}, ErrScope
	}
	if !provider.Enabled {
		return PublicIdentity{}, ErrScope
	}

	idempotencyKey := "generate:" + userID + ":" + providerID + ":" + requestID
	existing, err := s.store.GetJobByIdempotencyKey(ctx, idempotencyKey)
	switch {
	case err == nil && existing.State == "done":
		return s.returnKey(ctx, userID, existing.IdentityID, existing.Generation)
	case err == nil:
		return PublicIdentity{}, ErrConflict
	case !errors.Is(err, ErrScope):
		return PublicIdentity{}, err
	}

	identity, err := s.store.GetIdentityForUser(ctx, userID, providerID)
	switch {
	case err == nil:
		if identity.Revoked {
			return PublicIdentity{}, ErrRevoked
		}
	case errors.Is(err, ErrScope):
		identity, err = s.store.CreateIdentity(ctx, Identity{
			ID:         s.newID(),
			UserID:     userID,
			ProviderID: providerID,
		})
		if err != nil {
			return PublicIdentity{}, err
		}
	default:
		return PublicIdentity{}, err
	}

	generation := identity.ActiveGeneration + 1
	material, err := GenerateKeyMaterial(s.random)
	if err != nil {
		return PublicIdentity{}, err
	}

	secretRef := secretRefFor(identity.ID, generation)
	if _, err := s.custody.Store(ctx, secretRef, material); err != nil {
		return PublicIdentity{}, err
	}

	key, err := s.store.CreateKey(ctx, Key{
		IdentityID:        identity.ID,
		Generation:        generation,
		PublicKey:         material.PublicKey,
		Fingerprint:       material.Fingerprint,
		InternalSecretRef: secretRef,
		State:             PendingVerification,
		ConsentProjectIDs: append([]string(nil), consentProjectIDs...),
	})
	if err != nil {
		// The secret exists but nothing points at it. Remove it again so a
		// failed request cannot leave usable key material behind.
		_ = s.custody.DestroyAll(ctx, secretRef)
		return PublicIdentity{}, err
	}

	if _, err := s.store.CreateJob(ctx, Job{
		ID:             s.newID(),
		UserID:         userID,
		IdentityID:     identity.ID,
		Generation:     generation,
		Kind:           "provision",
		IdempotencyKey: idempotencyKey,
		State:          "done",
	}); err != nil && !errors.Is(err, ErrConflict) {
		return PublicIdentity{}, err
	}

	return publicIdentity(identity, key), nil
}

// Verify proves that a stored generation authenticates the provider account
// and, on success, makes it the identity's active generation.
func (s *Service) Verify(ctx context.Context, userID, identityID string, generation uint64) (PublicIdentity, error) {
	if !s.available() {
		return PublicIdentity{}, ErrUnavailable
	}
	if strings.TrimSpace(userID) == "" {
		return PublicIdentity{}, ErrPrincipal
	}

	identity, err := s.identityFor(ctx, userID, identityID)
	if err != nil {
		return PublicIdentity{}, err
	}
	if identity.Revoked {
		return PublicIdentity{}, ErrRevoked
	}

	key, err := s.store.GetKey(ctx, identity.ID, generation)
	if err != nil {
		return PublicIdentity{}, ErrScope
	}
	switch key.State {
	case Revoked:
		return PublicIdentity{}, ErrRevoked
	case Ready:
		return publicIdentity(identity, key), nil
	case PendingVerification:
	default:
		return PublicIdentity{}, ErrIdentity
	}

	provider, err := s.store.GetProvider(ctx, identity.ProviderID)
	if err != nil {
		return PublicIdentity{}, ErrScope
	}
	login, err := s.verifier.Verify(ctx, provider, key.InternalSecretRef, generation)
	if err != nil {
		return PublicIdentity{}, err
	}
	if strings.TrimSpace(login) == "" {
		return PublicIdentity{}, ErrIdentity
	}

	verifiedAt := s.now().UTC()
	verified, err := s.store.MarkKeyReady(ctx, identity.ID, generation, "", login, verifiedAt)
	if err != nil {
		return PublicIdentity{}, err
	}
	identity, err = s.store.SetActiveGeneration(ctx, identity.ID, generation)
	if err != nil {
		return PublicIdentity{}, err
	}
	return publicIdentity(identity, verified), nil
}

// Revoke stops local use of an identity and destroys its stored secrets.
//
// The local revoke takes effect even when the custody store is unreachable:
// the cleanup job stays pending and is retried.
func (s *Service) Revoke(ctx context.Context, userID, identityID string) error {
	if !s.available() {
		return ErrUnavailable
	}
	if strings.TrimSpace(userID) == "" {
		return ErrPrincipal
	}

	identity, err := s.identityFor(ctx, userID, identityID)
	if err != nil {
		return err
	}

	// Drop the signing permissions of this identity first: a lease that
	// outlives the revocation would let a task keep signing with a key the
	// user just withdrew.
	s.RevokeSigningLeases(identity.ID)

	if _, err := s.store.RevokeIdentity(ctx, identity.ID, userID); err != nil {
		return err
	}

	keys, err := s.store.ListKeysForUser(ctx, userID)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if key.IdentityID != identity.ID {
			continue
		}
		if key.State == Revoked && !key.CleanupPending {
			// Already revoked and its secret is gone. Repeating the revoke
			// must not destroy anything a second time.
			continue
		}
		if _, err := s.store.RevokeKey(ctx, key.IdentityID, key.Generation); err != nil {
			return err
		}
		job, err := s.store.CreateJob(ctx, Job{
			ID:             s.newID(),
			UserID:         userID,
			IdentityID:     key.IdentityID,
			Generation:     key.Generation,
			Kind:           "destroy",
			IdempotencyKey: fmt.Sprintf("destroy:%s:%d", key.IdentityID, key.Generation),
			State:          "pending",
		})
		if err != nil && !errors.Is(err, ErrConflict) {
			return err
		}
		if err := s.cleanupSecret(ctx, key, job); err != nil {
			// The local revoke already happened. The pending job records the
			// outstanding cleanup.
			continue
		}
	}
	return nil
}

func (s *Service) cleanupSecret(ctx context.Context, key Key, job Job) error {
	if err := s.custody.DestroyAll(ctx, key.InternalSecretRef); err != nil {
		if job.ID != "" {
			_, _ = s.store.UpdateJobState(ctx, job.ID, "pending", err.Error())
		}
		return err
	}
	if _, err := s.store.ClearCleanupPending(ctx, key.IdentityID, key.Generation); err != nil {
		return err
	}
	if job.ID != "" {
		if _, err := s.store.UpdateJobState(ctx, job.ID, "done", ""); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) identityFor(ctx context.Context, userID, identityID string) (Identity, error) {
	if strings.TrimSpace(identityID) == "" {
		return Identity{}, ErrScope
	}
	identities, err := s.store.ListIdentitiesForUser(ctx, userID)
	if err != nil {
		return Identity{}, err
	}
	for _, identity := range identities {
		if identity.ID == identityID {
			return identity, nil
		}
	}
	return Identity{}, ErrScope
}

func (s *Service) returnKey(ctx context.Context, userID, identityID string, generation uint64) (PublicIdentity, error) {
	identity, err := s.identityFor(ctx, userID, identityID)
	if err != nil {
		return PublicIdentity{}, err
	}
	key, err := s.store.GetKey(ctx, identity.ID, generation)
	if err != nil {
		return PublicIdentity{}, ErrScope
	}
	return publicIdentity(identity, key), nil
}

func publicIdentity(identity Identity, key Key) PublicIdentity {
	return PublicIdentity{
		ID:                identity.ID,
		UserID:            identity.UserID,
		ProviderID:        identity.ProviderID,
		Generation:        key.Generation,
		PublicKey:         key.PublicKey,
		Fingerprint:       key.Fingerprint,
		State:             key.State,
		AccountID:         key.AccountID,
		Login:             key.Login,
		VerifiedAt:        key.VerifiedAt,
		Active:            !identity.Revoked && identity.ActiveGeneration == key.Generation && key.State == Ready,
		CleanupPending:    key.CleanupPending,
		Diagnostic:        key.Diagnostic,
		ConsentProjectIDs: append([]string{}, key.ConsentProjectIDs...),
	}
}

// secretRefFor builds the custody reference of one generation.
//
// The reference is a single path segment: the custody adapter rejects
// separators so a reference can never escape its mount.
func secretRefFor(identityID string, generation uint64) string {
	return fmt.Sprintf("r2d-git-%s-%d", identityID, generation)
}
