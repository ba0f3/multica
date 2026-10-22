package r2dgit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/42wim/sshsig"
	"golang.org/x/crypto/ssh"
)

// marshalIdentity renders the public identity exactly as an HTTP response
// would, so a test can assert that no secret field reaches the browser.
func marshalIdentity(identity PublicIdentity) (string, error) {
	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

// --- test doubles -----------------------------------------------------------

type fakeStore struct {
	mu          sync.Mutex
	providers   map[string]Provider
	identities  map[string]Identity
	keys        map[string]Key
	jobs        map[string]Job
	originators map[string]string
	nextID      int
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		providers:   map[string]Provider{},
		identities:  map[string]Identity{},
		keys:        map[string]Key{},
		jobs:        map[string]Job{},
		originators: map[string]string{},
	}
}

// TaskOriginator resolves the human who authorized a task.
func (s *fakeStore) TaskOriginator(_ context.Context, taskID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	originator, ok := s.originators[taskID]
	if !ok || originator == "" {
		return "", ErrPrincipal
	}
	return originator, nil
}

func keySlot(identityID string, generation uint64) string {
	return identityID + "|" + string(rune(generation))
}

func (s *fakeStore) ListProviders(context.Context) ([]Provider, error) {
	return s.listProviders(false)
}

func (s *fakeStore) ListAllProviders(context.Context) ([]Provider, error) {
	return s.listProviders(true)
}

func (s *fakeStore) listProviders(all bool) ([]Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Provider{}
	for _, provider := range s.providers {
		if !all && !provider.Enabled {
			continue
		}
		out = append(out, provider)
	}
	return out, nil
}

func (s *fakeStore) CreateProvider(_ context.Context, provider Provider) (Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if provider.ID == "" {
		return Provider{}, ErrScope
	}
	if _, exists := s.providers[provider.ID]; exists {
		return Provider{}, ErrConflict
	}
	s.providers[provider.ID] = provider
	return provider, nil
}

func (s *fakeStore) GetProvider(_ context.Context, id string) (Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	provider, ok := s.providers[id]
	if !ok {
		return Provider{}, ErrScope
	}
	return provider, nil
}

func (s *fakeStore) GetProviderByKindHostPort(_ context.Context, kind, host string, port int) (Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, provider := range s.providers {
		if strings.EqualFold(provider.Kind, kind) &&
			strings.EqualFold(provider.Host, host) &&
			provider.Port == port {
			return provider, nil
		}
	}
	return Provider{}, ErrScope
}

func (s *fakeStore) UpdateProvider(_ context.Context, provider Provider) (Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.providers[provider.ID]; !ok {
		return Provider{}, ErrScope
	}
	s.providers[provider.ID] = provider
	return provider, nil
}

func (s *fakeStore) GetIdentityForUser(_ context.Context, userID, providerID string) (Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, identity := range s.identities {
		if identity.UserID == userID && identity.ProviderID == providerID {
			return identity, nil
		}
	}
	return Identity{}, ErrScope
}

func (s *fakeStore) ListIdentitiesForUser(_ context.Context, userID string) ([]Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Identity{}
	for _, identity := range s.identities {
		if identity.UserID == userID {
			out = append(out, identity)
		}
	}
	return out, nil
}

func (s *fakeStore) ListKeysForUser(_ context.Context, userID string) ([]Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Key{}
	for _, key := range s.keys {
		if identity, ok := s.identities[key.IdentityID]; ok && identity.UserID == userID {
			out = append(out, key)
		}
	}
	return out, nil
}

func (s *fakeStore) GetKey(_ context.Context, identityID string, generation uint64) (Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.keys[keySlot(identityID, generation)]
	if !ok {
		return Key{}, ErrScope
	}
	return key, nil
}

func (s *fakeStore) CreateIdentity(_ context.Context, identity Identity) (Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	identity.ID = "identity-" + string(rune('a'+s.nextID))
	s.identities[identity.ID] = identity
	return identity, nil
}

func (s *fakeStore) SetActiveGeneration(_ context.Context, identityID string, generation uint64) (Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	identity, ok := s.identities[identityID]
	if !ok {
		return Identity{}, ErrScope
	}
	identity.ActiveGeneration = generation
	identity.Epoch++
	s.identities[identityID] = identity
	return identity, nil
}

func (s *fakeStore) RevokeIdentity(_ context.Context, identityID, userID string) (Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	identity, ok := s.identities[identityID]
	if !ok || identity.UserID != userID {
		return Identity{}, ErrScope
	}
	identity.Revoked = true
	identity.ActiveGeneration = 0
	identity.Epoch++
	s.identities[identityID] = identity
	return identity, nil
}

func (s *fakeStore) CreateKey(_ context.Context, key Key) (Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[keySlot(key.IdentityID, key.Generation)] = key
	return key, nil
}

func (s *fakeStore) MarkKeyReady(_ context.Context, identityID string, generation uint64, accountID, login string, verifiedAt time.Time) (Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := keySlot(identityID, generation)
	key, ok := s.keys[slot]
	if !ok {
		return Key{}, ErrScope
	}
	key.State = Ready
	key.AccountID = accountID
	key.Login = login
	key.VerifiedAt = &verifiedAt
	s.keys[slot] = key
	return key, nil
}

func (s *fakeStore) RevokeKey(_ context.Context, identityID string, generation uint64) (Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := keySlot(identityID, generation)
	key, ok := s.keys[slot]
	if !ok {
		return Key{}, ErrScope
	}
	key.State = Revoked
	key.CleanupPending = true
	s.keys[slot] = key
	return key, nil
}

func (s *fakeStore) ClearCleanupPending(_ context.Context, identityID string, generation uint64) (Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	slot := keySlot(identityID, generation)
	key, ok := s.keys[slot]
	if !ok {
		return Key{}, ErrScope
	}
	key.CleanupPending = false
	s.keys[slot] = key
	return key, nil
}

func (s *fakeStore) CreateJob(_ context.Context, job Job) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.jobs[job.IdempotencyKey]; ok {
		return existing, ErrConflict
	}
	s.nextID++
	job.ID = "job-" + string(rune('a'+s.nextID))
	s.jobs[job.IdempotencyKey] = job
	return job, nil
}

func (s *fakeStore) GetJobByIdempotencyKey(_ context.Context, key string) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job, ok := s.jobs[key]
	if !ok {
		return Job{}, ErrScope
	}
	return job, nil
}

func (s *fakeStore) UpdateJobState(_ context.Context, id, state, lastError string) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, job := range s.jobs {
		if job.ID != id {
			continue
		}
		job.State = state
		job.LastError = lastError
		s.jobs[key] = job
		return job, nil
	}
	return Job{}, ErrScope
}

type fakeCustody struct {
	mu        sync.Mutex
	stored    map[string]KeyMaterial
	destroyed []string
	storeErr  error
	// signing makes WithSigner hand out a real signer for the stored
	// material, so a test can verify a produced signature.
	signing bool
}

func newFakeCustody() *fakeCustody {
	return &fakeCustody{stored: map[string]KeyMaterial{}}
}

func (c *fakeCustody) Store(_ context.Context, ref string, material KeyMaterial) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.storeErr != nil {
		return 0, c.storeErr
	}
	if _, exists := c.stored[ref]; exists {
		return 0, ErrConflict
	}
	c.stored[ref] = material
	return 1, nil
}

func (c *fakeCustody) DestroyAll(_ context.Context, ref string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.destroyed = append(c.destroyed, ref)
	delete(c.stored, ref)
	return nil
}

func (c *fakeCustody) WithSigner(_ context.Context, ref string, fn func(ssh.Signer) error) error {
	return c.WithPrivatePEM(context.Background(), ref, func(pem []byte) error {
		signer, err := ssh.ParsePrivateKey(pem)
		if err != nil {
			return ErrIdentity
		}
		return fn(signer)
	})
}

func (c *fakeCustody) WithPrivatePEM(_ context.Context, ref string, fn func([]byte) error) error {
	c.mu.Lock()
	signing := c.signing
	material, ok := c.stored[ref]
	c.mu.Unlock()
	if !signing {
		return ErrUnavailable
	}
	if !ok {
		return ErrIdentity
	}
	if fn == nil {
		return ErrScope
	}
	return fn(material.Private)
}

type fakeVerifier struct {
	login   string
	err     error
	refSeen string
}

func (v *fakeVerifier) Verify(_ context.Context, _ Provider, secretRef string, _ uint64) (string, error) {
	v.refSeen = secretRef
	return v.login, v.err
}

// --- tests ------------------------------------------------------------------

func newTestService(t *testing.T) (*Service, *fakeStore, *fakeCustody, *fakeVerifier) {
	t.Helper()
	store := newFakeStore()
	store.providers["provider-1"] = Provider{
		ID: "provider-1", Label: "GitHub", Kind: "github", Host: "github.com", Port: 22,
		HostPins: []string{"SHA256:pin"}, Enabled: true,
	}
	custody := newFakeCustody()
	verifier := &fakeVerifier{login: "octocat"}
	service := NewService(store, custody, verifier)
	service.random = strings.NewReader(strings.Repeat("r", 4096))
	service.now = func() time.Time { return time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC) }
	service.newID = func() string {
		store.nextID++
		return "id-" + string(rune('a'+store.nextID))
	}
	return service, store, custody, verifier
}

func TestGenerateCreatesPendingIdentityWithoutLeakingPrivateBytes(t *testing.T) {
	service, store, custody, _ := newTestService(t)

	identity, err := service.Generate(context.Background(), "user-a", "provider-1", "request-1", nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if identity.State != PendingVerification {
		t.Fatalf("state = %q, want %q", identity.State, PendingVerification)
	}
	if identity.PublicKey == "" || identity.Fingerprint == "" {
		t.Fatal("the public key and fingerprint must be returned so the user can register them")
	}
	if identity.Active {
		t.Fatal("a key that was never verified must not be active")
	}

	rendered, err := marshalIdentity(identity)
	if err != nil {
		t.Fatalf("marshal identity: %v", err)
	}
	for _, secret := range []string{"PRIVATE KEY", "internal_secret_ref", "secret_ref"} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("the public identity leaked %q: %s", secret, rendered)
		}
	}

	stored := custody.stored
	if len(stored) != 1 {
		t.Fatalf("custody holds %d secrets, want 1", len(stored))
	}
	for ref, material := range stored {
		if len(material.Private) == 0 {
			t.Fatal("the private key was not handed to custody")
		}
		if !strings.HasPrefix(ref, "r2d-git-") {
			t.Fatalf("secret ref %q does not use the reserved prefix", ref)
		}
	}
	if _, ok := store.keys[keySlot(identity.ID, 1)]; !ok {
		t.Fatal("the key row was not written")
	}
}

func TestGenerateIsIdempotentForTheSameRequest(t *testing.T) {
	service, store, custody, _ := newTestService(t)

	first, err := service.Generate(context.Background(), "user-a", "provider-1", "request-1", nil)
	if err != nil {
		t.Fatalf("first Generate: %v", err)
	}
	second, err := service.Generate(context.Background(), "user-a", "provider-1", "request-1", nil)
	if err != nil {
		t.Fatalf("second Generate: %v", err)
	}
	if first.ID != second.ID || first.Generation != second.Generation {
		t.Fatalf("a repeated request produced a different identity: %+v vs %+v", first, second)
	}
	if len(custody.stored) != 1 {
		t.Fatalf("custody holds %d secrets, want 1", len(custody.stored))
	}
	if len(store.keys) != 1 {
		t.Fatalf("the store holds %d keys, want 1", len(store.keys))
	}
}

func TestGenerateRefusesUnknownOrDisabledProvider(t *testing.T) {
	service, store, _, _ := newTestService(t)
	store.providers["provider-2"] = Provider{ID: "provider-2", Label: "Disabled", Kind: "gitea", Enabled: false}

	if _, err := service.Generate(context.Background(), "user-a", "missing", "request-1", nil); !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("unknown provider error = %v, want %v", err, ErrProviderNotFound)
	}
	if _, err := service.Generate(context.Background(), "user-a", "provider-2", "request-2", nil); !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("disabled provider error = %v, want %v", err, ErrProviderNotFound)
	}
}

func TestGenerateDoesNotWriteMetadataWhenCustodyFails(t *testing.T) {
	service, store, custody, _ := newTestService(t)
	custody.storeErr = ErrUnavailable
	if _, err := service.Generate(context.Background(), "user-a", "provider-1", "request-1", nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Generate error = %v, want %v", err, ErrUnavailable)
	}
	if len(store.keys) != 0 {
		t.Fatalf("the store holds %d keys, want 0 when custody failed", len(store.keys))
	}
}

func TestVerifyMovesPendingKeyToReady(t *testing.T) {
	service, _, custody, verifier := newTestService(t)

	generated, err := service.Generate(context.Background(), "user-a", "provider-1", "request-1", nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	verified, err := service.Verify(context.Background(), "user-a", generated.ID, generated.Generation)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.State != Ready {
		t.Fatalf("state = %q, want %q", verified.State, Ready)
	}
	if verified.Login != "octocat" {
		t.Fatalf("login = %q, want %q", verified.Login, "octocat")
	}
	if verified.VerifiedAt == nil {
		t.Fatal("verified_at was not recorded")
	}
	if !verified.Active {
		t.Fatal("a verified key must become the active generation")
	}
	if verifier.refSeen == "" {
		t.Fatal("the verifier did not receive the stored secret reference")
	}
	if _, ok := custody.stored[verifier.refSeen]; !ok {
		t.Fatalf("the verifier was given an unknown secret reference %q", verifier.refSeen)
	}
}

func TestVerifyRefusesAnotherUsersIdentity(t *testing.T) {
	service, _, _, _ := newTestService(t)

	generated, err := service.Generate(context.Background(), "user-a", "provider-1", "request-1", nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := service.Verify(context.Background(), "user-b", generated.ID, generated.Generation); !errors.Is(err, ErrScope) {
		t.Fatalf("Verify error = %v, want %v", err, ErrScope)
	}
}

func TestVerifyRefusesARevokedIdentity(t *testing.T) {
	service, _, _, _ := newTestService(t)

	generated, err := service.Generate(context.Background(), "user-a", "provider-1", "request-1", nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := service.Revoke(context.Background(), "user-a", generated.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := service.Verify(context.Background(), "user-a", generated.ID, generated.Generation); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Verify error = %v, want %v", err, ErrRevoked)
	}
}

func TestProfileReturnsOnlyTheCallersIdentities(t *testing.T) {
	service, _, _, _ := newTestService(t)

	if _, err := service.Generate(context.Background(), "user-a", "provider-1", "request-1", nil); err != nil {
		t.Fatalf("Generate for A: %v", err)
	}
	if _, err := service.Generate(context.Background(), "user-b", "provider-1", "request-2", nil); err != nil {
		t.Fatalf("Generate for B: %v", err)
	}

	profile, err := service.Profile(context.Background(), "user-a")
	if err != nil {
		t.Fatalf("Profile: %v", err)
	}
	if len(profile.Identities) != 1 {
		t.Fatalf("profile holds %d identities, want 1", len(profile.Identities))
	}
	if profile.Identities[0].UserID != "user-a" {
		t.Fatalf("profile leaked another user's identity: %+v", profile.Identities[0])
	}
	if len(profile.Providers) != 1 {
		t.Fatalf("profile holds %d providers, want 1", len(profile.Providers))
	}
}

func TestRevokeStopsLocalUseAndDestroysTheSecret(t *testing.T) {
	service, store, custody, _ := newTestService(t)

	generated, err := service.Generate(context.Background(), "user-a", "provider-1", "request-1", nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := service.Revoke(context.Background(), "user-a", generated.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	key, err := store.GetKey(context.Background(), generated.ID, generated.Generation)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if key.State != Revoked {
		t.Fatalf("key state = %q, want %q", key.State, Revoked)
	}
	if len(custody.destroyed) != 1 {
		t.Fatalf("custody destroyed %d secrets, want 1", len(custody.destroyed))
	}
	if len(custody.stored) != 0 {
		t.Fatalf("custody still holds %d secrets after revoke", len(custody.stored))
	}

	profile, err := service.Profile(context.Background(), "user-a")
	if err != nil {
		t.Fatalf("Profile: %v", err)
	}
	if len(profile.Identities) != 1 {
		t.Fatalf("profile holds %d identities, want 1", len(profile.Identities))
	}
	if profile.Identities[0].Active {
		t.Fatal("a revoked identity must not be active")
	}
}

func TestRevokeIsIdempotent(t *testing.T) {
	service, _, custody, _ := newTestService(t)

	generated, err := service.Generate(context.Background(), "user-a", "provider-1", "request-1", nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := service.Revoke(context.Background(), "user-a", generated.ID); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	before := len(custody.destroyed)
	if err := service.Revoke(context.Background(), "user-a", generated.ID); err != nil {
		t.Fatalf("second Revoke: %v", err)
	}
	if len(custody.destroyed) != before {
		t.Fatalf("a repeated revoke destroyed %d secrets, want %d", len(custody.destroyed), before)
	}
}

func TestRevokeRefusesAnotherUsersIdentity(t *testing.T) {
	service, _, _, _ := newTestService(t)

	generated, err := service.Generate(context.Background(), "user-a", "provider-1", "request-1", nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := service.Revoke(context.Background(), "user-b", generated.ID); !errors.Is(err, ErrScope) {
		t.Fatalf("Revoke error = %v, want %v", err, ErrScope)
	}
}

// revokingVerifier simulates a revocation that lands while the provider
// round trip is still in flight.
type revokingVerifier struct {
	service    *Service
	userID     string
	identityID string
}

func (v *revokingVerifier) Verify(context.Context, Provider, string, uint64) (string, error) {
	if err := v.service.Revoke(context.Background(), v.userID, v.identityID); err != nil {
		return "", err
	}
	return "octocat", nil
}

func TestVerifyDoesNotReviveAKeyRevokedDuringTheRoundTrip(t *testing.T) {
	service, store, _, _ := newTestService(t)
	service.random = strings.NewReader(strings.Repeat("r", 4096))

	generated, err := service.Generate(context.Background(), "user-a", "provider-1", "request-1", nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	service.verifier = &revokingVerifier{service: service, userID: "user-a", identityID: generated.ID}

	if _, err := service.Verify(context.Background(), "user-a", generated.ID, generated.Generation); err == nil {
		t.Fatal("Verify succeeded although the identity was revoked mid-flight")
	}

	key, err := store.GetKey(context.Background(), generated.ID, generated.Generation)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if key.State != Revoked {
		t.Fatalf("key state = %q, want %q: a revoked key must not be marked ready", key.State, Revoked)
	}
}

func TestSignGiteaSSHKeyVerification(t *testing.T) {
	service, store, custody, _ := newTestService(t)
	custody.signing = true
	store.providers["gitea-1"] = Provider{
		ID: "gitea-1", Label: "Gitea", Kind: "gitea", Host: "git.example.com", Port: 22,
		Enabled: true,
	}

	generated, err := service.Generate(context.Background(), "user-a", "gitea-1", "request-gitea", nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	token := "gitea-verification-token-abc"
	signature, err := service.SignGiteaSSHKeyVerification(
		context.Background(), "user-a", generated.ID, generated.Generation, token,
	)
	if err != nil {
		t.Fatalf("SignGiteaSSHKeyVerification: %v", err)
	}
	if err := sshsig.Verify(
		strings.NewReader(token),
		[]byte(signature),
		[]byte(generated.PublicKey),
		giteaSSHVerifyNamespace,
	); err != nil {
		t.Fatalf("Verify armored signature: %v", err)
	}
}

func TestSignGiteaSSHKeyVerificationRejectsNonGiteaProvider(t *testing.T) {
	service, _, custody, _ := newTestService(t)
	custody.signing = true

	generated, err := service.Generate(context.Background(), "user-a", "provider-1", "request-1", nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if _, err := service.SignGiteaSSHKeyVerification(
		context.Background(), "user-a", generated.ID, generated.Generation, "token",
	); !errors.Is(err, ErrScope) {
		t.Fatalf("error = %v, want %v", err, ErrScope)
	}
}
