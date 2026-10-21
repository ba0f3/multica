package r2dgit

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// signingTestService builds a service whose custody can actually sign, so a
// signature produced by the service can be verified against the public key
// the lease handed out.
func signingTestService(t *testing.T) (*Service, *fakeStore, *fakeCustody, *time.Time) {
	t.Helper()
	service, store, custody, _ := newTestService(t)
	custody.signing = true

	clock := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return clock }
	service.leaseTTL = time.Minute
	return service, store, custody, &clock
}

// readyIdentity gives the user a verified key on provider-1.
func readyIdentity(t *testing.T, service *Service, userID string) PublicIdentity {
	t.Helper()
	generated, err := service.Generate(context.Background(), userID, "provider-1", "request-"+userID, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	verified, err := service.Verify(context.Background(), userID, generated.ID, generated.Generation)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return verified
}

func TestOpenSigningLeaseBindsTheTasksOriginator(t *testing.T) {
	service, store, _, _ := signingTestService(t)
	store.originators["task-1"] = "user-a"
	readyIdentity(t, service, "user-a")

	lease, err := service.OpenSigningLease(context.Background(), "task-1", "attempt-1", "provider-1", "daemon-1")
	if err != nil {
		t.Fatalf("OpenSigningLease: %v", err)
	}
	if lease.LeaseID == "" {
		t.Fatal("the lease has no id")
	}
	if lease.PublicKey == "" {
		t.Fatal("the lease carries no public key")
	}
	if !lease.ExpiresAt.After(service.now()) {
		t.Fatalf("the lease expires at %s, which is not in the future", lease.ExpiresAt)
	}
}

func TestOpenSigningLeaseRefusesATaskWithoutAnOriginator(t *testing.T) {
	service, _, _, _ := signingTestService(t)

	if _, err := service.OpenSigningLease(context.Background(), "task-without-originator", "attempt-1", "provider-1", "daemon-1"); !errors.Is(err, ErrPrincipal) {
		t.Fatalf("err = %v, want %v", err, ErrPrincipal)
	}
}

func TestOpenSigningLeaseRefusesAProviderTheUserHasNoReadyKeyFor(t *testing.T) {
	service, store, _, _ := signingTestService(t)
	store.originators["task-1"] = "user-a"

	if _, err := service.OpenSigningLease(context.Background(), "task-1", "attempt-1", "provider-1", "daemon-1"); !errors.Is(err, ErrIdentity) {
		t.Fatalf("err = %v, want %v", err, ErrIdentity)
	}
}

func TestOpenSigningLeaseRefusesADisabledProvider(t *testing.T) {
	service, store, _, _ := signingTestService(t)
	store.originators["task-1"] = "user-a"
	store.providers["provider-2"] = Provider{ID: "provider-2", Kind: "gitea", Enabled: false}
	readyIdentity(t, service, "user-a")

	if _, err := service.OpenSigningLease(context.Background(), "task-1", "attempt-1", "provider-2", "daemon-1"); !errors.Is(err, ErrScope) {
		t.Fatalf("err = %v, want %v", err, ErrScope)
	}
}

func TestSignProducesAVerifiableSignature(t *testing.T) {
	service, store, custody, _ := signingTestService(t)
	store.originators["task-1"] = "user-a"
	readyIdentity(t, service, "user-a")

	lease, err := service.OpenSigningLease(context.Background(), "task-1", "attempt-1", "provider-1", "daemon-1")
	if err != nil {
		t.Fatalf("OpenSigningLease: %v", err)
	}

	payload := []byte("the bytes a git operation signs")
	signature, err := service.Sign(context.Background(), lease.LeaseID, "daemon-1", payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(lease.PublicKey))
	if err != nil {
		t.Fatalf("parse the lease public key: %v", err)
	}
	// The service returns the wire form the SSH agent protocol carries.
	var parsed ssh.Signature
	if err := ssh.Unmarshal(signature, &parsed); err != nil {
		t.Fatalf("unmarshal the signature: %v", err)
	}
	if err := publicKey.Verify(payload, &parsed); err != nil {
		t.Fatalf("the signature does not verify against the leased public key: %v", err)
	}
	if len(custody.stored) != 1 {
		t.Fatalf("custody holds %d secrets, want 1", len(custody.stored))
	}
}

func TestSignRefusesAnUnknownLease(t *testing.T) {
	service, _, _, _ := signingTestService(t)

	if _, err := service.Sign(context.Background(), "not-a-lease", "daemon-1", []byte("data")); err == nil {
		t.Fatal("an unknown lease was accepted")
	}
}

func TestSignStopsAfterTheKeyIsRevoked(t *testing.T) {
	service, store, _, _ := signingTestService(t)
	store.originators["task-1"] = "user-a"
	identity := readyIdentity(t, service, "user-a")

	lease, err := service.OpenSigningLease(context.Background(), "task-1", "attempt-1", "provider-1", "daemon-1")
	if err != nil {
		t.Fatalf("OpenSigningLease: %v", err)
	}

	if err := service.Revoke(context.Background(), "user-a", identity.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if _, err := service.Sign(context.Background(), lease.LeaseID, "daemon-1", []byte("data")); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Sign after revoke: err = %v, want %v", err, ErrRevoked)
	}
	if _, err := service.OpenSigningLease(context.Background(), "task-1", "attempt-1", "provider-1", "daemon-1"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("OpenSigningLease after revoke: err = %v, want %v", err, ErrRevoked)
	}
}

func TestSignRefusesAnExpiredLease(t *testing.T) {
	service, store, _, clock := signingTestService(t)
	store.originators["task-1"] = "user-a"
	readyIdentity(t, service, "user-a")

	lease, err := service.OpenSigningLease(context.Background(), "task-1", "attempt-1", "provider-1", "daemon-1")
	if err != nil {
		t.Fatalf("OpenSigningLease: %v", err)
	}

	*clock = clock.Add(2 * time.Minute)
	if _, err := service.Sign(context.Background(), lease.LeaseID, "daemon-1", []byte("data")); err == nil {
		t.Fatal("an expired lease was accepted")
	}
}

func TestOpenSigningLeaseRefusesAnotherUsersKey(t *testing.T) {
	service, store, _, _ := signingTestService(t)
	store.originators["task-1"] = "user-a"
	store.originators["task-2"] = "user-b"
	readyIdentity(t, service, "user-a")

	// user-b has no identity of their own, so a task authorized by user-b
	// must not be able to borrow user-a's key.
	if _, err := service.OpenSigningLease(context.Background(), "task-2", "attempt-1", "provider-1", "daemon-1"); !errors.Is(err, ErrIdentity) {
		t.Fatalf("err = %v, want %v", err, ErrIdentity)
	}
}

func TestReadyIdentitiesReturnsOnlyVerifiedKeys(t *testing.T) {
	service, _, _, _ := signingTestService(t)

	// A generated but unverified key must not be offered to a run.
	if _, err := service.Generate(context.Background(), "user-a", "provider-1", "request-unverified", nil); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	ready := readyIdentity(t, service, "user-b")

	identities, err := service.ReadyIdentities(context.Background(), "user-b")
	if err != nil {
		t.Fatalf("ReadyIdentities: %v", err)
	}
	if len(identities) != 1 {
		t.Fatalf("ReadyIdentities returned %d identities, want 1", len(identities))
	}
	if identities[0].IdentityID != ready.ID {
		t.Fatalf("identity id = %q, want %q", identities[0].IdentityID, ready.ID)
	}
	if identities[0].ProviderID != "provider-1" {
		t.Fatalf("provider id = %q, want %q", identities[0].ProviderID, "provider-1")
	}
	if identities[0].Host != "github.com" {
		t.Fatalf("provider host = %q, want %q", identities[0].Host, "github.com")
	}
	if identities[0].PublicKey == "" || identities[0].Fingerprint == "" {
		t.Fatal("the identity carries no public key or fingerprint")
	}

	unverified, err := service.ReadyIdentities(context.Background(), "user-a")
	if err != nil {
		t.Fatalf("ReadyIdentities for the unverified user: %v", err)
	}
	if len(unverified) != 0 {
		t.Fatalf("an unverified key was offered to a run: %+v", unverified)
	}
}

func TestReadyIdentitiesSkipsARevokedIdentity(t *testing.T) {
	service, _, _, _ := signingTestService(t)
	identity := readyIdentity(t, service, "user-a")

	if err := service.Revoke(context.Background(), "user-a", identity.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	identities, err := service.ReadyIdentities(context.Background(), "user-a")
	if err != nil {
		t.Fatalf("ReadyIdentities: %v", err)
	}
	if len(identities) != 0 {
		t.Fatalf("a revoked key was offered to a run: %+v", identities)
	}
}

func TestSigningUsesTheCustodyAdapterAndNotTheStore(t *testing.T) {
	service, store, custody, _ := signingTestService(t)
	store.originators["task-1"] = "user-a"
	readyIdentity(t, service, "user-a")

	lease, err := service.OpenSigningLease(context.Background(), "task-1", "attempt-1", "provider-1", "daemon-1")
	if err != nil {
		t.Fatalf("OpenSigningLease: %v", err)
	}

	custody.signing = false
	if _, err := service.Sign(context.Background(), lease.LeaseID, "daemon-1", []byte("data")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v, want %v", err, ErrUnavailable)
	}
}

func TestSignRefusesAnotherDaemonsLease(t *testing.T) {
	service, store, _, _ := signingTestService(t)
	store.originators["task-1"] = "user-a"
	readyIdentity(t, service, "user-a")

	lease, err := service.OpenSigningLease(context.Background(), "task-1", "attempt-1", "provider-1", "daemon-1")
	if err != nil {
		t.Fatalf("OpenSigningLease: %v", err)
	}

	// The lease id is not a credential on its own: another daemon must not be
	// able to spend it.
	if _, err := service.Sign(context.Background(), lease.LeaseID, "daemon-2", []byte("data")); err == nil {
		t.Fatal("a lease issued to one daemon was honoured for another")
	}
}

func TestOpenSigningLeaseRequiresADaemon(t *testing.T) {
	service, store, _, _ := signingTestService(t)
	store.originators["task-1"] = "user-a"
	readyIdentity(t, service, "user-a")

	if _, err := service.OpenSigningLease(context.Background(), "task-1", "attempt-1", "provider-1", ""); !errors.Is(err, ErrPrincipal) {
		t.Fatalf("err = %v, want %v", err, ErrPrincipal)
	}
}

func TestSignRenewsALiveLease(t *testing.T) {
	service, store, _, clock := signingTestService(t)
	store.originators["task-1"] = "user-a"
	readyIdentity(t, service, "user-a")

	lease, err := service.OpenSigningLease(context.Background(), "task-1", "attempt-1", "provider-1", "daemon-1")
	if err != nil {
		t.Fatalf("OpenSigningLease: %v", err)
	}

	// A long run keeps signing as long as it keeps using the lease: each
	// successful signature slides the window forward.
	for step := 0; step < 4; step++ {
		if _, err := service.Sign(context.Background(), lease.LeaseID, "daemon-1", []byte("data")); err != nil {
			t.Fatalf("Sign at step %d: %v", step, err)
		}
		*clock = clock.Add(30 * time.Second)
	}
}

func TestRotationStopsThePreviousGeneration(t *testing.T) {
	service, store, _, _ := signingTestService(t)
	store.originators["task-1"] = "user-a"
	first := readyIdentity(t, service, "user-a")

	lease, err := service.OpenSigningLease(context.Background(), "task-1", "attempt-1", "provider-1", "daemon-1")
	if err != nil {
		t.Fatalf("OpenSigningLease: %v", err)
	}

	// Rotate to a second generation.
	second, err := service.Generate(context.Background(), "user-a", "provider-1", "request-rotation", nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if second.Generation == first.Generation {
		t.Fatal("the rotation reused the first generation")
	}
	if _, err := service.Verify(context.Background(), "user-a", second.ID, second.Generation); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if _, err := service.Sign(context.Background(), lease.LeaseID, "daemon-1", []byte("data")); !errors.Is(err, ErrRevoked) {
		t.Fatalf("a lease of the previous generation still signs: err = %v, want %v", err, ErrRevoked)
	}
}
