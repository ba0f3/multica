package r2dgit

import (
	"context"
	"errors"
	"testing"
)

func TestSigningLeaseRejectsRotationFromAnotherBackend(t *testing.T) {
	ctx := context.Background()
	first, store, custody, _ := signingTestService(t)
	store.originators["replica-task"] = "user-a"
	identity := readyIdentity(t, first, "user-a")
	old, err := first.OpenSigningLease(ctx, "replica-task", "attempt-1", "provider-1", "daemon-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Sign(ctx, old.LeaseID, "daemon-1", []byte("before rotation")); err != nil {
		t.Fatalf("positive control before rotation: %v", err)
	}
	if err := first.RenewSigningLease(ctx, old.LeaseID, "daemon-1"); err != nil {
		t.Fatalf("positive renew control: %v", err)
	}

	// Separate service and lease registry, shared durable store/custody.
	// Rotating on second must not rely on first's in-memory invalidation map.
	second := NewService(store, custody, first.verifier)
	second.now = first.now
	replacement, err := second.Generate(ctx, "user-a", "provider-1", "rotate-on-second-backend", nil)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Generation <= identity.Generation {
		t.Fatal("test did not generate a newer key generation")
	}
	if _, err := second.Verify(ctx, "user-a", replacement.ID, replacement.Generation); err != nil {
		t.Fatal(err)
	}
	// Preserve the reproduction condition: the old key remains Ready, and
	// no local notification has revoked first's lease.
	key, err := store.GetKey(ctx, identity.ID, identity.Generation)
	if err != nil || key.State != Ready {
		t.Fatalf("old generation unexpectedly revoked in store: %+v, %v", key, err)
	}
	first.leaseMu.Lock()
	locallyRevoked := first.leases[old.LeaseID].Revoked
	first.leaseMu.Unlock()
	if locallyRevoked {
		t.Fatal("test accidentally shared lease invalidation between backends")
	}
	if _, err := first.Sign(ctx, old.LeaseID, "daemon-1", []byte("after rotation")); !errors.Is(err, ErrRevoked) {
		t.Fatalf("old lease signed after remote rotation: %v", err)
	}
	if err := first.RenewSigningLease(ctx, old.LeaseID, "daemon-1"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("old lease renewed after remote rotation: %v", err)
	}

	fresh, err := first.OpenSigningLease(ctx, "replica-task", "attempt-1", "provider-1", "daemon-1")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.PublicKey != replacement.PublicKey {
		t.Fatal("fresh lease did not use the active generation")
	}
	if _, err := first.Sign(ctx, fresh.LeaseID, "daemon-1", []byte("current key")); err != nil {
		t.Fatalf("current generation must remain usable: %v", err)
	}
}
