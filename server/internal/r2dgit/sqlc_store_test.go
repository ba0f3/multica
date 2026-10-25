package r2dgit

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/multica-ai/multica/server/internal/testutil"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

// newDBStore connects to the test database and returns a store on the real
// schema. The test skips when no database is reachable so the credential
// unit tests still run on a machine without PostgreSQL.
func newDBStore(t *testing.T) (*SQLCStore, *pgxpool.Pool) {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL is not set; skipping the database-backed store test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Skipf("could not connect to the database: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("database not reachable: %v", err)
	}
	t.Cleanup(pool.Close)
	return NewSQLCStore(db.New(pool)), pool
}

func TestSQLCStoreRoundTripsAnIdentityAndItsKey(t *testing.T) {
	store, pool := newDBStore(t)
	ctx := context.Background()

	providerID := insertProviderRow(t, pool, "github", "github.com")
	identity, err := store.CreateIdentity(ctx, Identity{
		ID:         newRandomID(),
		UserID:     newRandomID(),
		ProviderID: providerID,
	})
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM r2d_git_key WHERE identity_id = $1", identity.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM r2d_git_identity WHERE id = $1", identity.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM r2d_git_provider WHERE id = $1", providerID)
	})

	if _, err := store.CreateKey(ctx, Key{
		IdentityID:        identity.ID,
		Generation:        1,
		PublicKey:         "ssh-ed25519 AAAAC3Nza",
		Fingerprint:       "SHA256:abc",
		InternalSecretRef: "r2d-git-" + identity.ID + "-1",
		State:             PendingVerification,
		ConsentProjectIDs: []string{"project-1"},
	}, identity.Epoch); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	keys, err := store.ListKeysForUser(ctx, identity.UserID)
	if err != nil {
		t.Fatalf("ListKeysForUser: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("stored %d keys, want 1", len(keys))
	}
	if keys[0].State != PendingVerification {
		t.Fatalf("state = %q, want %q", keys[0].State, PendingVerification)
	}
	if len(keys[0].ConsentProjectIDs) != 1 || keys[0].ConsentProjectIDs[0] != "project-1" {
		t.Fatalf("consent projects = %v, want [project-1]", keys[0].ConsentProjectIDs)
	}

	verifiedAt := time.Now().UTC().Truncate(time.Millisecond)
	verified, err := store.MarkKeyReady(ctx, identity.ID, 1, "account-1", "octocat", verifiedAt)
	if err != nil {
		t.Fatalf("MarkKeyReady: %v", err)
	}
	if verified.State != Ready || verified.Login != "octocat" {
		t.Fatalf("verified key = %+v", verified)
	}
	if verified.VerifiedAt == nil {
		t.Fatal("verified_at was not stored")
	}

	updated, err := store.SetActiveGeneration(ctx, identity.ID, 1)
	if err != nil {
		t.Fatalf("SetActiveGeneration: %v", err)
	}
	if updated.ActiveGeneration != 1 {
		t.Fatalf("active generation = %d, want 1", updated.ActiveGeneration)
	}
	if updated.Epoch <= identity.Epoch {
		t.Fatalf("epoch = %d, want more than %d", updated.Epoch, identity.Epoch)
	}

	revoked, err := store.RevokeIdentity(ctx, identity.ID, identity.UserID)
	if err != nil {
		t.Fatalf("RevokeIdentity: %v", err)
	}
	if !revoked.Revoked || revoked.ActiveGeneration != 0 {
		t.Fatalf("revoked identity = %+v", revoked)
	}
}

func TestSQLCStoreKeepsUsersApart(t *testing.T) {
	store, pool := newDBStore(t)
	ctx := context.Background()

	providerID := insertProviderRow(t, pool, "gitea", "git.example.com")
	owner := newRandomID()
	other := newRandomID()

	identity, err := store.CreateIdentity(ctx, Identity{ID: newRandomID(), UserID: owner, ProviderID: providerID})
	if err != nil {
		t.Fatalf("CreateIdentity: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM r2d_git_identity WHERE id = $1", identity.ID)
		_, _ = pool.Exec(ctx, "DELETE FROM r2d_git_provider WHERE id = $1", providerID)
	})

	if _, err := store.GetIdentityForUser(ctx, other, providerID); err == nil {
		t.Fatal("another user's identity was returned")
	}
	if _, err := store.GetIdentityForUser(ctx, owner, providerID); err != nil {
		t.Fatalf("the owner's identity was not returned: %v", err)
	}
}

func TestSQLCStoreReopensOnlyAfterRevocationAndWithTheCurrentEpoch(t *testing.T) {
	store, pool := newDBStore(t)
	ctx := t.Context()
	userID := newRandomID()
	fixture := testutil.New(pool, "", userID)
	providerID := fixture.Insert(t, "r2d_git_provider", testutil.Cols{
		"label": "Epoch test", "kind": "gitea", "host": newRandomID() + ".example.com",
		"port": 22, "host_pins": `["SHA256:test-pin"]`, "enabled": true,
	})
	identity, err := store.CreateIdentity(ctx, Identity{ID: newRandomID(), UserID: userID, ProviderID: providerID})
	if err != nil {
		t.Fatal(err)
	}
	fixture.Cleanup(t, "DELETE FROM r2d_git_identity WHERE id = $1", identity.ID)
	fixture.Cleanup(t, "DELETE FROM r2d_git_key WHERE identity_id = $1", identity.ID)
	key := Key{IdentityID: identity.ID, Generation: 1, PublicKey: "ssh-ed25519 test", Fingerprint: "SHA256:first", InternalSecretRef: secretRefFor(identity.ID, 1), State: PendingVerification}
	if _, err := store.CreateKey(ctx, key, identity.Epoch); err != nil {
		t.Fatal(err)
	}
	revoked, err := store.RevokeIdentity(ctx, identity.ID, userID)
	if err != nil {
		t.Fatal(err)
	}
	key.Generation = 2
	key.InternalSecretRef = secretRefFor(identity.ID, 2)
	if _, err := store.CreateKey(ctx, key, revoked.Epoch); !errors.Is(err, ErrConflict) {
		t.Fatalf("generation during revoke sweep = %v, want conflict", err)
	}
	if _, err := store.RevokeKey(ctx, identity.ID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateKey(ctx, key, identity.Epoch); !errors.Is(err, ErrConflict) {
		t.Fatalf("generation with stale epoch = %v, want conflict", err)
	}
	stillRevoked, err := store.GetIdentityForUser(ctx, userID, providerID)
	if err != nil || !stillRevoked.Revoked {
		t.Fatalf("failed generation changed identity: %+v, %v", stillRevoked, err)
	}
	if _, err := store.GetKey(ctx, identity.ID, 2); !errors.Is(err, ErrScope) {
		t.Fatalf("failed generation persisted a key: %v", err)
	}
	if _, err := store.CreateKey(ctx, key, revoked.Epoch); err != nil {
		t.Fatalf("fresh generation: %v", err)
	}
	reopened, err := store.GetIdentityForUser(ctx, userID, providerID)
	if err != nil || reopened.Revoked || reopened.ActiveGeneration != 0 || reopened.Epoch <= revoked.Epoch {
		t.Fatalf("reopened identity = %+v, %v", reopened, err)
	}
	previous, err := store.GetKey(ctx, identity.ID, 1)
	if err != nil || previous.State != Revoked {
		t.Fatalf("old key revived: %+v, %v", previous, err)
	}
}

func TestSQLCStoreJobIdempotencyKeyIsUnique(t *testing.T) {
	store, pool := newDBStore(t)
	ctx := context.Background()

	userID := newRandomID()
	identityID := newRandomID()
	key := "generate:" + userID + ":request-1"
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM r2d_git_key_job WHERE idempotency_key = $1", key)
	})

	if _, err := store.CreateJob(ctx, Job{
		ID:             newRandomID(),
		UserID:         userID,
		IdentityID:     identityID,
		Generation:     1,
		Kind:           "provision",
		IdempotencyKey: key,
		State:          "done",
	}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if _, err := store.CreateJob(ctx, Job{
		ID:             newRandomID(),
		UserID:         userID,
		IdentityID:     identityID,
		Generation:     2,
		Kind:           "provision",
		IdempotencyKey: key,
		State:          "done",
	}); err == nil {
		t.Fatal("a duplicated idempotency key was accepted")
	}
}

// insertProviderRow inserts an enabled provider and removes it afterwards.
func insertProviderRow(t *testing.T, pool *pgxpool.Pool, kind, host string) string {
	t.Helper()
	id := newRandomID()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO r2d_git_provider (id, label, kind, host, port, host_pins, enabled)
		VALUES ($1, $2, $3, $4, 22, '["SHA256:test-pin"]'::jsonb, true)`,
		id, host+" provider", kind, host); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	return id
}
