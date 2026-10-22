package r2dgit

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"

	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/multica-ai/multica/server/internal/util/secretbox"
)

func TestDBCustodyRoundTrip(t *testing.T) {
	_, pool := newDBStore(t)
	queries := db.New(pool)
	ctx := context.Background()

	key := make([]byte, secretbox.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	box, err := secretbox.New(key)
	if err != nil {
		t.Fatalf("secretbox.New: %v", err)
	}
	custody, err := NewDBCustody(queries, box)
	if err != nil {
		t.Fatalf("NewDBCustody: %v", err)
	}

	ref := "r2d-git-test-" + newRandomID() + "-1"
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM r2d_git_key_secret WHERE secret_ref = $1", ref)
	})

	material, err := GenerateKeyMaterial(randomReader{})
	if err != nil {
		t.Fatalf("GenerateKeyMaterial: %v", err)
	}
	version, err := custody.Store(ctx, ref, material)
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if version != 1 {
		t.Fatalf("version = %d, want 1", version)
	}
	if _, err := custody.Store(ctx, ref, material); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate Store: %v, want ErrConflict", err)
	}

	var seen bool
	if err := custody.WithSigner(ctx, ref, func(signer ssh.Signer) error {
		seen = true
		if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
			t.Fatalf("unexpected key type %q", signer.PublicKey().Type())
		}
		return nil
	}); err != nil {
		t.Fatalf("WithSigner: %v", err)
	}
	if !seen {
		t.Fatal("WithSigner callback was not invoked")
	}

	if err := custody.DestroyAll(ctx, ref); err != nil {
		t.Fatalf("DestroyAll: %v", err)
	}
	if err := custody.WithSigner(ctx, ref, func(ssh.Signer) error { return nil }); err == nil {
		t.Fatal("expected error after DestroyAll")
	}
}
