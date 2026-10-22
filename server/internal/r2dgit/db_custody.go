package r2dgit

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/ssh"

	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/multica-ai/multica/server/internal/util/secretbox"
)

// DBCustody stores Git private keys as secretbox ciphertext in PostgreSQL.
//
// It is the default custody backend when OpenBao is not configured. A
// deployment still needs a 32-byte master key (MULTICA_GIT_SECRET_KEY or a
// JWT_SECRET-derived key in development).
type DBCustody struct {
	queries *db.Queries
	box     *secretbox.Box
}

func (DBCustody) String() string   { return "[database Git custody]" }
func (DBCustody) GoString() string { return "[database Git custody]" }

// NewDBCustody builds a database-backed custody adapter.
func NewDBCustody(queries *db.Queries, box *secretbox.Box) (EncryptedCustody, error) {
	if queries == nil || box == nil {
		return nil, ErrUnavailable
	}
	return &DBCustody{queries: queries, box: box}, nil
}

// Store writes one immutable generation. A duplicate ref is refused.
func (c *DBCustody) Store(ctx context.Context, ref string, material KeyMaterial) (int, error) {
	if c == nil || !custodySegment.MatchString(ref) {
		return 0, ErrUnavailable
	}
	if len(material.Private) == 0 {
		return 0, ErrIdentity
	}
	sealed, err := c.box.Seal(material.Private)
	if err != nil {
		return 0, ErrUnavailable
	}
	rows, err := c.queries.InsertR2DGitKeySecret(ctx, db.InsertR2DGitKeySecretParams{
		SecretRef: ref,
		Sealed:    sealed,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return 0, ErrConflict
		}
		return 0, ErrUnavailable
	}
	if rows == 0 {
		return 0, ErrConflict
	}
	return 1, nil
}

// WithSigner loads a stored generation and hands it to fn while the decoded
// bytes are alive.
func (c *DBCustody) WithSigner(ctx context.Context, ref string, fn func(ssh.Signer) error) error {
	if fn == nil {
		return ErrScope
	}
	if c == nil || !custodySegment.MatchString(ref) {
		return ErrUnavailable
	}
	row, err := c.queries.GetR2DGitKeySecret(ctx, ref)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUnavailable
		}
		return ErrUnavailable
	}
	private, err := c.box.Open(row.Sealed)
	if err != nil {
		return ErrUnavailable
	}
	defer clear(private)

	signer, err := ssh.ParsePrivateKey(private)
	if err != nil {
		return ErrIdentity
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return ErrIdentity
	}
	return fn(signer)
}

// DestroyAll permanently removes the secret for one ref.
func (c *DBCustody) DestroyAll(ctx context.Context, ref string) error {
	if c == nil || !custodySegment.MatchString(ref) {
		return ErrUnavailable
	}
	if err := c.queries.DeleteR2DGitKeySecret(ctx, ref); err != nil {
		return ErrUnavailable
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
