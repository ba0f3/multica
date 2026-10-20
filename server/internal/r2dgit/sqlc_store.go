package r2dgit

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

// SQLCStore is the database-backed implementation of Store.
//
// It is the only place that knows the shape of the r2d_git_* tables. The
// credential service above it works with plain identifiers, so a schema
// change stays inside this file.
type SQLCStore struct {
	queries *db.Queries
}

// NewSQLCStore builds a store on top of the generated queries.
func NewSQLCStore(queries *db.Queries) *SQLCStore {
	return &SQLCStore{queries: queries}
}

var _ Store = (*SQLCStore)(nil)

func (s *SQLCStore) ListProviders(ctx context.Context) ([]Provider, error) {
	rows, err := s.queries.ListR2DGitProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Provider, 0, len(rows))
	for _, row := range rows {
		provider := Provider{
			ID:      util.UUIDToString(row.ID),
			Label:   row.Label,
			Kind:    row.Kind,
			Host:    row.Host,
			Port:    int(row.Port),
			Enabled: row.Enabled,
		}
		provider.HostPins = decodeHostPins(row.HostPins)
		out = append(out, provider)
	}
	return out, nil
}

func (s *SQLCStore) GetProvider(ctx context.Context, id string) (Provider, error) {
	providerID, err := util.ParseUUID(id)
	if err != nil {
		return Provider{}, ErrScope
	}
	row, err := s.queries.GetR2DGitProvider(ctx, providerID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Provider{}, ErrScope
		}
		return Provider{}, err
	}
	provider := Provider{
		ID:      util.UUIDToString(row.ID),
		Label:   row.Label,
		Kind:    row.Kind,
		Host:    row.Host,
		Port:    int(row.Port),
		Enabled: row.Enabled,
	}
	provider.HostPins = decodeHostPins(row.HostPins)
	return provider, nil
}

func (s *SQLCStore) GetIdentityForUser(ctx context.Context, userID, providerID string) (Identity, error) {
	user, err := util.ParseUUID(userID)
	if err != nil {
		return Identity{}, ErrScope
	}
	provider, err := util.ParseUUID(providerID)
	if err != nil {
		return Identity{}, ErrScope
	}
	row, err := s.queries.GetR2DGitIdentityForUser(ctx, db.GetR2DGitIdentityForUserParams{
		UserID:     user,
		ProviderID: provider,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Identity{}, ErrScope
		}
		return Identity{}, err
	}
	return identityFromRow(row), nil
}

func (s *SQLCStore) ListIdentitiesForUser(ctx context.Context, userID string) ([]Identity, error) {
	user, err := util.ParseUUID(userID)
	if err != nil {
		return nil, ErrScope
	}
	rows, err := s.queries.ListR2DGitIdentitiesForUser(ctx, user)
	if err != nil {
		return nil, err
	}
	out := make([]Identity, 0, len(rows))
	for _, row := range rows {
		out = append(out, identityFromRow(row))
	}
	return out, nil
}

func (s *SQLCStore) ListKeysForUser(ctx context.Context, userID string) ([]Key, error) {
	user, err := util.ParseUUID(userID)
	if err != nil {
		return nil, ErrScope
	}
	rows, err := s.queries.ListR2DGitKeysForUser(ctx, user)
	if err != nil {
		return nil, err
	}
	out := make([]Key, 0, len(rows))
	for _, row := range rows {
		key := Key{
			IdentityID:        util.UUIDToString(row.IdentityID),
			Generation:        uint64(row.Generation),
			PublicKey:         row.PublicKey,
			Fingerprint:       row.Fingerprint,
			InternalSecretRef: row.InternalSecretRef,
			State:             KeyState(row.State),
			AccountID:         row.AccountID,
			Login:             row.Login,
			CleanupPending:    row.CleanupPending,
			Diagnostic:        row.Diagnostic,
			ConsentProjectIDs: decodeConsentProjects(row.ConsentProjectIds),
		}
		if row.VerifiedAt.Valid {
			verifiedAt := row.VerifiedAt.Time.UTC()
			key.VerifiedAt = &verifiedAt
		}
		out = append(out, key)
	}
	return out, nil
}

func (s *SQLCStore) GetKey(ctx context.Context, identityID string, generation uint64) (Key, error) {
	identity, err := util.ParseUUID(identityID)
	if err != nil {
		return Key{}, ErrScope
	}
	row, err := s.queries.GetR2DGitKey(ctx, db.GetR2DGitKeyParams{
		IdentityID: identity,
		Generation: int64(generation),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Key{}, ErrScope
		}
		return Key{}, err
	}
	return keyFromRow(row), nil
}

func (s *SQLCStore) CreateIdentity(ctx context.Context, identity Identity) (Identity, error) {
	id, err := util.ParseUUID(identity.ID)
	if err != nil {
		return Identity{}, err
	}
	user, err := util.ParseUUID(identity.UserID)
	if err != nil {
		return Identity{}, ErrScope
	}
	provider, err := util.ParseUUID(identity.ProviderID)
	if err != nil {
		return Identity{}, ErrScope
	}
	row, err := s.queries.CreateR2DGitIdentity(ctx, db.CreateR2DGitIdentityParams{
		ID:         id,
		UserID:     user,
		ProviderID: provider,
	})
	if err != nil {
		return Identity{}, err
	}
	return identityFromRow(row), nil
}

func (s *SQLCStore) SetActiveGeneration(ctx context.Context, identityID string, generation uint64) (Identity, error) {
	identity, err := util.ParseUUID(identityID)
	if err != nil {
		return Identity{}, ErrScope
	}
	row, err := s.queries.SetR2DGitIdentityActiveGeneration(ctx, db.SetR2DGitIdentityActiveGenerationParams{
		ID:               identity,
		ActiveGeneration: int64(generation),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Identity{}, ErrScope
		}
		return Identity{}, err
	}
	return identityFromRow(row), nil
}

func (s *SQLCStore) RevokeIdentity(ctx context.Context, identityID, userID string) (Identity, error) {
	identity, err := util.ParseUUID(identityID)
	if err != nil {
		return Identity{}, ErrScope
	}
	user, err := util.ParseUUID(userID)
	if err != nil {
		return Identity{}, ErrScope
	}
	row, err := s.queries.RevokeR2DGitIdentity(ctx, db.RevokeR2DGitIdentityParams{
		ID:     identity,
		UserID: user,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Identity{}, ErrScope
		}
		return Identity{}, err
	}
	return identityFromRow(row), nil
}

func (s *SQLCStore) CreateKey(ctx context.Context, key Key) (Key, error) {
	identity, err := util.ParseUUID(key.IdentityID)
	if err != nil {
		return Key{}, err
	}
	consent := key.ConsentProjectIDs
	if consent == nil {
		// The column only accepts a JSON array, and a nil slice would
		// encode as null.
		consent = []string{}
	}
	encoded, err := json.Marshal(consent)
	if err != nil {
		return Key{}, err
	}
	verifiedAt := pgtype.Timestamptz{}
	if key.VerifiedAt != nil {
		verifiedAt = pgtype.Timestamptz{Time: key.VerifiedAt.UTC(), Valid: true}
	}
	row, err := s.queries.CreateR2DGitKey(ctx, db.CreateR2DGitKeyParams{
		IdentityID:        identity,
		Generation:        int64(key.Generation),
		PublicKey:         key.PublicKey,
		Fingerprint:       key.Fingerprint,
		InternalSecretRef: key.InternalSecretRef,
		State:             string(key.State),
		AccountID:         key.AccountID,
		Login:             key.Login,
		VerifiedAt:        verifiedAt,
		CleanupPending:    key.CleanupPending,
		Diagnostic:        key.Diagnostic,
		ConsentProjectIds: encoded,
	})
	if err != nil {
		return Key{}, err
	}
	return keyFromRow(row), nil
}

func (s *SQLCStore) MarkKeyReady(ctx context.Context, identityID string, generation uint64, accountID, login string, verifiedAt time.Time) (Key, error) {
	identity, err := util.ParseUUID(identityID)
	if err != nil {
		return Key{}, err
	}
	row, err := s.queries.MarkR2DGitKeyReady(ctx, db.MarkR2DGitKeyReadyParams{
		IdentityID: identity,
		Generation: int64(generation),
		AccountID:  accountID,
		Login:      login,
		VerifiedAt: pgtype.Timestamptz{Time: verifiedAt.UTC(), Valid: true},
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Key{}, ErrScope
		}
		return Key{}, err
	}
	return keyFromRow(row), nil
}

func (s *SQLCStore) RevokeKey(ctx context.Context, identityID string, generation uint64) (Key, error) {
	identity, err := util.ParseUUID(identityID)
	if err != nil {
		return Key{}, err
	}
	row, err := s.queries.RevokeR2DGitKey(ctx, db.RevokeR2DGitKeyParams{
		IdentityID: identity,
		Generation: int64(generation),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Key{}, ErrScope
		}
		return Key{}, err
	}
	return keyFromRow(row), nil
}

func (s *SQLCStore) ClearCleanupPending(ctx context.Context, identityID string, generation uint64) (Key, error) {
	identity, err := util.ParseUUID(identityID)
	if err != nil {
		return Key{}, err
	}
	row, err := s.queries.ClearR2DGitKeyCleanupPending(ctx, db.ClearR2DGitKeyCleanupPendingParams{
		IdentityID: identity,
		Generation: int64(generation),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Key{}, ErrScope
		}
		return Key{}, err
	}
	return keyFromRow(row), nil
}

func (s *SQLCStore) CreateJob(ctx context.Context, job Job) (Job, error) {
	id, err := util.ParseUUID(job.ID)
	if err != nil {
		return Job{}, err
	}
	user, err := util.ParseUUID(job.UserID)
	if err != nil {
		return Job{}, ErrScope
	}
	identity, err := util.ParseUUID(job.IdentityID)
	if err != nil {
		return Job{}, ErrScope
	}
	row, err := s.queries.CreateR2DGitKeyJob(ctx, db.CreateR2DGitKeyJobParams{
		ID:             id,
		UserID:         user,
		IdentityID:     identity,
		Generation:     int64(job.Generation),
		Kind:           job.Kind,
		IdempotencyKey: job.IdempotencyKey,
		State:          job.State,
		LastError:      job.LastError,
	})
	if err != nil {
		return Job{}, err
	}
	return jobFromRow(row), nil
}

func (s *SQLCStore) GetJobByIdempotencyKey(ctx context.Context, idempotencyKey string) (Job, error) {
	row, err := s.queries.GetR2DGitKeyJobByIdempotencyKey(ctx, idempotencyKey)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Job{}, ErrScope
		}
		return Job{}, err
	}
	return jobFromRow(row), nil
}

func (s *SQLCStore) UpdateJobState(ctx context.Context, id, state, lastError string) (Job, error) {
	jobID, err := util.ParseUUID(id)
	if err != nil {
		return Job{}, err
	}
	row, err := s.queries.UpdateR2DGitKeyJobState(ctx, db.UpdateR2DGitKeyJobStateParams{
		ID:        jobID,
		State:     state,
		LastError: lastError,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Job{}, ErrScope
		}
		return Job{}, err
	}
	return jobFromRow(row), nil
}

func identityFromRow(row db.R2dGitIdentity) Identity {
	return Identity{
		ID:               util.UUIDToString(row.ID),
		UserID:           util.UUIDToString(row.UserID),
		ProviderID:       util.UUIDToString(row.ProviderID),
		ActiveGeneration: uint64(row.ActiveGeneration),
		Epoch:            uint64(row.Epoch),
		Revoked:          row.Revoked,
	}
}

func keyFromRow(row db.R2dGitKey) Key {
	key := Key{
		IdentityID:        util.UUIDToString(row.IdentityID),
		Generation:        uint64(row.Generation),
		PublicKey:         row.PublicKey,
		Fingerprint:       row.Fingerprint,
		InternalSecretRef: row.InternalSecretRef,
		State:             KeyState(row.State),
		AccountID:         row.AccountID,
		Login:             row.Login,
		CleanupPending:    row.CleanupPending,
		Diagnostic:        row.Diagnostic,
		ConsentProjectIDs: decodeConsentProjects(row.ConsentProjectIds),
	}
	if row.VerifiedAt.Valid {
		verifiedAt := row.VerifiedAt.Time.UTC()
		key.VerifiedAt = &verifiedAt
	}
	return key
}

func jobFromRow(row db.R2dGitKeyJob) Job {
	return Job{
		ID:             util.UUIDToString(row.ID),
		UserID:         util.UUIDToString(row.UserID),
		IdentityID:     util.UUIDToString(row.IdentityID),
		Generation:     uint64(row.Generation),
		Kind:           row.Kind,
		IdempotencyKey: row.IdempotencyKey,
		State:          row.State,
		LastError:      row.LastError,
	}
}

func decodeHostPins(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var pins []string
	if json.Unmarshal(raw, &pins) != nil {
		return nil
	}
	return pins
}

func decodeConsentProjects(raw []byte) []string {
	if len(raw) == 0 {
		return []string{}
	}
	var projects []string
	if json.Unmarshal(raw, &projects) != nil {
		return []string{}
	}
	return projects
}
