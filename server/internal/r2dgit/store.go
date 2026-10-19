package r2dgit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrConflict = errors.New("git_identity_conflict")

type Database interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}
type Transactions interface {
	Begin(context.Context) (pgx.Tx, error)
}
type Store struct {
	DB           Database
	Transactions Transactions
	Restore      *RestoreGuard
}

func (s *Store) transaction(ctx context.Context, fn func(pgx.Tx) error) error {
	return s.transactionAt(ctx, "", fn)
}
func (s *Store) transactionAt(ctx context.Context, expected string, fn func(pgx.Tx) error) error {
	if s == nil || s.DB == nil || s.Transactions == nil {
		return ErrUnavailable
	}
	tx, err := s.Transactions.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if s.Restore != nil {
		if _, err = tx.Exec(ctx, `SET LOCAL multica.git_authority_mutation='witnessed'`); err != nil {
			return err
		}
	}
	if err = fn(tx); err != nil {
		return err
	}
	if s.Restore == nil {
		var installed bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM r2d_git_restore_checkpoint)`).Scan(&installed); err != nil {
			return err
		}
		if installed {
			return ErrUnavailable
		}
	}
	if s.Restore != nil {
		finalCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		if err = s.Restore.commitAt(finalCtx, tx, expected); err != nil {
			return err
		}
		return nil
	}
	return tx.Commit(ctx)
}

var errStaleAuthorizationSnapshot = errors.New("git_authorization_snapshot_changed")

// Only audited pure DB readers use this helper. An arbitrary mutation
// callback, external operation or uncertain commit is never replayed.
func (s *Store) readOnly(ctx context.Context, fn func(pgx.Tx) error) error {
	for attempt := 0; attempt < 3; attempt++ {
		err := s.transaction(ctx, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY`); err != nil {
				return err
			}
			return fn(tx)
		})
		if !errors.Is(err, errStaleAuthorizationSnapshot) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return ErrConflict
}

func event(ctx context.Context, db Database, userID, subjectID, action string) error {
	_, err := db.Exec(ctx, `INSERT INTO r2d_git_security_event(id,user_id,subject_id,action) VALUES($1,$2,$3,$4)`, uuid.NewString(), userID, subjectID, action)
	return err
}

type Provider struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Kind     string   `json:"kind"`
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	HostPins []string `json:"-"`
}
type Profile struct {
	Providers           []Provider       `json:"providers"`
	Identities          []PublicIdentity `json:"identities"`
	ManagementAvailable bool             `json:"management_available"`
	Projects            []ProjectOption  `json:"projects"`
}
type KeyMaterial struct {
	PublicKey  string `json:"-"`
	PrivateKey []byte `json:"-"`
}

func (KeyMaterial) String() string   { return "[redacted Git key material]" }
func (KeyMaterial) GoString() string { return "[redacted Git key material]" }

type KeyGenerator interface {
	Generate(context.Context) (KeyMaterial, error)
}
type KeyCustody interface {
	Store(context.Context, string, KeyMaterial) (int, error)
	DestroyAll(context.Context, string) error
}
type IdentityVerifier interface {
	Verify(context.Context, Provider, string, string, uint64) (Verification, error)
}

// Service is wired to the application DB. Worker dependencies default nil, so
// an unconfigured server cannot create keys or pretend verification succeeded.
type Service struct {
	Store       *Store
	Generator   KeyGenerator
	Custody     KeyCustody
	Verifier    IdentityVerifier
	OutputProof RepositoryProver
	WritePolicy ProviderWritePolicy
	Now         func() time.Time
}

func NewService(db Database, tx Transactions) *Service {
	return &Service{Store: &Store{DB: db, Transactions: tx}, Now: time.Now}
}
func (s *Service) available() bool {
	return s != nil && s.Generator != nil && s.Custody != nil && s.Verifier != nil
}
func (s *Service) Profile(ctx context.Context, userID string) (Profile, error) {
	out := Profile{Providers: []Provider{}, Identities: []PublicIdentity{}, Projects: []ProjectOption{}, ManagementAvailable: s.available()}
	if !activeHuman(ctx, s.Store.DB, userID) {
		return out, ErrPrincipal
	}
	var projectErr error
	out.Projects, projectErr = projectsFor(ctx, s.Store.DB, userID)
	if projectErr != nil {
		return out, projectErr
	}
	rows, err := s.Store.DB.Query(ctx, `SELECT id::text,label,kind,host,port FROM r2d_git_provider WHERE enabled ORDER BY label,id`)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var p Provider
		if err = rows.Scan(&p.ID, &p.Label, &p.Kind, &p.Host, &p.Port); err != nil {
			rows.Close()
			return out, err
		}
		out.Providers = append(out.Providers, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	rows, err = s.Store.DB.Query(ctx, keySelect+` WHERE i.user_id=$1 ORDER BY i.id,k.generation DESC`, userID)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		k, _, err := scanKey(rows)
		if err != nil {
			return out, err
		}
		out.Identities = append(out.Identities, k)
	}
	return out, rows.Err()
}

const keySelect = `SELECT i.id::text,i.user_id::text,i.provider_id::text,k.generation,k.public_key,k.fingerprint,k.state,k.account_id,k.login,k.verified_at,
 (i.active_generation=k.generation AND NOT i.revoked),k.cleanup_pending,k.diagnostic,k.internal_secret_ref,k.consent_project_ids
 FROM r2d_git_identity i JOIN r2d_git_key k ON k.identity_id=i.id`

type scanner interface{ Scan(...any) error }

func scanKey(row scanner) (PublicIdentity, string, error) {
	var p PublicIdentity
	var ref string
	var at pgtype.Timestamptz
	var consent []byte
	err := row.Scan(&p.ID, &p.UserID, &p.ProviderID, &p.Generation, &p.PublicKey, &p.Fingerprint, &p.State, &p.AccountID, &p.Login, &at, &p.Active, &p.CleanupPending, &p.Diagnostic, &ref, &consent)
	if err == nil && json.Unmarshal(consent, &p.ConsentProjectIDs) != nil {
		return p, ref, ErrUnavailable
	}
	if at.Valid {
		p.VerifiedAt = &at.Time
	}
	return p, ref, err
}
func loadKey(ctx context.Context, db Database, userID, id string, generation uint64) (PublicIdentity, string, error) {
	return scanKey(db.QueryRow(ctx, keySelect+` WHERE i.user_id=$1 AND i.id=$2 AND k.generation=$3`, userID, id, generation))
}
func loadProvider(ctx context.Context, db Database, id string) (Provider, error) {
	var p Provider
	var pins []byte
	err := db.QueryRow(ctx, `SELECT id::text,label,kind,host,port,host_pins FROM r2d_git_provider WHERE id=$1 AND enabled`, id).Scan(&p.ID, &p.Label, &p.Kind, &p.Host, &p.Port, &pins)
	if err == nil && (json.Unmarshal(pins, &p.HostPins) != nil || len(p.HostPins) == 0) {
		return p, ErrIdentity
	}
	return p, err
}

func (s *Service) Generate(ctx context.Context, userID, providerID, requestID string, consentProjects []string) (PublicIdentity, error) {
	if !s.available() {
		return PublicIdentity{}, ErrUnavailable
	}
	if _, err := uuid.Parse(requestID); err != nil {
		return PublicIdentity{}, ErrScope
	}
	consentProjects = append([]string{}, consentProjects...)
	sort.Strings(consentProjects)
	workerToken := uuid.NewString()
	var id, ref string
	var generation uint64
	fresh := false
	err := s.Store.transaction(ctx, func(tx pgx.Tx) error {
		if !activeHuman(ctx, tx, userID) {
			return ErrPrincipal
		}
		for i, project := range consentProjects {
			if i > 0 && consentProjects[i-1] == project {
				return ErrScope
			}
			rank, e := projectRole(ctx, tx, userID, project)
			if e != nil || rank < 1 {
				return ErrScope
			}
		}
		if _, err := loadProvider(ctx, tx, providerID); err != nil {
			return ErrScope
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, userID+":"+providerID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO r2d_git_identity(id,user_id,provider_id) SELECT $1,$2,$3 WHERE EXISTS(SELECT 1 FROM "user" WHERE id=$2) ON CONFLICT(user_id,provider_id) DO NOTHING`, uuid.NewString(), userID, providerID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT id::text FROM r2d_git_identity WHERE user_id=$1 AND provider_id=$2 FOR UPDATE`, userID, providerID).Scan(&id); err != nil {
			return err
		}
		var jobIdentity, kind string
		err := tx.QueryRow(ctx, `SELECT identity_id::text,generation,kind FROM r2d_git_key_job WHERE user_id=$1 AND idempotency_key=$2`, userID, requestID).Scan(&jobIdentity, &generation, &kind)
		if err == nil {
			if jobIdentity != id || kind != "provision" {
				return ErrConflict
			}
			key, _, e := loadKey(ctx, tx, userID, id, generation)
			if e != nil {
				return e
			}
			if string(encode(key.ConsentProjectIDs)) != string(encode(consentProjects)) {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var pending bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM r2d_git_key WHERE identity_id=$1 AND state IN ('provisioning','pending_verification'))`, id).Scan(&pending); err != nil {
			return err
		}
		if pending {
			return ErrConflict
		}
		if err := tx.QueryRow(ctx, `SELECT COALESCE(max(generation),0)+1 FROM r2d_git_key WHERE identity_id=$1`, id).Scan(&generation); err != nil {
			return err
		}
		ref = uuid.NewString()
		if _, err := tx.Exec(ctx, `INSERT INTO r2d_git_key(identity_id,generation,internal_secret_ref,state,consent_project_ids) VALUES($1,$2,$3,'provisioning',$4)`, id, generation, ref, encode(consentProjects)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO r2d_git_key_job(id,user_id,identity_id,generation,kind,idempotency_key,worker_token,lease_until) VALUES($1,$2,$3,$4,'provision',$5,$6,clock_timestamp()+interval '30 seconds')`, uuid.NewString(), userID, id, generation, requestID, workerToken); err != nil {
			return err
		}
		fresh = true
		return event(ctx, tx, userID, id, "key_provision_intent")
	})
	if err != nil {
		return PublicIdentity{}, err
	}
	if fresh {
		workerCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		material, err := s.Generator.Generate(workerCtx)
		if err == nil {
			defer clear(material.PrivateKey)
			var key KeyGeneration
			key, err = newGeneration(id, userID, providerID, ref, generation, material.PublicKey)
			if err == nil {
				if workerCtx.Err() != nil {
					err = ErrUnavailable
				} else {
					_, err = s.Custody.Store(workerCtx, ref, material)
				}
			}
			if err == nil {
				err = s.Store.transaction(ctx, func(tx pgx.Tx) error {
					// A stale worker cannot acknowledge a reconciled/revoked generation.
					var live bool
					if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM r2d_git_key_job WHERE identity_id=$1 AND generation=$2 AND kind='provision' AND state='pending' AND worker_token=$3 AND lease_until>clock_timestamp())`, id, generation, workerToken).Scan(&live); e != nil {
						return e
					}
					if !live {
						return ErrRevoked
					}
					// Revoke may race the worker. Never revive a tombstoned row.
					tag, e := tx.Exec(ctx, `UPDATE r2d_git_key SET public_key=$3,fingerprint=$4,state='pending_verification' WHERE identity_id=$1 AND generation=$2 AND state='provisioning'`, id, generation, key.public.PublicKey, key.public.Fingerprint)
					if e != nil {
						return e
					}
					if tag.RowsAffected() != 1 {
						return ErrRevoked
					}
					_, e = tx.Exec(ctx, `UPDATE r2d_git_key_job SET state='done' WHERE identity_id=$1 AND generation=$2 AND kind='provision'`, id, generation)
					return e
				})
			}
		}
		if err != nil {
			// Intent survives a crash/DB outage. Reconciliation tombstones any
			// incomplete provision before retrying cleanup, never reuses a key.
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			_ = s.failProvision(cleanupCtx, userID, id, generation)
			cancel()
			return PublicIdentity{}, ErrUnavailable
		}
	}
	p, _, err := loadKey(ctx, s.Store.DB, userID, id, generation)
	return p, err
}

func queueCleanup(ctx context.Context, tx pgx.Tx, userID, id string, generation uint64) error {
	_, err := tx.Exec(ctx, `INSERT INTO r2d_git_key_job(id,user_id,identity_id,generation,kind,idempotency_key) VALUES($1,$2,$3,$4,'destroy',$5) ON CONFLICT(identity_id,generation,kind) DO NOTHING`, uuid.NewString(), userID, id, generation, uuid.NewString())
	return err
}
func (s *Service) failProvision(ctx context.Context, userID, id string, generation uint64) error {
	return s.Store.transaction(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE r2d_git_key SET state='revoked',cleanup_pending=true,diagnostic='git_custody_unavailable' WHERE identity_id=$1 AND generation=$2`, id, generation); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE r2d_git_key_job SET state='error' WHERE identity_id=$1 AND generation=$2 AND kind='provision'`, id, generation); err != nil {
			return err
		}
		return queueCleanup(ctx, tx, userID, id, generation)
	})
}

// ReconcileExpired runs after a worker deadline, including after process restart.
// It never regenerates or retries a possibly successful external write. KV CAS=0
// prevents a delayed write from replacing an already-created/destroyed version;
// a missing KV path remains cleanup-pending rather than a false destruction ack.
func (s *Service) ReconcileExpired(ctx context.Context, userID, id string) error {
	return s.Store.transaction(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE r2d_git_key_job j SET state='error' FROM r2d_git_identity i WHERE i.id=j.identity_id AND i.id=$1 AND i.user_id=$2 AND j.kind='provision' AND j.state='pending' AND j.lease_until<clock_timestamp() RETURNING j.generation`, id, userID)
		if err != nil {
			return err
		}
		var generations []uint64
		for rows.Next() {
			var g uint64
			if err := rows.Scan(&g); err != nil {
				rows.Close()
				return err
			}
			generations = append(generations, g)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, g := range generations {
			if _, err := tx.Exec(ctx, `UPDATE r2d_git_key SET state='revoked',cleanup_pending=true,diagnostic='git_provision_interrupted' WHERE identity_id=$1 AND generation=$2`, id, g); err != nil {
				return err
			}
			if err := queueCleanup(ctx, tx, userID, id, g); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Service) Verify(ctx context.Context, userID, id string, generation uint64) (PublicIdentity, error) {
	if !activeHuman(ctx, s.Store.DB, userID) {
		return PublicIdentity{}, ErrPrincipal
	}
	if !s.available() {
		return PublicIdentity{}, ErrUnavailable
	}
	p, ref, err := loadKey(ctx, s.Store.DB, userID, id, generation)
	if err != nil {
		return p, err
	}
	if p.State != PendingVerification {
		return p, ErrIdentity
	}
	provider, err := loadProvider(ctx, s.Store.DB, p.ProviderID)
	if err != nil {
		return p, ErrIdentity
	}
	v, err := s.Verifier.Verify(ctx, provider, ref, id, generation)
	if err != nil {
		_, _ = s.Store.DB.Exec(ctx, `UPDATE r2d_git_key SET diagnostic='git_identity_unverified' WHERE identity_id=$1 AND generation=$2 AND state='pending_verification'`, id, generation)
		return PublicIdentity{}, ErrIdentity
	}
	k := KeyGeneration{public: p, secretRef: ref}
	verified, err := k.verified(v)
	if err != nil || v.VerifiedAt.After(s.Now().Add(time.Minute)) || v.VerifiedAt.Before(s.Now().Add(-time.Minute)) {
		return PublicIdentity{}, ErrIdentity
	}
	err = s.Store.transaction(ctx, func(tx pgx.Tx) error {
		if !activeHuman(ctx, tx, userID) {
			return ErrPrincipal
		}
		var active uint64
		var revoked bool
		if err := tx.QueryRow(ctx, `SELECT active_generation,revoked FROM r2d_git_identity WHERE id=$1 AND user_id=$2 FOR UPDATE`, id, userID).Scan(&active, &revoked); err != nil {
			return err
		}
		current, _, err := loadKey(ctx, tx, userID, id, generation)
		if err != nil {
			return err
		}
		if current.State != PendingVerification {
			return ErrIdentity
		}
		var previousLogin, previousAccount string
		err = tx.QueryRow(ctx, `SELECT login,account_id FROM r2d_git_key WHERE identity_id=$1 AND verified_at IS NOT NULL ORDER BY generation LIMIT 1`, id).Scan(&previousLogin, &previousAccount)
		if err == nil && !sameProviderAccount(previousLogin, previousAccount, v.Login, v.AccountID) {
			return ErrIdentity
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE r2d_git_key SET state='ready',login=$3,account_id=$4,verified_at=$5,diagnostic='' WHERE identity_id=$1 AND generation=$2`, id, generation, verified.public.Login, verified.public.AccountID, v.VerifiedAt)
		if err != nil {
			return err
		}
		if active == 0 && !revoked {
			_, err = tx.Exec(ctx, `UPDATE r2d_git_identity SET active_generation=$2,epoch=epoch+1 WHERE id=$1`, id, generation)
			if err != nil {
				return err
			}
		}
		return event(ctx, tx, userID, id, "key_verified")
	})
	if err != nil {
		return PublicIdentity{}, err
	}
	p, _, err = loadKey(ctx, s.Store.DB, userID, id, generation)
	return p, err
}

func (s *Service) Activate(ctx context.Context, userID, id string, generation uint64) (PublicIdentity, error) {
	err := s.Store.transaction(ctx, func(tx pgx.Tx) error {
		if !activeHuman(ctx, tx, userID) {
			return ErrPrincipal
		}
		var active uint64
		if err := tx.QueryRow(ctx, `SELECT active_generation FROM r2d_git_identity WHERE id=$1 AND user_id=$2 FOR UPDATE`, id, userID).Scan(&active); err != nil {
			return err
		}
		p, _, err := loadKey(ctx, tx, userID, id, generation)
		if err != nil {
			return err
		}
		if p.State != Ready || generation < active {
			return ErrIdentity
		}
		if active == generation {
			return nil
		}
		if active > 0 {
			old, _, err := loadKey(ctx, tx, userID, id, active)
			if err != nil {
				return err
			}
			if !sameProviderAccount(old.Login, old.AccountID, p.Login, p.AccountID) {
				return ErrIdentity
			}
			if _, err := tx.Exec(ctx, `UPDATE r2d_git_key SET state='revoked',cleanup_pending=true WHERE identity_id=$1 AND generation=$2`, id, active); err != nil {
				return err
			}
			if err := queueCleanup(ctx, tx, userID, id, active); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE r2d_git_identity SET active_generation=$2,epoch=epoch+1,revoked=false WHERE id=$1`, id, generation); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE r2d_git_run_grant SET state='revoked' WHERE identity_id=$1`, id); err != nil {
			return err
		}
		return event(ctx, tx, userID, id, "key_activated")
	})
	if err != nil {
		return PublicIdentity{}, err
	}
	p, _, err := loadKey(ctx, s.Store.DB, userID, id, generation)
	return p, err
}

func (s *Service) Revoke(ctx context.Context, userID, id string) error {
	err := s.Store.transaction(ctx, func(tx pgx.Tx) error {
		if !activeHuman(ctx, tx, userID) {
			return ErrPrincipal
		}
		var exists string
		if err := tx.QueryRow(ctx, `SELECT id::text FROM r2d_git_identity WHERE id=$1 AND user_id=$2 FOR UPDATE`, id, userID).Scan(&exists); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE r2d_git_identity SET active_generation=0,epoch=epoch+1,revoked=true WHERE id=$1`, id); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE r2d_git_run_grant SET state='revoked' WHERE identity_id=$1`, id); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `UPDATE r2d_git_key SET state='revoked',cleanup_pending=true WHERE identity_id=$1 RETURNING generation`, id)
		if err != nil {
			return err
		}
		var generations []uint64
		for rows.Next() {
			var g uint64
			if err := rows.Scan(&g); err != nil {
				rows.Close()
				return err
			}
			generations = append(generations, g)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, g := range generations {
			if err := queueCleanup(ctx, tx, userID, id, g); err != nil {
				return err
			}
		}
		return event(ctx, tx, userID, id, "identity_revoked")
	})
	if err != nil {
		return err
	}
	_ = s.Cleanup(ctx, userID, id)
	return nil
}

// Cleanup is retryable from the durable job table. It never reverses a local
// tombstone. Incomplete provisioning is reconciled to revoked before destroy.
func (s *Service) Cleanup(ctx context.Context, userID, id string) error {
	if err := s.ReconcileExpired(ctx, userID, id); err != nil {
		return err
	}
	if s.Custody == nil {
		return ErrUnavailable
	}
	rows, err := s.Store.DB.Query(ctx, `SELECT k.generation,k.internal_secret_ref,k.state FROM r2d_git_key k JOIN r2d_git_identity i ON i.id=k.identity_id WHERE i.id=$1 AND i.user_id=$2 AND k.cleanup_pending AND NOT EXISTS(SELECT 1 FROM r2d_git_key_job j WHERE j.identity_id=k.identity_id AND j.generation=k.generation AND j.kind='provision' AND j.state='pending')`, id, userID)
	if err != nil {
		return err
	}
	type pending struct {
		generation uint64
		ref, state string
	}
	var jobs []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.generation, &p.ref, &p.state); err != nil {
			rows.Close()
			return err
		}
		jobs = append(jobs, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, job := range jobs {
		if job.state == string(Provisioning) {
			if err := s.failProvision(ctx, userID, id, job.generation); err != nil {
				return err
			}
		}
		if err := s.Custody.DestroyAll(ctx, job.ref); err != nil {
			return ErrUnavailable
		}
		err = s.Store.transaction(ctx, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `UPDATE r2d_git_key SET cleanup_pending=false WHERE identity_id=$1 AND generation=$2 AND state='revoked'`, id, job.generation); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE r2d_git_key_job SET state='done' WHERE identity_id=$1 AND generation=$2 AND kind='destroy'`, id, job.generation)
			return err
		})
		if err != nil {
			return err
		}
	}
	var remaining bool
	if err := s.Store.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM r2d_git_key k JOIN r2d_git_identity i ON i.id=k.identity_id WHERE i.id=$1 AND i.user_id=$2 AND k.cleanup_pending)`, id, userID).Scan(&remaining); err != nil {
		return err
	}
	if remaining {
		return ErrConflict
	}
	return nil
}

// NewOpenBaoCustody configures trusted KV transport only; it never creates a key.
// Caller configuration must come from the operator, never an account request.
func NewOpenBaoCustody(baseURL, mount, token string, client *http.Client) (EncryptedCustody, error) {
	b, err := newBaoCustody(baseURL, mount, token, client)
	if err != nil {
		return nil, err
	}
	return baoWorker{b}, nil
}

type baoWorker struct{ bao *baoCustody }

func (b baoWorker) WithSigner(ctx context.Context, ref string, fn func(ssh.Signer) error) error {
	return b.bao.WithSigner(ctx, ref, fn)
}

func (b baoWorker) Store(ctx context.Context, ref string, key KeyMaterial) (int, error) {
	return b.bao.store(ctx, ref, generatedKey{publicKey: key.PublicKey, private: key.PrivateKey})
}
func (b baoWorker) DestroyAll(ctx context.Context, ref string) error {
	return b.bao.destroyAll(ctx, ref)
}

type Ed25519Generator struct{}

func (Ed25519Generator) Generate(ctx context.Context) (KeyMaterial, error) {
	if ctx.Err() != nil {
		return KeyMaterial{}, ErrUnavailable
	}
	k, err := generateProductionKey()
	if err != nil {
		return KeyMaterial{}, err
	}
	return KeyMaterial{PublicKey: k.publicKey, PrivateKey: k.private}, nil
}

// JSON metadata is kept separate from key material throughout DB persistence.
func encode(value any) []byte { b, _ := json.Marshal(value); return b }
