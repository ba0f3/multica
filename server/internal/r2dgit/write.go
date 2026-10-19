package r2dgit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
)

const zeroObject = "0000000000000000000000000000000000000000"
const maxPackBytes = 16 << 20

var ErrRejected = errors.New("git_update_rejected")

// ErrCommitted means the provider confirmed the mutation and its durable audit
// succeeded, but authorization expired before returning success. Do not retry.
var ErrCommitted = errors.New("git_update_committed_delivery_revoked")

// RefUpdate contains exactly one compare-and-swap, never a refspec or argv.
type RefUpdate struct{ Old, New, Ref string }

func objectID(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (u RefUpdate) valid() bool {
	return objectID(u.Old) && objectID(u.New) && u.New != zeroObject && u.Old != u.New && validWriteRef(u.Ref)
}

// WriteTransport runs in the key worker. Push must verify the provider's current
// old object and call authorize immediately before sending its canonical update.
// Any failure after sending an update is indeterminate, including cancellation.
type WriteTransport interface {
	WriteReference(context.Context, BoundOperation) (string, error)
	ReadReference(context.Context, BoundOperation, string) ([]byte, error)
	Push(context.Context, BoundOperation, RefUpdate, []byte, func(context.Context) error) error
}

type WriteQuarantine interface {
	Prepare(context.Context, []byte, []byte, RefUpdate) ([]byte, error)
}

type ReconciliationJournal interface {
	AuditJournal
	Lookup(context.Context, string) (BoundOperation, string, error)
}

// ReconcileWrite observes the same user's current ref without sending an
// update. Matching the desired object cannot prove which actor wrote it, so the
// original uncertain record remains immutable. Never turn observation into retry.
func (b Broker) ReconcileWrite(ctx context.Context, l Lease, channel, id string) (string, error) {
	journal, ok := b.Journal.(ReconciliationJournal)
	tr, transportOK := b.Transport.(WriteTransport)
	if !ok || !transportOK {
		return "", ErrUnavailable
	}
	ctx, check, stop, err := b.watchWrite(ctx, l, channel)
	if err != nil {
		return "", err
	}
	defer stop()
	original, outcome, err := journal.Lookup(ctx, id)
	if err != nil {
		return "", ErrAudit
	}
	expected := b.writeOperation(l)
	expected.OldObject, expected.NewObject, expected.PackDigest = original.OldObject, original.NewObject, original.PackDigest
	if original != expected || !objectID(original.OldObject) || !objectID(original.NewObject) || original.NewObject == zeroObject || len(original.PackDigest) != 64 {
		return "", ErrScope
	}
	if outcome != "pending" && outcome != "indeterminate" && outcome != "succeeded" {
		return "", ErrScope
	}
	observed, err := tr.WriteReference(ctx, expected)
	if err != nil || !objectID(observed) {
		return "", ErrProvider
	}
	if err = check(ctx); err != nil {
		return "", err
	}
	observation := expected
	observation.Reconciles = id
	observation.ObservedObject = observed
	observationID := uuid.NewString()
	fresh, err := journal.Begin(ctx, observationID, observation)
	if err != nil || !fresh {
		return "", ErrAudit
	}
	if journal.Complete(ctx, observationID, "succeeded") != nil {
		return "", ErrAudit
	}
	if err = check(ctx); err != nil {
		return "", err
	}
	if observed == original.NewObject {
		return "matches_new", nil
	}
	if observed == original.OldObject {
		return "matches_old", nil
	}
	return "diverged", nil
}

func (b Broker) writeOperation(l Lease) BoundOperation {
	s, g := l.run.spec, l.grant.spec
	return BoundOperation{UserID: s.Binding.OriginatorUserID, ContextID: s.ID, TaskID: s.Binding.TaskID, AttemptID: s.AttemptID, ProviderID: g.ProviderID, RepositoryID: g.RepositoryID, IdentityID: g.IdentityID, Generation: g.CredentialGeneration, Operation: Write, Ref: l.ref, RootID: s.RootID, GrantID: g.ID, PolicyEpoch: s.PolicyEpoch, GrantEpoch: g.Epoch}
}

// watchWrite bounds both policy outages and active cancellation. Authority
// adapters must honor context cancellation (the SQL adapter does). This only
// cancels the transport; a remote mutation already sent cannot be recalled.
func (b Broker) watchWrite(ctx context.Context, l Lease, channel string) (context.Context, func(context.Context) error, func(), error) {
	if b.Now == nil || channel != l.channelID {
		return nil, nil, nil, ErrRevoked
	}
	if l.operation != Write || !validWriteRef(l.ref) {
		return nil, nil, nil, ErrScope
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	check := func(parent context.Context) error {
		bounded, done := context.WithTimeout(parent, time.Second)
		defer done()
		if !b.Now().Before(l.expires) {
			return ErrRevoked
		}
		if err := b.Authorizer.Authorize(bounded, l.run, l.grant, channel, Write, l.ref, b.Now()); err != nil {
			return err
		}
		if !b.Now().Before(l.expires) {
			return ErrRevoked
		}
		return nil
	}
	if err := check(ctx); err != nil {
		cancel()
		return nil, nil, nil, err
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-ticker.C:
				if check(ctx) != nil {
					cancel()
					return
				}
			}
		}
	}()
	return ctx, check, func() { close(stop); cancel(); wg.Wait() }, nil
}

// WriteAdvertisement discloses only the granted ref, after live same-key proof
// and a durable intent. It is not a reservation of the remote ref.
func (b Broker) WriteAdvertisement(ctx context.Context, l Lease, channel, id string) (string, error) {
	tr, ok := b.Transport.(WriteTransport)
	if !ok || b.Journal == nil || !nonempty(id) {
		return "", ErrUnavailable
	}
	ctx, check, stop, err := b.watchWrite(ctx, l, channel)
	if err != nil {
		return "", err
	}
	defer stop()
	op := b.writeOperation(l)
	fresh, err := b.Journal.Begin(ctx, id, op)
	if err != nil {
		return "", ErrAudit
	}
	if !fresh {
		return "", ErrIndeterminate
	}
	old, err := tr.WriteReference(ctx, op)
	if err != nil || !objectID(old) {
		_ = b.Journal.Complete(ctx, id, "denied")
		return "", ErrProvider
	}
	if err = check(ctx); err != nil {
		_ = b.Journal.Complete(ctx, id, "denied")
		return "", err
	}
	if b.Journal.Complete(ctx, id, "succeeded") != nil {
		return "", ErrAudit
	}
	if err = check(ctx); err != nil {
		return "", err
	}
	return old, nil
}

// Write accepts a bounded protocol request, validates in secret-free quarantine,
// records immutable old/new/digest intent, then sends a single canonical CAS.
// A duplicate or uncertain operation is never retried by this method.
func (b Broker) Write(ctx context.Context, l Lease, channel, id string, u RefUpdate, incoming []byte) error {
	tr, ok := b.Transport.(WriteTransport)
	if !ok || b.Quarantine == nil || b.Journal == nil || !nonempty(id) {
		return ErrUnavailable
	}
	if !u.valid() || u.Ref != l.ref || len(incoming) < 32 || len(incoming) > maxPackBytes {
		return ErrScope
	}
	incoming = bytes.Clone(incoming)
	defer clear(incoming)
	ctx, check, stop, err := b.watchWrite(ctx, l, channel)
	if err != nil {
		return err
	}
	defer stop()
	op := b.writeOperation(l)
	old, err := tr.WriteReference(ctx, op)
	if err != nil {
		return ErrProvider
	}
	if old != u.Old {
		return ErrRejected
	}
	var base []byte
	if old != zeroObject {
		base, err = tr.ReadReference(ctx, op, old)
		if err != nil {
			clear(base)
			return ErrProvider
		}
		defer clear(base)
	}
	pack, err := b.Quarantine.Prepare(ctx, base, incoming, u)
	if err != nil {
		clear(pack)
		return ErrRejected
	}
	defer clear(pack)
	if len(pack) < 32 || len(pack) > maxPackBytes {
		return ErrRejected
	}
	if err = check(ctx); err != nil {
		return err
	}
	digest := sha256.Sum256(pack)
	op.OldObject, op.NewObject, op.PackDigest = u.Old, u.New, hex.EncodeToString(digest[:])
	fresh, err := b.Journal.Begin(ctx, id, op)
	if err != nil {
		return ErrAudit
	}
	if !fresh {
		return ErrIndeterminate
	}
	if err = check(ctx); err != nil {
		_ = b.Journal.Complete(ctx, id, "denied")
		return err
	}
	err = tr.Push(ctx, op, u, pack, check)
	confirmed := err == nil
	if err == nil && check(ctx) != nil {
		err = ErrCommitted
	}
	outcome := "succeeded"
	if err != nil && !confirmed {
		outcome = "indeterminate"
		if errors.Is(err, ErrRejected) || errors.Is(err, ErrScope) || errors.Is(err, ErrRevoked) || errors.Is(err, ErrPrincipal) || errors.Is(err, ErrRuntime) {
			outcome = "denied"
		}
	}
	// Cancellation must not prevent persisting an uncertain remote outcome.
	auditCtx, done := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer done()
	if b.Journal.Complete(auditCtx, id, outcome) != nil {
		return ErrIndeterminate
	}
	if outcome == "indeterminate" {
		return ErrIndeterminate
	}
	if err == nil && check(ctx) != nil {
		return ErrCommitted
	}
	return err
}
