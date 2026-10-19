//go:build linux

package r2dgit

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

type ProtectedDeploymentConfig struct {
	Restore       *RestoreGuard
	Application   WorkloadApplicationConfig
	Generator     KeyGenerator
	Custody       EncryptedCustody
	Addresses     map[string][]netip.Prefix
	Quarantine    GitQuarantine
	WritePolicy   ProviderWritePolicy
	RetryFailures bool
}

// ProtectedDeployment owns one protected-only scheduler. It never invokes the
// legacy task claim, daemon dispatch, native session or public result paths.
type ProtectedDeployment struct {
	mu            sync.Mutex
	tick          sync.Mutex
	lifetime      context.Context
	cancel        context.CancelFunc
	service       *Service
	app           *WorkloadApplication
	runtimeID     string
	closed        bool
	retryFailures bool
	retryCursor   string
}

// NewProtectedDeployment performs startup reconciliation before dispatch. No
// production startup supplies this configuration until rollout acceptance; nil
// is the ordinary server's disabled state and touches no credentials or engine.
func NewProtectedDeployment(ctx context.Context, s *Service, c *ProtectedDeploymentConfig) (*ProtectedDeployment, error) {
	if c == nil {
		return nil, nil
	}
	if s == nil || s.Store == nil || s.Store.DB == nil || s.Now == nil || c.Application.AcceptanceID == "" || len(c.Application.OperatorKey) != ed25519.PublicKeySize || c.Application.Model == nil {
		return nil, ErrUnavailable
	}
	if c.Restore == nil || c.Restore.check(ctx, s.Store.DB) != nil {
		return nil, ErrRevoked
	}
	publicService := s
	store := *s.Store
	store.Restore = c.Restore
	protectedService := *s
	protectedService.Store = &store
	s = &protectedService
	acceptance, err := s.runtimeAcceptance(ctx, c.Application.AcceptanceID, c.Application.OperatorKey)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(c.Application.Policy)
	if err != nil || acceptance.RuntimeID != c.Application.Policy.RuntimeID || acceptance.PolicyDigest != hexDigest(raw) {
		return nil, ErrRuntime
	}
	// Keep failure atomic with respect to the handler's profile dependencies.
	workers := *s
	workers.WritePolicy = c.WritePolicy
	transport, err := workers.ConfigureWorkers(c.Generator, c.Custody, c.Addresses, c.Quarantine)
	if err != nil {
		return nil, err
	}
	application := c.Application
	if application.Transport == nil {
		application.Transport = transport
	}
	workers.OutputProof = application.Transport
	application.Journal = SQLJournal{DB: s.Store.DB, Restore: c.Restore}
	application.Quarantine = c.Quarantine
	app, err := NewWorkloadApplication(&workers, application)
	if err != nil {
		return nil, err
	}
	if err = app.Recover(ctx); err != nil {
		_ = app.Close()
		return nil, err
	}
	if err = workers.MaintainCredentials(ctx, 32); err != nil {
		_ = app.Close()
		return nil, err
	}
	publicService.Store = &store
	publicService.Generator, publicService.Custody, publicService.Verifier, publicService.OutputProof = workers.Generator, workers.Custody, workers.Verifier, workers.OutputProof
	publicService.WritePolicy = workers.WritePolicy
	lifetime, cancel := context.WithCancel(context.Background())
	return &ProtectedDeployment{service: &workers, app: app, runtimeID: application.Policy.RuntimeID, lifetime: lifetime, cancel: cancel, retryFailures: c.RetryFailures}, nil
}

func (d *ProtectedDeployment) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if d == nil {
		http.Error(w, "protected execution unavailable", http.StatusServiceUnavailable)
		return
	}
	d.app.ServeHTTP(w, r)
}

// Tick executes a bounded, deterministic pass. Prepare arbitrates the exact
// queued->running transition under its existing locks; duplicate workers cannot
// deliver source before that claim succeeds. There is no retry on uncertainty.
func (d *ProtectedDeployment) Tick(ctx context.Context) error {
	if d == nil {
		return ErrRuntime
	}
	d.tick.Lock()
	defer d.tick.Unlock()
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return ErrRuntime
	}
	ctx, stop := context.WithTimeout(ctx, 25*time.Second)
	defer stop()
	unregister := context.AfterFunc(d.lifetime, stop)
	defer unregister()
	if err := d.service.MaintainCredentials(ctx, 8); err != nil {
		return err
	}
	if d.retryFailures {
		if err := d.retryFailed(ctx); err != nil {
			return err
		}
	}
	rows, err := d.service.Store.DB.Query(ctx, `SELECT c.id::text FROM r2d_git_run_context c JOIN agent_task_queue t ON t.id=c.task_id WHERE t.status='queued' AND t.runtime_id=$1 AND c.state='active' ORDER BY t.created_at,c.id LIMIT 4`, d.runtimeID)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := d.app.Prepare(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

func (d *ProtectedDeployment) Run(ctx context.Context) error {
	if d == nil {
		return ErrRuntime
	}
	defer d.Close()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := d.Tick(ctx); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (d *ProtectedDeployment) retryFailed(ctx context.Context) error {
	rows, err := d.service.Store.DB.Query(ctx, `SELECT c.id::text FROM r2d_git_run_context c JOIN agent_task_queue t ON t.id=c.task_id WHERE t.runtime_id=$1 AND t.status='failed' AND c.state='active' AND c.id::text>$2 AND NOT EXISTS(SELECT 1 FROM r2d_git_run_context retry WHERE retry.parent_id=c.id AND retry.derivation='retry') ORDER BY c.id LIMIT 4`, d.runtimeID, d.retryCursor)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		d.retryCursor = ""
		return nil
	}
	for _, id := range ids {
		d.retryCursor = id
		if _, err = d.service.EnqueueRetry(ctx, id); err != nil && !errors.Is(err, ErrScope) && !errors.Is(err, ErrRevoked) && !errors.Is(err, ErrPrincipal) && !errors.Is(err, ErrIdentity) && !errors.Is(err, ErrConflict) {
			return err
		}
	}
	return nil
}

func (d *ProtectedDeployment) Close() error {
	if d == nil {
		return nil
	}
	d.cancel()
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	return d.app.Close()
}
