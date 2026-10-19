package r2dgit

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// ConfigureWorkers connects explicit trusted dependencies. It performs no key
// generation, provider call, capability advertisement or runtime activation.
func (s *Service) ConfigureWorkers(generator KeyGenerator, custody EncryptedCustody, addresses map[string][]netip.Prefix, quarantine GitQuarantine) (*SSHWorker, error) {
	if s == nil || s.Store == nil || s.Store.DB == nil || s.Now == nil || generator == nil || custody == nil || !filepath.IsAbs(quarantine.GitExecutable) || !filepath.IsAbs(quarantine.Root) {
		return nil, ErrUnavailable
	}
	info, err := os.Lstat(quarantine.Root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, ErrRuntime
	}
	worker, err := NewSSHWorker(s, custody, addresses, quarantine)
	if err != nil {
		return nil, err
	}
	s.Generator, s.Custody, s.Verifier, s.OutputProof = generator, custody, worker, worker
	return worker, nil
}

// MaintainCredentials bounds one startup/tick pass. Interrupted provisions are
// revoked and destroyed, never regenerated. An outage returns failure and leaves
// the durable jobs pending for a later pass.
func (s *Service) MaintainCredentials(ctx context.Context, limit int) error {
	if s == nil || s.Store == nil || s.Store.DB == nil || s.Custody == nil || limit < 1 || limit > 128 {
		return ErrUnavailable
	}
	ctx, stop := context.WithTimeout(ctx, 20*time.Second)
	defer stop()
	rows, err := s.Store.DB.Query(ctx, `SELECT i.user_id::text,i.id::text FROM r2d_git_identity i WHERE EXISTS(SELECT 1 FROM r2d_git_key k WHERE k.identity_id=i.id AND k.cleanup_pending) OR EXISTS(SELECT 1 FROM r2d_git_key_job j WHERE j.identity_id=i.id AND j.kind='provision' AND j.state='pending' AND j.lease_until<clock_timestamp()) ORDER BY i.id LIMIT $1`, limit)
	if err != nil {
		return err
	}
	type identity struct{ user, id string }
	var pending []identity
	for rows.Next() {
		var item identity
		if err = rows.Scan(&item.user, &item.id); err != nil {
			break
		}
		pending = append(pending, item)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return err
	}
	for _, item := range pending {
		if err := s.ReconcileExpired(ctx, item.user, item.id); err != nil {
			return err
		}
		if err := s.Cleanup(ctx, item.user, item.id); err != nil {
			return err
		}
	}
	return nil
}
