package r2dgit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"net/http"
	"sync"
	"time"
)

// WorkloadChannels is held by the trusted supervisor/broker. The certificate
// private key belongs to the outside-workload proxy, never to the container.
// Registration is internal to launch; an HTTP request cannot register a lease.
type WorkloadChannels struct {
	mu            sync.Mutex
	authorizer    Authorizer
	now           func() time.Time
	entries       map[[32]byte]workloadChannel
	spent         map[[32]byte]bool
	spentChannels map[string]bool
}

type workloadChannel struct {
	lease    Lease
	lifetime context.Context
}

func NewWorkloadChannels(a Authorizer, now func() time.Time) *WorkloadChannels {
	return &WorkloadChannels{authorizer: a, now: now, entries: make(map[[32]byte]workloadChannel), spent: make(map[[32]byte]bool), spentChannels: make(map[string]bool)}
}

func (c *WorkloadChannels) register(cert *x509.Certificate, l Lease, lifetime context.Context) error {
	if c == nil || c.now == nil || cert == nil || len(cert.Raw) == 0 || lifetime == nil || lifetime.Err() != nil {
		return ErrPrincipal
	}
	if c.now().Before(cert.NotBefore) || !c.now().Before(cert.NotAfter) || l.expires.After(cert.NotAfter) {
		return ErrScope
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	pin := sha256.Sum256(cert.Raw)
	if c.spent[pin] || c.spentChannels[l.channelID] {
		return ErrConflict
	}
	for _, entry := range c.entries {
		if entry.lease.channelID == l.channelID {
			return ErrConflict
		}
	}
	c.entries[pin] = workloadChannel{l, lifetime}
	c.spent[pin] = true
	c.spentChannels[l.channelID] = true
	return nil
}

func (c *WorkloadChannels) revoke(cert *x509.Certificate, lease Lease) {
	if c == nil || cert == nil {
		return
	}
	c.mu.Lock()
	pin := sha256.Sum256(cert.Raw)
	if entry, ok := c.entries[pin]; ok && entry.lease.channelID == lease.channelID && entry.lease.run.spec == lease.run.spec {
		delete(c.entries, pin)
	}
	c.mu.Unlock()
}

// Authenticate uses the TLS-verified leaf, not X-User/Task/Channel headers,
// URL/query parameters, cookies, bearer tokens or a certificate subject string.
func (c *WorkloadChannels) Authenticate(r *http.Request) (Lease, string, error) {
	if c == nil || c.now == nil || r.TLS == nil || len(r.TLS.PeerCertificates) != 1 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return Lease{}, "", ErrPrincipal
	}
	cert := r.TLS.PeerCertificates[0]
	if !bytes.Equal(cert.Raw, r.TLS.VerifiedChains[0][0].Raw) {
		return Lease{}, "", ErrPrincipal
	}
	c.mu.Lock()
	entry, ok := c.entries[sha256.Sum256(cert.Raw)]
	c.mu.Unlock()
	if !ok || entry.lifetime.Err() != nil || !c.now().Before(entry.lease.expires) {
		return Lease{}, "", ErrRevoked
	}
	l := entry.lease
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()
	stop := context.AfterFunc(entry.lifetime, cancel)
	defer stop()
	if err := c.authorizer.Authorize(ctx, l.run, l.grant, l.channelID, l.operation, l.ref, c.now()); err != nil {
		return Lease{}, "", err
	}
	// A revoke while the online policy lookup was in flight must win too.
	c.mu.Lock()
	_, live := c.entries[sha256.Sum256(cert.Raw)]
	c.mu.Unlock()
	if !live || entry.lifetime.Err() != nil || !c.now().Before(l.expires) {
		return Lease{}, "", ErrRevoked
	}
	return l, l.channelID, nil
}
