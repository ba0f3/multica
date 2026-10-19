//go:build linux

package handler

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/multica-ai/multica/server/internal/middleware"
	"github.com/multica-ai/multica/server/internal/r2dgit"
	"github.com/multica-ai/multica/server/internal/service"
	"github.com/multica-ai/multica/server/internal/sourceguard"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

//go:embed protected_control.html
var protectedControlHTML []byte

//go:embed protected_control.js
var protectedControlJS []byte

// LocalProtectedServerConfig never comes from a task or environment switch.
// Both listeners must be loopback TLS. Production main does not construct it.
type LocalProtectedServerConfig struct {
	Control, Broker       net.Listener
	ControlTLS, BrokerTLS *tls.Config
	Authentication        middleware.ProtectedControlAuthConfig
	Worker                *r2dgit.ProtectedDeploymentConfig
}

type LocalProtectedServer struct {
	auth                            *middleware.ProtectedControlAuth
	worker                          *r2dgit.ProtectedDeployment
	control, broker                 *http.Server
	controlListener, brokerListener net.Listener
	stop                            context.CancelFunc
	once                            sync.Once
	started                         atomic.Bool
	closed                          atomic.Bool
	closeErr                        error
}

func loopbackEndpoint(listener net.Listener) (string, bool) {
	if listener == nil {
		return "", false
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	return listener.Addr().String(), ok && address.IP.IsLoopback() && address.Port > 0
}
func servingTLS(c *tls.Config, endpoint string) bool {
	if c == nil || c.MinVersion < tls.VersionTLS13 || (c.MaxVersion != 0 && c.MaxVersion < tls.VersionTLS13) || len(c.Certificates) != 1 || c.InsecureSkipVerify || c.GetConfigForClient != nil || c.GetCertificate != nil || len(c.NameToCertificate) != 0 {
		return false
	}
	certificate := c.Certificates[0]
	if len(certificate.Certificate) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return false
	}
	host, _, err := net.SplitHostPort(endpoint)
	now := time.Now()
	if err != nil || leaf.VerifyHostname(host) != nil || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return false
	}
	key, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return false
	}
	public, err := x509.MarshalPKIXPublicKey(key.Public())
	return err == nil && bytes.Equal(public, leaf.RawSubjectPublicKeyInfo)
}

// NewLocalProtectedServer completes the local authentication/control/broker/worker
// composition without constructing any legacy router, relay, scheduler or signer.
// Nil remains disabled, with no listener, credential or engine side effect.
func NewLocalProtectedServer(ctx context.Context, s *r2dgit.Service, c *LocalProtectedServerConfig) (_ *LocalProtectedServer, err error) {
	if c == nil {
		return nil, nil
	}
	success := false
	defer func() {
		if !success {
			if c.Control != nil {
				_ = c.Control.Close()
			}
			if c.Broker != nil {
				_ = c.Broker.Close()
			}
		}
	}()
	control, controlOK := loopbackEndpoint(c.Control)
	broker, brokerOK := loopbackEndpoint(c.Broker)
	if !controlOK || !brokerOK || control == broker || !servingTLS(c.ControlTLS, control) || !servingTLS(c.BrokerTLS, broker) || c.BrokerTLS.ClientAuth != tls.RequireAndVerifyClientCert || c.BrokerTLS.ClientCAs == nil || s == nil || s.Store == nil || s.Store.DB == nil || c.Worker == nil || c.Worker.Restore == nil || s.Store.Restore != c.Worker.Restore || c.Authentication.Origin != "https://"+control || c.Worker.Application.BrokerURL != "https://"+broker {
		return nil, r2dgit.ErrUnavailable
	}
	ac := c.Authentication
	ac.Source = s
	authentication, err := middleware.NewProtectedControlAuth(ac)
	if err != nil {
		return nil, err
	}
	if err = s.CheckSourceState(ctx); err != nil {
		authentication.Close()
		return nil, err
	}
	// Install before even startup recovery/maintenance can touch a delivery sink.
	sourceguard.Install(func(ctx context.Context) error {
		held, err := s.ReaderlessSourceBlocked(ctx)
		if err != nil {
			return err
		}
		if held {
			return sourceguard.ErrUnavailable
		}
		return nil
	})
	worker, err := service.NewProtectedWorker(ctx, s, c.Worker)
	if err != nil {
		authentication.Close()
		return nil, err
	}
	h := &Handler{Queries: db.New(s.Store.DB), GitSecurity: s}
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
			if r.Method == http.MethodGet && r.URL.Path == "/health" {
				writeJSON(w, 200, map[string]bool{"live": true})
				return
			}
			if !authentication.SameOrigin(r) || r.URL.EscapedPath() != r.URL.Path {
				writeError(w, 403, "protected_control_unavailable")
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), time.Second)
			defer cancel()
			if s.CheckSourceState(ctx) != nil {
				writeError(w, 503, "protected_control_unavailable")
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(protectedControlHTML)
	})
	r.Get("/auth/script", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		_, _ = w.Write(protectedControlJS)
	})
	r.Post("/auth/code", authentication.RequestCode)
	r.Post("/auth/session", authentication.VerifyCode)
	r.Group(func(r chi.Router) {
		r.Use(authentication.Authenticate)
		r.Get("/auth/session", func(http.ResponseWriter, *http.Request) {})
		r.Delete("/auth/session", func(http.ResponseWriter, *http.Request) {})
		h.MountGitAccountRoutes(r)
	})
	lifetime, stop := context.WithCancel(context.Background())
	newServer := func(handler http.Handler, c *tls.Config) *http.Server {
		return &http.Server{Handler: handler, TLSConfig: fixedServingTLS(c), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return lifetime }}
	}
	p := &LocalProtectedServer{auth: authentication, worker: worker, control: newServer(r, c.ControlTLS), broker: newServer(worker, c.BrokerTLS), controlListener: c.Control, brokerListener: c.Broker, stop: stop}
	success = true
	return p, nil
}

// Serve owns both TLS listeners and the protected-only scheduler until cancellation
// or first failure. No listener can fall back to a human/legacy authentication path.
func (p *LocalProtectedServer) Serve(ctx context.Context) error {
	if p == nil || p.closed.Load() || !p.started.CompareAndSwap(false, true) {
		return r2dgit.ErrUnavailable
	}
	run, stop := context.WithCancel(ctx)
	defer stop()
	results := make(chan error, 3)
	go func() { results <- p.control.ServeTLS(p.controlListener, "", "") }()
	go func() { results <- p.broker.ServeTLS(p.brokerListener, "", "") }()
	go func() { results <- p.worker.Run(run) }()
	var result error
	received := 0
	select {
	case result = <-results:
		received++
	case <-ctx.Done():
		result = ctx.Err()
	}
	stop()
	_ = p.Close()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for received < 3 {
		select {
		case <-results:
			received++
		case <-timer.C:
			return errors.Join(result, r2dgit.ErrUnavailable)
		}
	}
	if errors.Is(result, http.ErrServerClosed) {
		return r2dgit.ErrUnavailable
	}
	return result
}
func (p *LocalProtectedServer) Close() error {
	if p == nil {
		return nil
	}
	p.once.Do(func() {
		p.closed.Store(true)
		p.stop()
		p.auth.Close()
		_ = p.control.Close()
		_ = p.broker.Close()
		_ = p.controlListener.Close()
		_ = p.brokerListener.Close()
		p.closeErr = p.worker.Close()
	})
	return p.closeErr
}

// Rehandshake every connection against this explicit listener identity. A caller
// cannot supply dynamic TLS configuration or share cached broker sessions.
func fixedServingTLS(c *tls.Config) *tls.Config {
	clone := c.Clone()
	clone.SessionTicketsDisabled = true
	clone.NextProtos = []string{"http/1.1"}
	return clone
}
