// Package gitagent serves a per-attempt SSH agent socket.
//
// The socket is a capability: whoever can open it can ask the daemon to sign
// with the key the task was granted. It is therefore created inside a
// per-attempt directory with no group or world access, and it exposes only
// two operations — list the granted identity and sign with it. Adding,
// removing or locking identities is refused.
package gitagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// DefaultMaxRequestBytes bounds one sign request. A Git signature covers a
// small request, and the cap keeps the socket from being used to ask the
// server to sign large arbitrary payloads.
const DefaultMaxRequestBytes = 64 << 10

// Signer produces a signature with the key a task was granted.
//
// It returns the wire form the SSH agent protocol carries, so a caller can
// forward a request to a remote signer without parsing it locally.
type Signer interface {
	PublicKey() string
	Sign(ctx context.Context, data []byte) ([]byte, error)
}

// Options configures one attempt's agent socket.
type Options struct {
	// SocketPath is the absolute path to listen on.
	SocketPath string
	// PublicKey is the authorized-key line of the granted identity.
	PublicKey string
	// Signer produces signatures for that identity.
	Signer Signer
	// MaxRequestBytes bounds one sign request. Zero uses the default.
	MaxRequestBytes int
	// OnClose runs after the socket is closed and removed. Optional.
	OnClose func()
}

// Socket is a running agent socket.
type Socket struct {
	listener net.Listener
	path     string
	onClose  func()

	mu     sync.Mutex
	closed bool
	conns  map[net.Conn]struct{}
}

// Serve starts an agent socket.
//
// It refuses to adopt an existing path: the caller owns the per-attempt
// directory, and a path that is already there means the attempt has not
// cleaned up, which must not silently hand a stale capability to a new run.
func Serve(ctx context.Context, opts Options) (*Socket, error) {
	if !filepath.IsAbs(opts.SocketPath) {
		return nil, errors.New("gitagent: the socket path must be absolute")
	}
	if opts.Signer == nil {
		return nil, errors.New("gitagent: a signer is required")
	}
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(opts.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("gitagent: parse the granted public key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(opts.SocketPath), 0o700); err != nil {
		return nil, fmt.Errorf("gitagent: create the attempt directory: %w", err)
	}
	if _, err := os.Lstat(opts.SocketPath); err == nil {
		return nil, fmt.Errorf("gitagent: %s already exists", opts.SocketPath)
	}

	listener, err := net.Listen("unix", opts.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("gitagent: listen: %w", err)
	}
	// The directory is the capability's real guard, but the socket itself is
	// narrowed too so a broader directory mode cannot widen access.
	if err := os.Chmod(opts.SocketPath, 0o600); err != nil {
		listener.Close()
		_ = os.Remove(opts.SocketPath)
		return nil, fmt.Errorf("gitagent: restrict the socket: %w", err)
	}

	socket := &Socket{
		listener: listener,
		path:     opts.SocketPath,
		onClose:  opts.OnClose,
		conns:    map[net.Conn]struct{}{},
	}
	restricted := &restrictedAgent{
		publicKey:       publicKey,
		signer:          opts.Signer,
		maxRequestBytes: opts.MaxRequestBytes,
	}

	go socket.accept(restricted)

	if ctx != nil {
		go func() {
			<-ctx.Done()
			_ = socket.Close()
		}()
	}
	return socket, nil
}

func (s *Socket) accept(restricted *restrictedAgent) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			return
		}
		s.conns[conn] = struct{}{}
		s.mu.Unlock()

		go func() {
			defer func() {
				conn.Close()
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
			}()
			// ServeAgent returns when the client disconnects or the
			// connection is closed below.
			_ = agent.ServeAgent(restricted, conn)
		}()
	}
}

// Path returns the socket path.
func (s *Socket) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Close stops serving, drops every live connection and removes the socket
// file.
//
// Dropping the live connections matters: a runner that opened the socket
// before the task ended must not keep signing after it.
func (s *Socket) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()

	err := s.listener.Close()
	for _, conn := range conns {
		_ = conn.Close()
	}
	_ = os.Remove(s.path)
	if s.onClose != nil {
		s.onClose()
	}
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// restrictedAgent implements agent.Agent for exactly one identity.
type restrictedAgent struct {
	publicKey       ssh.PublicKey
	signer          Signer
	maxRequestBytes int
}

// List returns the granted identity and nothing else.
func (a *restrictedAgent) List() ([]*agent.Key, error) {
	return []*agent.Key{{
		Format:  a.publicKey.Type(),
		Blob:    a.publicKey.Marshal(),
		Comment: "multica task credential",
	}}, nil
}

// Sign signs only with the granted identity.
//
// Any other key is refused, so a runner cannot ask the daemon to sign with a
// credential that belongs to another task or another user.
func (a *restrictedAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	if key == nil || !bytes.Equal(key.Marshal(), a.publicKey.Marshal()) {
		return nil, errors.New("gitagent: key not available")
	}
	limit := a.maxRequestBytes
	if limit <= 0 {
		limit = DefaultMaxRequestBytes
	}
	if len(data) > limit {
		return nil, errors.New("gitagent: sign request too large")
	}
	raw, err := a.signer.Sign(context.Background(), data)
	if err != nil {
		return nil, err
	}
	var signature ssh.Signature
	if err := ssh.Unmarshal(raw, &signature); err != nil {
		return nil, err
	}
	if signature.Format != a.publicKey.Type() {
		return nil, errors.New("gitagent: the signer returned a foreign signature format")
	}
	return &signature, nil
}

// Add is refused: a task must not be able to import an identity.
func (a *restrictedAgent) Add(agent.AddedKey) error {
	return errors.New("gitagent: adding an identity is not permitted")
}

// Remove is refused: a task must not be able to withdraw the granted identity.
func (a *restrictedAgent) Remove(ssh.PublicKey) error {
	return errors.New("gitagent: removing an identity is not permitted")
}

// RemoveAll is refused: a task must not be able to empty the agent.
func (a *restrictedAgent) RemoveAll() error {
	return errors.New("gitagent: removing identities is not permitted")
}

// Lock is refused: the identity is managed by the daemon, not the runner.
func (a *restrictedAgent) Lock([]byte) error {
	return errors.New("gitagent: locking the agent is not permitted")
}

// Unlock is refused: the identity is managed by the daemon, not the runner.
func (a *restrictedAgent) Unlock([]byte) error {
	return errors.New("gitagent: unlocking the agent is not permitted")
}

// Signers reports no signer. The agent protocol asks for identities through
// List, and a signer here would hand a plaintext-capable object to code that
// only needs a signature.
func (a *restrictedAgent) Signers() ([]ssh.Signer, error) {
	return nil, nil
}

// generateEd25519 mints the key a test signer wraps.
func generateEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
