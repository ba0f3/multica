package gitagent

import (
	"context"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// testSigner is a Signer backed by a real Ed25519 key.
type testSigner struct {
	publicKey string
	signer    ssh.Signer
	refused   bool
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	_, private, err := generateEd25519()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return &testSigner{
		publicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
		signer:    signer,
	}
}

func (s *testSigner) PublicKey() string { return s.publicKey }

func (s *testSigner) Sign(_ context.Context, data []byte) ([]byte, error) {
	if s.refused {
		return nil, context.Canceled
	}
	signature, err := s.signer.Sign(rand.Reader, data)
	if err != nil {
		return nil, err
	}
	return ssh.Marshal(signature), nil
}

func startAgent(t *testing.T) (string, *testSigner, *Socket) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "attempt")
	socketPath := filepath.Join(dir, "ssh-agent.sock")
	signer := newTestSigner(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	socket, err := Serve(ctx, Options{
		SocketPath: socketPath,
		PublicKey:  signer.PublicKey(),
		Signer:     signer,
	})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	return socketPath, signer, socket
}

func dialAgent(t *testing.T, socketPath string) (agent.Agent, net.Conn) {
	t.Helper()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial the agent socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return agent.NewClient(conn), conn
}

func TestAgentListsExactlyTheGrantedIdentity(t *testing.T) {
	socketPath, signer, _ := startAgent(t)
	client, _ := dialAgent(t, socketPath)

	keys, err := client.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("List returned %d keys, want 1", len(keys))
	}
	want := signer.signer.PublicKey()
	if string(keys[0].Blob) != string(want.Marshal()) {
		t.Fatalf("List returned a different key than the granted one")
	}
}

func TestAgentSignsWithTheGrantedIdentity(t *testing.T) {
	socketPath, signer, _ := startAgent(t)
	client, _ := dialAgent(t, socketPath)

	payload := []byte("the bytes git signs")
	signature, err := client.Sign(signer.signer.PublicKey(), payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.signer.PublicKey().Verify(payload, signature); err != nil {
		t.Fatalf("the signature does not verify: %v", err)
	}
}

func TestAgentRefusesAMutation(t *testing.T) {
	socketPath, signer, _ := startAgent(t)
	client, _ := dialAgent(t, socketPath)

	if err := client.Add(agent.AddedKey{PrivateKey: signer.signer}); err == nil {
		t.Fatal("Add succeeded; a task must not be able to add an identity")
	}
	if err := client.Remove(signer.signer.PublicKey()); err == nil {
		t.Fatal("Remove succeeded; a task must not be able to remove the granted identity")
	}

	// The refusal must not have changed the granted set.
	keys, err := client.List()
	if err != nil {
		t.Fatalf("List after a refused mutation: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("List returned %d keys after a refused mutation, want 1", len(keys))
	}
}

func TestAgentRefusesToSignWithAnotherKey(t *testing.T) {
	socketPath, _, _ := startAgent(t)
	client, _ := dialAgent(t, socketPath)

	other := newTestSigner(t)
	if _, err := client.Sign(other.signer.PublicKey(), []byte("data")); err == nil {
		t.Fatal("the agent signed with a key it was not granted")
	}
}

func TestAgentStopsServingAfterClose(t *testing.T) {
	socketPath, signer, socket := startAgent(t)
	client, _ := dialAgent(t, socketPath)

	if _, err := client.List(); err != nil {
		t.Fatalf("List before close: %v", err)
	}
	if err := socket.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// A connection that was open before the close must not keep signing.
	signer.refused = true
	if _, err := client.Sign(signer.signer.PublicKey(), []byte("data")); err == nil {
		t.Fatal("the agent kept serving a connection after Close")
	}

	// And a fresh connection must be refused.
	if conn, err := net.DialTimeout("unix", socketPath, time.Second); err == nil {
		conn.Close()
		t.Fatal("a new connection was accepted after Close")
	}
}

func TestAgentRefusesAnOversizedSignRequest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "attempt")
	socketPath := filepath.Join(dir, "ssh-agent.sock")
	signer := newTestSigner(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socket, err := Serve(ctx, Options{
		SocketPath:      socketPath,
		PublicKey:       signer.PublicKey(),
		Signer:          signer,
		MaxRequestBytes: 16,
	})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	t.Cleanup(func() { _ = socket.Close() })

	client, _ := dialAgent(t, socketPath)
	if _, err := client.Sign(signer.signer.PublicKey(), make([]byte, 32)); err == nil {
		t.Fatal("the agent signed a payload larger than the configured cap")
	}
}

func TestAgentRefusesAnExistingSocketPath(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "ssh-agent.sock")
	if err := os.WriteFile(socketPath, []byte("not a socket"), 0o600); err != nil {
		t.Fatalf("write the placeholder: %v", err)
	}
	signer := newTestSigner(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, err := Serve(ctx, Options{SocketPath: socketPath, PublicKey: signer.PublicKey(), Signer: signer}); err == nil {
		t.Fatal("Serve reused an existing path; it must refuse rather than adopt it")
	}
}

func TestAgentRequiresAnAbsoluteSocketPath(t *testing.T) {
	signer := newTestSigner(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, err := Serve(ctx, Options{SocketPath: "relative.sock", PublicKey: signer.PublicKey(), Signer: signer}); err == nil {
		t.Fatal("Serve accepted a relative socket path")
	}
}
