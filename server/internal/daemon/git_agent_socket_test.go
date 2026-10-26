package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// generateEd25519Key mints the key the fake server signs with.
func generateEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// fakeGitSigningServer is a server that issues a lease for one key and signs
// with it. It is enough to exercise the daemon's socket end to end.
func fakeGitSigningServer(t *testing.T, signer ssh.Signer) *httptest.Server {
	t.Helper()
	publicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/git-signing-lease"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"lease_id":    "lease-1",
				"public_key":  publicKey,
				"fingerprint": ssh.FingerprintSHA256(signer.PublicKey()),
				"expires_at":  time.Now().Add(time.Minute).UTC(),
			})
		case r.URL.Path == "/api/daemon/git-signatures":
			var body struct {
				LeaseID string `json:"lease_id"`
				Data    string `json:"data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode the signature request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			payload, err := base64.StdEncoding.DecodeString(body.Data)
			if err != nil {
				t.Errorf("decode the payload: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			signature, err := signer.Sign(rand.Reader, payload)
			if err != nil {
				t.Errorf("sign: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"signature": base64.StdEncoding.EncodeToString(ssh.Marshal(signature)),
			})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestGitSigningUsesClaimDaemonTokenWithoutChangingOwnerClient(t *testing.T) {
	_, private, err := generateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	signingServer := fakeGitSigningServer(t, signer)
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer mdt_task_fixture" {
			http.Error(w, "daemon token required", http.StatusForbidden)
			return
		}
		signingServer.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	profile := gitAgentTestProfile(t)
	d := newGitAgentTestDaemon(t, server.URL, profile)
	d.client.SetToken("mul_owner_fixture")
	task := gitAgentTestTask()
	task.GitSigningDaemonToken = "mdt_task_fixture"
	socket, stop := d.startGitAgentSocket(t.Context(), task, profile, "task-credential")
	t.Cleanup(stop)
	if socket == "" {
		t.Fatal("task Git signing lease was not opened with its daemon credential")
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := agent.NewClient(conn)
	data := []byte("task ssh authentication")
	sig, err := client.Sign(signer.PublicKey(), data)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.PublicKey().Verify(data, sig); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || d.client.Token() != "mul_owner_fixture" {
		t.Fatalf("lease/sign requests=%d or owner client was changed", len(paths))
	}
}

func gitAgentTestTask() Task {
	return Task{
		ID:                    "task-1",
		GitSigningDaemonToken: "mdt_fixture",
		Repos:                 []RepoData{{URL: "git@github.com:acme/api.git"}},
		GitIdentities: []GitIdentityBinding{
			{ProviderID: "provider-1", Host: "github.com", IdentityID: "identity-1", Generation: 1},
		},
	}
}

func newGitAgentTestDaemon(t *testing.T, baseURL, profile string) *Daemon {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	daemon := &Daemon{
		client: NewClient(baseURL),
		logger: logger,
	}
	daemon.cfg.Profile = profile
	return daemon
}

func gitAgentTestProfile(t *testing.T) string {
	t.Helper()
	// Test names in t.TempDir paths can exceed the Unix socket path limit.
	profile, err := os.MkdirTemp("", "git-agent-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(profile) })
	return profile
}

func TestStartGitAgentSocketServesSignatures(t *testing.T) {
	_, private, err := generateEd25519Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	server := fakeGitSigningServer(t, signer)
	profile := gitAgentTestProfile(t)
	daemon := newGitAgentTestDaemon(t, server.URL, profile)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socketPath, stop := daemon.startGitAgentSocket(ctx, gitAgentTestTask(), profile, "attempt-1")
	if socketPath == "" {
		t.Fatal("the daemon did not start a signing socket")
	}
	if !strings.HasPrefix(socketPath, filepath.Join(profile, "git-agent")+string(os.PathSeparator)) {
		t.Fatalf("socket path %q is not under the per-attempt directory", socketPath)
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial the socket: %v", err)
	}
	defer conn.Close()
	client := agent.NewClient(conn)

	keys, err := client.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("List returned %d keys, want 1", len(keys))
	}

	payload := []byte("the bytes a git operation signs")
	signature, err := client.Sign(signer.PublicKey(), payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signer.PublicKey().Verify(payload, signature); err != nil {
		t.Fatalf("the signature does not verify against the server's key: %v", err)
	}

	stop()
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("the socket still exists after the run ended: %v", err)
	}
}

func TestStartGitAgentSocketIsPerAttempt(t *testing.T) {
	_, private, err := generateEd25519Key()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	server := fakeGitSigningServer(t, signer)
	profile := gitAgentTestProfile(t)
	daemon := newGitAgentTestDaemon(t, server.URL, profile)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	firstTask := gitAgentTestTask()
	firstTask.ID = "task-a"
	secondTask := gitAgentTestTask()
	secondTask.ID = "task-b"

	firstPath, stopFirst := daemon.startGitAgentSocket(ctx, firstTask, profile, "attempt-a1")
	defer stopFirst()
	secondPath, stopSecond := daemon.startGitAgentSocket(ctx, secondTask, profile, "attempt-b1")
	defer stopSecond()

	if firstPath == "" || secondPath == "" {
		t.Fatalf("one of the attempts has no socket: %q / %q", firstPath, secondPath)
	}
	if firstPath == secondPath {
		t.Fatalf("two attempts share the socket %q", firstPath)
	}
}

func TestStartGitAgentSocketWithoutACredentialLeavesTheEnvironmentAlone(t *testing.T) {
	profile := t.TempDir()
	daemon := newGitAgentTestDaemon(t, "http://127.0.0.1:1", profile)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	task := Task{ID: "task-1", Repos: []RepoData{{URL: "git@github.com:acme/api.git"}}}
	if socketPath, stop := daemon.startGitAgentSocket(ctx, task, profile, "attempt-1"); socketPath != "" {
		t.Fatalf("a run with no credential got the socket %q", socketPath)
	} else {
		stop()
	}

	// And the host's agent must never be handed to a run.
	t.Setenv("SSH_AUTH_SOCK", "/tmp/host-ssh-agent.sock")
	env := taskMulticaEnvironment(task, "claude", "agent", "token", "/config", "/workspaces", "http://localhost", 8080, 0, t.TempDir())
	if _, inherited := env["SSH_AUTH_SOCK"]; inherited {
		t.Fatal("the host SSH_AUTH_SOCK leaked into the agent environment")
	}
}
