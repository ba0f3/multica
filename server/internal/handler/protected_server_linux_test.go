//go:build linux

package handler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/multica-ai/multica/server/internal/middleware"
	"github.com/multica-ai/multica/server/internal/r2dgit"
	"github.com/multica-ai/multica/server/internal/sourceguard"
)

func controlListen(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}
func controlTLSFixture(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	temporary := httptest.NewTLSServer(http.NotFoundHandler())
	roots := x509.NewCertPool()
	roots.AddCert(temporary.Certificate())
	config := &tls.Config{Certificates: temporary.TLS.Certificates, MinVersion: tls.VersionTLS13}
	temporary.Close()
	return config, roots
}

func TestR2DGitLocalProtectedServerRejectsUnsafeConstruction(t *testing.T) {
	if p, err := NewLocalProtectedServer(context.Background(), nil, nil); err != nil || p != nil {
		t.Fatal("default enabled protected serving")
	}
	for _, mode := range []string{"missing_tls", "missing_client_auth", "mismatched_origin", "missing_worker"} {
		t.Run(mode, func(t *testing.T) {
			control, broker := controlListen(t), controlListen(t)
			conf, _ := controlTLSFixture(t)
			brokerTLS := conf.Clone()
			brokerTLS.ClientAuth = tls.RequireAndVerifyClientCert
			brokerTLS.ClientCAs = x509.NewCertPool()
			c := &LocalProtectedServerConfig{Control: control, Broker: broker, ControlTLS: conf, BrokerTLS: brokerTLS, Authentication: middleware.ProtectedControlAuthConfig{Origin: "https://" + control.Addr().String()}}
			if mode == "missing_tls" {
				c.ControlTLS = nil
			}
			if mode == "missing_client_auth" {
				c.BrokerTLS.ClientAuth = tls.NoClientCert
			}
			if mode == "mismatched_origin" {
				c.Authentication.Origin = "https://foreign.invalid"
			}
			p, err := NewLocalProtectedServer(context.Background(), nil, c)
			if p != nil || err == nil {
				t.Fatal("invalid construction accepted")
			}
			for _, listener := range []net.Listener{control, broker} {
				_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(time.Millisecond))
				if conn, err := listener.Accept(); err == nil {
					conn.Close()
					t.Fatal("failed construction retained a listener")
				} else if !errors.Is(err, net.ErrClosed) {
					t.Fatal("listener was not closed", err)
				}
			}
		})
	}
}

func TestR2DGitLocalProtectedServingFreshLoginToCompiledOutput(t *testing.T) {
	entrypoint := buildProtectedEntrypoint(t)
	provider := filepath.Join(t.TempDir(), "provider")
	goExecutable, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	build := exec.Command(goExecutable, "build", "-o", provider, "./cmd/protected-provider")
	build.Dir = "../.."
	build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("provider build: %v %s", err, out)
	}
	f := newGitWorkloadFixture(t)
	ctx := context.Background()
	guard := gitRestoreFixture(t, f.f)
	if err := f.app.Close(); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-local-control-A" {
			t.Error("wrong model identity")
		}
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid model body")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "completed", "output": []any{map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": `{"content":"fresh local protected result","changes":[]}`}}}}})
	}))
	defer upstream.Close()
	model, err := r2dgit.NewResponsesGateway(upstream.URL+"/v1/responses", upstream.Client(), []r2dgit.ModelAccount{{UserID: f.f.user, Model: "synthetic-local-control", Token: "synthetic-local-control-A", ProjectIDs: []string{f.f.project}, ExpiresAt: time.Now().Add(time.Hour)}}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	control, broker := controlListen(t), controlListen(t)
	tlsConfig, roots := controlTLSFixture(t)
	brokerTLS := tlsConfig.Clone()
	brokerTLS.ClientAuth = tls.RequireAndVerifyClientCert
	brokerTLS.ClientCAs = x509.NewCertPool()
	brokerTLS.ClientCAs.AddCert(f.enroller.ca)
	origin := "https://" + control.Addr().String()
	raw, _ := json.Marshal(f.config.Policy)
	digest := sha256.Sum256(raw)
	pin := sha256.Sum256(f.enroller.ca.Raw)
	acceptance := r2dgit.RuntimeAcceptance{ID: uuid.NewString(), ActorID: f.f.user, RuntimeID: f.f.runtime, PolicyDigest: hex.EncodeToString(digest[:]), WorkerCertificateSHA256: hex.EncodeToString(pin[:]), ExpiresAt: time.Now().Add(time.Hour)}
	message, _ := r2dgit.RuntimeAcceptanceBytes(acceptance)
	acceptance.Signature = ed25519.Sign(f.enroller.operator, message)
	if err := f.f.h.GitSecurity.RecordRuntimeAcceptance(ctx, acceptance, f.enroller.operator.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dbfx.Exec(t, `DELETE FROM r2d_git_security_event WHERE id=$1 OR subject_id=$1`, acceptance.ID) })
	config := f.config
	config.Model = model
	config.AcceptanceID = acceptance.ID
	config.Enroller = acceptedSyntheticEnrollment{f.enroller, acceptance.ID}
	config.BrokerURL = "https://" + broker.Addr().String()
	config.BrokerRoots = roots
	mail := &controlMailFixture{codes: map[string]string{}}
	worker := &r2dgit.ProtectedDeploymentConfig{Restore: guard, Application: config, Generator: f.f.worker, Custody: syntheticSigningCustody{f.f.worker}, Addresses: map[string][]netip.Prefix{f.f.provider: {netip.MustParsePrefix("127.0.0.0/8")}}, Quarantine: r2dgit.GitQuarantine{GitExecutable: "/usr/bin/git", Root: t.TempDir()}}
	// Everything except the selected TLS defect is fully valid. A regression
	// would therefore construct the worker rather than merely fail on nil config.
	originalCustody := f.f.h.GitSecurity.Custody
	for _, mode := range []string{"dynamic_config", "dynamic_certificate", "mismatched_key", "malformed_certificate", "missing_client_auth"} {
		badControl, badBroker := controlListen(t), controlListen(t)
		humanTLS, mutualTLS := tlsConfig.Clone(), brokerTLS.Clone()
		switch mode {
		case "dynamic_config":
			mutualTLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return &tls.Config{}, nil }
		case "dynamic_certificate":
			humanTLS.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }
		case "mismatched_key":
			humanTLS.Certificates = append([]tls.Certificate(nil), humanTLS.Certificates...)
			humanTLS.Certificates[0].PrivateKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{99}, 32))
		case "malformed_certificate":
			humanTLS.Certificates = []tls.Certificate{{Certificate: [][]byte{[]byte("invalid")}, PrivateKey: tlsConfig.Certificates[0].PrivateKey}}
		case "missing_client_auth":
			mutualTLS.ClientAuth = tls.NoClientCert
		}
		badWorker := *worker
		badWorker.Application = config
		badWorker.Application.BrokerURL = "https://" + badBroker.Addr().String()
		bad, err := NewLocalProtectedServer(ctx, f.f.h.GitSecurity, &LocalProtectedServerConfig{Control: badControl, Broker: badBroker, ControlTLS: humanTLS, BrokerTLS: mutualTLS, Authentication: middleware.ProtectedControlAuthConfig{Origin: "https://" + badControl.Addr().String(), Delivery: mail}, Worker: &badWorker})
		if err == nil || bad != nil {
			if bad != nil {
				_ = bad.Close()
			}
			t.Fatal("unsafe TLS constructed worker", mode)
		}
		if f.f.h.GitSecurity.Custody != originalCustody {
			t.Fatal("invalid TLS touched credential composition", mode)
		}
	}
	p, err := NewLocalProtectedServer(ctx, f.f.h.GitSecurity, &LocalProtectedServerConfig{Control: control, Broker: broker, ControlTLS: tlsConfig, BrokerTLS: brokerTLS, Authentication: middleware.ProtectedControlAuthConfig{Origin: origin, Delivery: mail}, Worker: worker})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close(); sourceguard.Install(nil) })
	f.engine.mu.Lock()
	f.engine.entrypoint = entrypoint
	f.engine.providerBinary = provider
	f.engine.helperRoot = t.TempDir()
	f.engine.entrypointTimeout = 15
	f.engine.mu.Unlock()
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- p.Serve(runCtx) }()
	t.Cleanup(func() { stop(); _ = p.Close() })
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}, Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	request := func(client *http.Client, method, path string, body any, csrf, workspace string, want int) []byte {
		t.Helper()
		var encoded []byte
		if body != nil {
			encoded, _ = json.Marshal(body)
		}
		req, err := http.NewRequest(method, origin+path, bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", origin)
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		if workspace != "" {
			req.Header.Set("X-Workspace-ID", workspace)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("control request", err)
		}
		defer res.Body.Close()
		raw, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != want {
			t.Fatalf("%s %s: %d %s", method, path, res.StatusCode, raw)
		}
		for _, cookie := range res.Cookies() {
			if cookie.Name == "multica_auth" || strings.HasPrefix(cookie.Name, "CloudFront-") {
				t.Fatal("legacy source authority issued")
			}
		}
		return raw
	}
	login := func(client *http.Client, user string) string {
		t.Helper()
		var email string
		if err := testPool.QueryRow(ctx, `SELECT email FROM "user" WHERE id=$1`, user).Scan(&email); err != nil {
			t.Fatal(err)
		}
		raw := request(client, "POST", "/auth/code", map[string]string{"email": email}, "", "", 202)
		var receipt struct {
			ID string `json:"challenge_id"`
		}
		if json.Unmarshal(raw, &receipt) != nil {
			t.Fatal("challenge receipt")
		}
		raw = request(client, "POST", "/auth/session", map[string]string{"challenge_id": receipt.ID, "code": mail.code(email)}, "", "", 200)
		var session struct {
			User string `json:"user_id"`
			CSRF string `json:"csrf_token"`
		}
		if json.Unmarshal(raw, &session) != nil || session.User != user || session.CSRF == "" {
			t.Fatal("fresh login identity", string(raw))
		}
		return session.CSRF
	}
	request(client, "GET", "/auth/session", nil, "", "", 401)
	html := request(client, "GET", "/", nil, "", "", 200)
	if !bytes.Contains(html, []byte("Multica protected controls")) {
		t.Fatal("missing fixed control page")
	}
	script := request(client, "GET", "/auth/script", nil, "", "", 200)
	if bytes.Contains(script, []byte("localStorage")) || bytes.Contains(script, []byte("innerHTML")) {
		t.Fatal("source/token unsafe browser storage")
	}
	csrf := login(client, f.f.user)
	request(client, "GET", "/api/me/git-identities", nil, "", "", 200)
	for _, path := range []string{"/api/me", "/api/search-index/snapshot", "/api/issues/search", "/uploads/legacy/source.txt", "/api/auth/cli-token", "/api/attachments/legacy/signed-download"} {
		request(client, "GET", path, nil, "", "", 404)
	}
	request(client, "POST", "/auth/verify-code", map[string]string{"email": "fixture@invalid", "code": "123456"}, "", "", 404)
	request(client, "POST", "/api/me/git-runs", f.f.runRequest(), "", f.f.workspace, 403)
	f.classifyAssignment(t, f.f.runRequest())
	raw = request(client, "POST", "/api/me/git-runs", f.f.runRequest(), csrf, f.f.workspace, 201)
	var run r2dgit.RunInfo
	if json.Unmarshal(raw, &run) != nil || run.Context.Binding.OriginatorUserID != f.f.user || run.ExecutionAvailable {
		t.Fatal("wrong admission identity/default enablement", string(raw))
	}
	deadline := time.Now().Add(20 * time.Second)
	var output string
	for time.Now().Before(deadline) {
		var status string
		if err := testPool.QueryRow(ctx, `SELECT status FROM agent_task_queue WHERE id=$1`, run.Context.Binding.TaskID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status == "completed" {
			if err := testPool.QueryRow(ctx, `SELECT id::text FROM r2d_git_output WHERE context_id=$1`, run.Context.ID).Scan(&output); err != nil {
				t.Fatal(err)
			}
			break
		}
		if status == "failed" {
			t.Fatal("composed local workload failed")
		}
		select {
		case err := <-done:
			t.Fatal("serving stopped early", err)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	if output == "" {
		t.Fatal("compiled workflow did not complete")
	}
	if raw := request(client, "GET", "/api/me/git-outputs/"+output, nil, "", "", 200); string(raw) != "fresh local protected result" {
		t.Fatal("wrong protected output", string(raw))
	}
	jarB, _ := cookiejar.New(nil)
	clientB := &http.Client{Jar: jarB, Transport: client.Transport, Timeout: 10 * time.Second}
	_ = login(clientB, f.f.other)
	request(clientB, "GET", "/api/me/git-outputs/"+output, nil, "", "", 404)
	// Human cookies do not authenticate the mTLS-only broker listener.
	req, _ := http.NewRequest("GET", config.BrokerURL+"/", nil)
	if response, err := client.Do(req); err == nil {
		response.Body.Close()
		t.Fatal("human client reached broker without a workload certificate")
	}
	request(client, "DELETE", "/auth/session", nil, csrf, "", 200)
	request(client, "GET", "/api/me/git-outputs/"+output, nil, "", "", 401)
	stop()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("shutdown", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("protected serving did not stop")
	}
	if err := p.Serve(context.Background()); err == nil {
		t.Fatal("closed server restarted")
	}
	if sourceguard.Check(ctx) == nil {
		t.Fatal("close removed historical source hold")
	}
}
