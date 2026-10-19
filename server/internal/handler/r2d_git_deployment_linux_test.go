//go:build linux

package handler

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/multica-ai/multica/server/internal/r2dgit"
	"github.com/multica-ai/multica/server/internal/service"
)

type acceptedSyntheticEnrollment struct {
	base *gitWorkloadEnrollment
	id   string
}

func (e acceptedSyntheticEnrollment) Enroll(ctx context.Context, r r2dgit.WorkloadEnrollmentRequest) (r2dgit.WorkloadEnrollment, error) {
	out, err := e.base.Enroll(ctx, r)
	if err != nil {
		return out, err
	}
	out.AcceptanceID = e.id
	message, err := r2dgit.WorkloadRegistrationBytes(r, out.Certificate.Certificate[0], e.id)
	if err != nil {
		return out, err
	}
	out.Signature = ed25519.Sign(e.base.operator, message)
	return out, nil
}

type stalledSyntheticCustody struct {
	syntheticSigningCustody
	entered chan struct{}
}

func (c stalledSyntheticCustody) DestroyAll(ctx context.Context, _ string) error {
	select {
	case c.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestR2DGitProtectedDeploymentCompositionAndShutdown(t *testing.T) {
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
	if disabled, err := service.NewProtectedWorker(ctx, f.f.h.GitSecurity, nil); err != nil || disabled != nil {
		t.Fatal("default startup did not remain disabled")
	}
	if err := f.app.Close(); err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if json.NewDecoder(r.Body).Decode(&payload) != nil || r.Header.Get("Authorization") != "Bearer synthetic-worker-A" {
			t.Error("wrong model credential")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "completed", "output": []any{map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": `{"content":"composed protected result","changes":[]}`}}}}})
	}))
	defer upstream.Close()
	model, err := r2dgit.NewResponsesGateway(upstream.URL+"/v1/responses", upstream.Client(), []r2dgit.ModelAccount{{UserID: f.f.user, Model: "synthetic-worker-model", Token: "synthetic-worker-A", ProjectIDs: []string{f.f.project}, ExpiresAt: time.Now().Add(time.Hour)}}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	var pointer atomic.Pointer[r2dgit.ProtectedDeployment]
	broker := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { pointer.Load().ServeHTTP(w, r) }))
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(f.enroller.ca)
	broker.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots, MinVersion: tls.VersionTLS13}
	broker.StartTLS()
	t.Cleanup(broker.Close)
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(broker.Certificate())
	raw, _ := json.Marshal(f.config.Policy)
	digest := sha256.Sum256(raw)
	pin := sha256.Sum256(f.enroller.ca.Raw)
	a := r2dgit.RuntimeAcceptance{ID: uuid.NewString(), ActorID: f.f.user, RuntimeID: f.f.runtime, PolicyDigest: hex.EncodeToString(digest[:]), WorkerCertificateSHA256: hex.EncodeToString(pin[:]), ExpiresAt: time.Now().Add(time.Hour)}
	message, _ := r2dgit.RuntimeAcceptanceBytes(a)
	a.Signature = ed25519.Sign(f.enroller.operator, message)
	if err := f.f.h.GitSecurity.RecordRuntimeAcceptance(ctx, a, f.enroller.operator.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dbfx.Exec(t, `DELETE FROM r2d_git_security_event WHERE id=$1 OR subject_id=$1`, a.ID) })
	appConfig := f.config
	appConfig.Model = model
	appConfig.AcceptanceID = a.ID
	appConfig.Enroller = acceptedSyntheticEnrollment{f.enroller, a.ID}
	appConfig.BrokerURL = broker.URL
	appConfig.BrokerRoots = serverRoots
	entered := make(chan struct{}, 1)
	config := r2dgit.ProtectedDeploymentConfig{Restore: guard, Application: appConfig, Generator: f.f.worker, Custody: stalledSyntheticCustody{syntheticSigningCustody{f.f.worker}, entered}, Addresses: map[string][]netip.Prefix{f.f.provider: {netip.MustParsePrefix("127.0.0.0/8")}}, Quarantine: r2dgit.GitQuarantine{GitExecutable: "/usr/bin/git", Root: t.TempDir()}}
	config.RetryFailures = true
	worker, err := service.NewProtectedWorker(ctx, f.f.h.GitSecurity, &config)
	if err != nil {
		t.Fatal(err)
	}
	pointer.Store(worker)
	t.Cleanup(func() { _ = worker.Close() })
	f.engine.mu.Lock()
	f.engine.entrypoint = entrypoint
	f.engine.providerBinary = provider
	f.engine.helperRoot = t.TempDir()
	f.engine.entrypointTimeout = 15
	f.engine.mu.Unlock()
	run := f.admit(t, f.f.token, f.f.runRequest())
	if err := worker.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
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
			t.Fatal("composed workload failed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if output == "" {
		t.Fatal("scheduler did not complete compiled provider workflow")
	}
	if got := f.f.call(t, f.f.token, "GET", "/api/me/git-outputs/"+output, nil, 200).Body.String(); got != "composed protected result" {
		t.Fatal("wrong composed result")
	}
	f.f.call(t, f.f.otherToken, "GET", "/api/me/git-outputs/"+output, nil, 404)
	failed := f.admit(t, f.f.token, f.f.runRequest())
	if err := f.f.h.GitSecurity.MutateAuthority(ctx, func(db r2dgit.Database) error {
		_, err := db.Exec(ctx, `UPDATE agent_task_queue SET status='failed',completed_at=now(),max_attempts=3 WHERE id=$1`, failed.Context.Binding.TaskID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := worker.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	var retryID, retryTask string
	if err := testPool.QueryRow(ctx, `SELECT id::text,task_id::text FROM r2d_git_run_context WHERE parent_id=$1 AND derivation='retry'`, failed.Context.ID).Scan(&retryID, &retryTask); err != nil {
		t.Fatal(err)
	}
	if retryTask == failed.Context.Binding.TaskID {
		t.Fatal("scheduler reused failed attempt")
	}
	deadline = time.Now().Add(10 * time.Second)
	completed := false
	for time.Now().Before(deadline) {
		var status string
		if err := testPool.QueryRow(ctx, `SELECT status FROM agent_task_queue WHERE id=$1`, retryTask).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status == "completed" {
			completed = true
			break
		}
		if status == "failed" {
			t.Fatal("scheduled fresh retry failed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !completed {
		t.Fatal("scheduler did not execute fresh retry")
	}
	if _, err := f.f.h.GitSecurity.Current(ctx, failed.Context, failed.Grant); err == nil {
		t.Fatal("scheduler revived predecessor authority")
	}
	revokeCtx, revokeStop := context.WithTimeout(ctx, 500*time.Millisecond)
	if err := f.f.h.GitSecurity.Revoke(revokeCtx, f.f.user, run.Grant.IdentityID); err != nil {
		revokeStop()
		t.Fatal(err)
	}
	revokeStop()
	select {
	case <-entered:
	default:
	}
	done := make(chan error, 1)
	go func() { done <- worker.Tick(ctx) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("maintenance did not block")
	}
	start := time.Now()
	if err := worker.Close(); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("Close waited on stalled tick instead of cancelling")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stalled tick succeeded after close")
		}
	case <-time.After(time.Second):
		t.Fatal("stalled tick survived lifetime cancellation")
	}
	if worker.Tick(ctx) == nil {
		t.Fatal("closed worker dispatched")
	}
}
