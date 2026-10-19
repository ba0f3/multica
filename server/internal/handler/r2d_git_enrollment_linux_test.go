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
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/multica-ai/multica/server/internal/r2dgit"
	"golang.org/x/crypto/ssh"
)

type syntheticSigningCustody struct{ *gitFakeWorker }

func (syntheticSigningCustody) WithSigner(context.Context, string, func(ssh.Signer) error) error {
	return r2dgit.ErrUnavailable
}

func TestR2DGitCredentialCompositionAndMaintenance(t *testing.T) {
	f := newGitHTTPFixture(t)
	key := f.ready(t)
	custody := syntheticSigningCustody{f.worker}
	q := r2dgit.GitQuarantine{GitExecutable: "/usr/bin/git", Root: t.TempDir()}
	if _, err := f.h.GitSecurity.ConfigureWorkers(f.worker, custody, map[string][]netip.Prefix{f.provider: {netip.MustParsePrefix("127.0.0.0/8")}}, q); err != nil {
		t.Fatal(err)
	}
	if err := f.h.GitSecurity.Revoke(context.Background(), f.user, key.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.h.GitSecurity.MaintainCredentials(context.Background(), 8); err != nil {
		t.Fatal(err)
	}
	var pending bool
	if err := testPool.QueryRow(context.Background(), `SELECT cleanup_pending FROM r2d_git_key WHERE identity_id=$1 AND generation=$2`, key.ID, key.Generation).Scan(&pending); err != nil || pending {
		t.Fatalf("maintenance did not finish synthetic cleanup: %v", err)
	}
	if err := f.h.GitSecurity.MaintainCredentials(context.Background(), 129); err == nil {
		t.Fatal("unbounded maintenance accepted")
	}
	if _, err := f.h.GitSecurity.ConfigureWorkers(f.worker, custody, nil, q); err == nil {
		t.Fatal("missing catalog authority accepted")
	}
}

func TestR2DGitAuthenticatedEnrollmentTransport(t *testing.T) {
	for _, mode := range []string{"accepted", "revoked", "revoke-running", "wrong-worker", "wrong-policy", "forged-assignment", "replay"} {
		t.Run(mode, func(t *testing.T) {
			f := newGitWorkloadFixture(t)
			ctx := context.Background()
			clientKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{101}, 32))
			template := &x509.Certificate{SerialNumber: big.NewInt(101), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
			der, err := x509.CreateCertificate(nil, template, f.enroller.ca, clientKey.Public(), f.enroller.caKey)
			if err != nil {
				t.Fatal(err)
			}
			pin := sha256.Sum256(der)
			policy, _ := json.Marshal(f.config.Policy)
			digest := sha256.Sum256(policy)
			a := r2dgit.RuntimeAcceptance{ID: uuid.NewString(), ActorID: f.f.user, RuntimeID: f.f.runtime, PolicyDigest: hex.EncodeToString(digest[:]), WorkerCertificateSHA256: hex.EncodeToString(pin[:]), ExpiresAt: time.Now().Add(time.Hour)}
			if mode == "wrong-worker" {
				a.WorkerCertificateSHA256 = strings.Repeat("0", 64)
			}
			if mode == "wrong-policy" {
				a.PolicyDigest = strings.Repeat("0", 64)
			}
			message, _ := r2dgit.RuntimeAcceptanceBytes(a)
			a.Signature = ed25519.Sign(f.enroller.operator, message)
			pub := f.enroller.operator.Public().(ed25519.PublicKey)
			if err := f.f.h.GitSecurity.RecordRuntimeAcceptance(ctx, a, pub); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { dbfx.Exec(t, `DELETE FROM r2d_git_security_event WHERE id=$1 OR subject_id=$1`, a.ID) })
			if mode == "revoked" {
				if err := f.f.h.GitSecurity.RevokeRuntimeAcceptance(ctx, a.ID, ed25519.Sign(f.enroller.operator, r2dgit.RuntimeRevocationBytes(a.ID)), pub); err != nil {
					t.Fatal(err)
				}
			}
			issuer := r2dgit.EnrollmentIssuer{Service: f.f.h.GitSecurity, AcceptanceID: a.ID, OperatorKey: f.enroller.operator, CA: f.enroller.ca, CAKey: f.enroller.caKey, Entropy: bytes.NewReader(bytes.Repeat([]byte{102}, 8192))}
			var captured r2dgit.WorkloadEnrollmentRequest
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "forged-assignment" {
					var req r2dgit.WorkloadEnrollmentRequest
					_ = json.NewDecoder(r.Body).Decode(&req)
					req.AssignmentDigest = strings.Repeat("0", 64)
					raw, _ := json.Marshal(req)
					r.Body = io.NopCloser(bytes.NewReader(raw))
				}
				issuer.ServeHTTP(w, r)
			}))
			roots := x509.NewCertPool()
			roots.AddCert(f.enroller.ca)
			server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
			server.StartTLS()
			t.Cleanup(server.Close)
			serverRoots := x509.NewCertPool()
			serverRoots.AddCert(server.Certificate())
			client, err := r2dgit.NewHTTPWorkloadEnroller(server.URL, &tls.Config{RootCAs: serverRoots, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: clientKey}}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(client.Close)
			if err := f.app.Close(); err != nil {
				t.Fatal(err)
			}
			f.config.Enroller = enrollmentCapture{client, &captured}
			f.config.AcceptanceID = a.ID
			app, err := r2dgit.NewWorkloadApplication(f.f.h.GitSecurity, f.config)
			if err != nil {
				t.Fatal(err)
			}
			f.app = app
			*f.brokerApp = app
			t.Cleanup(func() { _ = app.Close() })
			if err := app.Recover(ctx); err != nil {
				t.Fatal(err)
			}
			run := f.admit(t, f.f.token, f.f.runRequest())
			h, err := app.Prepare(ctx, run.Context.ID)
			if mode != "accepted" && mode != "replay" && mode != "revoke-running" {
				if err == nil {
					t.Fatal("invalid operator enrollment launched")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			job := <-f.engine.started
			if mode == "revoke-running" {
				if err := f.f.h.GitSecurity.RevokeRuntimeAcceptance(ctx, a.ID, ed25519.Sign(f.enroller.operator, r2dgit.RuntimeRevocationBytes(a.ID)), pub); err != nil {
					t.Fatal(err)
				}
				if result := waitGitWorkload(t, h); result.Err == nil {
					t.Fatal("runtime acceptance revocation completed successfully")
				}
				return
			}
			if mode == "replay" {
				if _, err := client.Enroll(ctx, captured); err == nil {
					t.Fatal("ambiguous enrollment replay issued another certificate")
				}
			}
			f.engine.exit(job, 1)
			if result := waitGitWorkload(t, h); result.Err == nil {
				t.Fatal("unprepared enrollment-only workload completed")
			}
			if _, err := r2dgit.NewHTTPWorkloadEnroller(server.URL, &tls.Config{RootCAs: serverRoots, InsecureSkipVerify: true}); err == nil {
				t.Fatal("unverified enrollment TLS accepted")
			}
		})
	}
}

type enrollmentCapture struct {
	client  *r2dgit.HTTPWorkloadEnroller
	request *r2dgit.WorkloadEnrollmentRequest
}

func (e enrollmentCapture) Enroll(ctx context.Context, r r2dgit.WorkloadEnrollmentRequest) (r2dgit.WorkloadEnrollment, error) {
	*e.request = r
	return e.client.Enroll(ctx, r)
}
