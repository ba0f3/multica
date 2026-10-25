package daemon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/daemon/repocache"
)

// newTestCertPEM returns a self-signed CA certificate as PEM with the given
// common name, generated in the test so the operator's real certificate never
// enters the tree.
func newTestCertPEM(t *testing.T, commonName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// seedMachineTrust points the ambient git config's http.sslCAInfo at a fresh
// PEM file so machineCATrust resolves deterministically, without depending on
// the developer's own git config or the system bundle. It returns the machine
// certificate PEM it wrote.
func seedMachineTrust(t *testing.T) string {
	t.Helper()
	certPEM := newTestCertPEM(t, "machine-ca")
	global := filepath.Join(t.TempDir(), "gitconfig")
	bundle := filepath.Join(t.TempDir(), "machine.pem")
	if err := os.WriteFile(bundle, []byte(certPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "config", "--file", global, "http.sslCAInfo", bundle).CombinedOutput(); err != nil {
		t.Skipf("git config unavailable: %s: %v", out, err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", global)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	return certPEM
}

func newWorkerCATestDaemon(t *testing.T, cache *repocache.Cache) *Daemon {
	t.Helper()
	return &Daemon{repoCache: cache, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// pemCertificateSubjects parses the CERTIFICATE blocks of data and returns their
// common names in order.
func pemCertificateSubjects(t *testing.T, data []byte) []string {
	t.Helper()
	var subjects []string
	rest := data
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse certificate: %v", err)
		}
		subjects = append(subjects, cert.Subject.CommonName)
	}
	return subjects
}

func TestWriteWorkerCABundleAppendsExtraCert(t *testing.T) {
	seedMachineTrust(t)
	cache := repocache.New(t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { _ = cache.SetExtraCACerts("") })

	serverPEM := newTestCertPEM(t, "server-ca")
	if err := cache.SetExtraCACerts(serverPEM); err != nil {
		t.Fatalf("SetExtraCACerts: %v", err)
	}

	extraDir := t.TempDir()
	extraPEM := newTestCertPEM(t, "extra-ca")
	extraPath := filepath.Join(extraDir, "extra.pem")
	if err := os.WriteFile(extraPath, []byte(extraPEM), 0o644); err != nil {
		t.Fatal(err)
	}

	envRoot := t.TempDir()
	d := newWorkerCATestDaemon(t, cache)
	got, err := d.writeWorkerCABundle(envRoot, extraPath)
	if err != nil {
		t.Fatalf("writeWorkerCABundle: %v", err)
	}
	if got != filepath.Join(envRoot, "ca-bundle.pem") {
		t.Fatalf("bundle path = %q, want %q", got, filepath.Join(envRoot, "ca-bundle.pem"))
	}

	data, err := os.ReadFile(got)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	subjects := pemCertificateSubjects(t, data)
	joined := strings.Join(subjects, ",")
	for _, want := range []string{"machine-ca", "server-ca", "extra-ca"} {
		if !strings.Contains(joined, want) {
			t.Errorf("bundle subjects %q missing %q", joined, want)
		}
	}
}

func TestWriteWorkerCABundleFailsOnInvalidExtra(t *testing.T) {
	nonCertKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(nonCertKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))

	cases := map[string]struct {
		content string
		missing bool
	}{
		"missing file":        {missing: true},
		"non-pem content":     {content: "this is not a PEM file"},
		"non-certificate pem": {content: keyPEM},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			// Seed machine trust so the cache side of the bundle is non-empty;
			// the invalid extra path must still fail the whole write.
			seedMachineTrust(t)
			cache := repocache.New(t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))

			extraPath := filepath.Join(t.TempDir(), "extra.pem")
			if !tc.missing {
				if err := os.WriteFile(extraPath, []byte(tc.content), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			envRoot := t.TempDir()
			d := newWorkerCATestDaemon(t, cache)
			if _, err := d.writeWorkerCABundle(envRoot, extraPath); err == nil {
				t.Fatal("expected an error for an invalid extra CA path")
			} else if !strings.Contains(err.Error(), extraPath) {
				t.Fatalf("error should name the path %q: %v", extraPath, err)
			}
			if _, err := os.Stat(filepath.Join(envRoot, "ca-bundle.pem")); !os.IsNotExist(err) {
				t.Fatalf("no bundle file should be left behind (err=%v)", err)
			}
		})
	}
}

func TestWriteWorkerCABundleServerCAOnly(t *testing.T) {
	seedMachineTrust(t)
	cache := repocache.New(t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { _ = cache.SetExtraCACerts("") })

	serverPEM := newTestCertPEM(t, "server-ca")
	if err := cache.SetExtraCACerts(serverPEM); err != nil {
		t.Fatalf("SetExtraCACerts: %v", err)
	}

	envRoot := t.TempDir()
	d := newWorkerCATestDaemon(t, cache)
	got, err := d.writeWorkerCABundle(envRoot, "")
	if err != nil {
		t.Fatalf("writeWorkerCABundle: %v", err)
	}
	if got != filepath.Join(envRoot, "ca-bundle.pem") {
		t.Fatalf("bundle path = %q, want %q", got, filepath.Join(envRoot, "ca-bundle.pem"))
	}
	data, err := os.ReadFile(got)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	subjects := pemCertificateSubjects(t, data)
	joined := strings.Join(subjects, ",")
	for _, want := range []string{"machine-ca", "server-ca"} {
		if !strings.Contains(joined, want) {
			t.Errorf("bundle subjects %q missing %q", joined, want)
		}
	}
}

func TestWriteWorkerCABundleNoExtraAndNoServerCA(t *testing.T) {
	seedMachineTrust(t)
	cache := repocache.New(t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	envRoot := t.TempDir()
	d := newWorkerCATestDaemon(t, cache)
	got, err := d.writeWorkerCABundle(envRoot, "")
	if err != nil {
		t.Fatalf("writeWorkerCABundle: %v", err)
	}
	if got != "" {
		t.Fatalf("bundle path = %q, want empty", got)
	}
	if _, err := os.Stat(filepath.Join(envRoot, "ca-bundle.pem")); !os.IsNotExist(err) {
		t.Fatalf("no bundle file should be left behind (err=%v)", err)
	}
}
