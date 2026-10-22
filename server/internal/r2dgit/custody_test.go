package r2dgit

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/ssh"
)

func rsaPrivateKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatalf("marshal rsa key: %v", err)
	}
	return pem.EncodeToMemory(block)
}

func newTestCustody(t *testing.T, handler http.HandlerFunc) EncryptedCustody {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	custody, err := NewBaoCustody(server.URL, "multica-git", "test-token", server.Client())
	if err != nil {
		t.Fatalf("NewBaoCustody: %v", err)
	}
	return custody
}

func TestNewBaoCustodyRejectsUntrustedConfiguration(t *testing.T) {
	client := httptest.NewTLSServer(http.NotFoundHandler())
	defer client.Close()

	cases := map[string]struct {
		baseURL string
		mount   string
		token   string
		client  *http.Client
	}{
		"plain http":         {baseURL: "http://vault.example", mount: "m", token: "t", client: client.Client()},
		"credentials":        {baseURL: "https://user:pass@vault.example", mount: "m", token: "t", client: client.Client()},
		"query":              {baseURL: "https://vault.example?x=1", mount: "m", token: "t", client: client.Client()},
		"bad mount":          {baseURL: "https://vault.example", mount: "../escape", token: "t", client: client.Client()},
		"empty token":        {baseURL: "https://vault.example", mount: "m", token: "", client: client.Client()},
		"nil client":         {baseURL: "https://vault.example", mount: "m", token: "t", client: nil},
		"missing host":       {baseURL: "https://", mount: "m", token: "t", client: client.Client()},
		"non alpha numerics": {baseURL: "https://vault.example", mount: "a/b", token: "t", client: client.Client()},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewBaoCustody(testCase.baseURL, testCase.mount, testCase.token, testCase.client); err == nil {
				t.Fatal("expected an error for an untrusted custody configuration")
			}
		})
	}
}

func TestBaoCustodyDoesNotFollowRedirects(t *testing.T) {
	var redirectTargetHits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectTargetHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	custody := newTestCustody(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/v1/multica-git/data/ref", http.StatusTemporaryRedirect)
	})

	_, err := custody.Store(context.Background(), "ref", KeyMaterial{Private: []byte("secret")})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Store error = %v, want %v", err, ErrUnavailable)
	}
	if hits := redirectTargetHits.Load(); hits != 0 {
		t.Fatalf("redirect target was contacted %d times, want 0", hits)
	}
}

func TestBaoCustodyStoreUsesCASZero(t *testing.T) {
	var received struct {
		Options struct {
			CAS int `json:"cas"`
		} `json:"options"`
		Data struct {
			PrivateKey string `json:"private_key"`
		} `json:"data"`
	}
	custody := newTestCustody(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/multica-git/data/ref" {
			t.Errorf("request path = %q", r.URL.Path)
		}
		if r.Header.Get("X-Vault-Token") != "test-token" {
			t.Errorf("missing custody token header")
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"version": 3}})
	})

	version, err := custody.Store(context.Background(), "ref", KeyMaterial{Private: []byte("secret")})
	if err != nil {
		t.Fatalf("Store: %v", err)
	}
	if version != 3 {
		t.Fatalf("version = %d, want 3", version)
	}
	if received.Options.CAS != 0 {
		t.Fatalf("CAS = %d, want 0 so an existing generation is never overwritten", received.Options.CAS)
	}
	decoded, err := base64.StdEncoding.DecodeString(received.Data.PrivateKey)
	if err != nil {
		t.Fatalf("decode stored private key: %v", err)
	}
	if string(decoded) != "secret" {
		t.Fatalf("stored private key = %q, want %q", decoded, "secret")
	}
}

func TestBaoCustodyStoreRefusesEmptyMaterial(t *testing.T) {
	custody := newTestCustody(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("the custody adapter must not be called without key material")
	})
	if _, err := custody.Store(context.Background(), "ref", KeyMaterial{}); !errors.Is(err, ErrIdentity) {
		t.Fatalf("Store error = %v, want %v", err, ErrIdentity)
	}
}

func TestBaoCustodyDestroyAllDestroysEveryLiveVersion(t *testing.T) {
	var destroyed []int
	custody := newTestCustody(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/metadata/ref"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"versions": map[string]any{
						"1": map[string]any{"destroyed": false},
						"2": map[string]any{"destroyed": true},
						"3": map[string]any{"destroyed": false},
					},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/destroy/ref"):
			var body struct {
				Versions []int `json:"versions"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode destroy request: %v", err)
			}
			destroyed = body.Versions
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
		}
	})

	if err := custody.DestroyAll(context.Background(), "ref"); err != nil {
		t.Fatalf("DestroyAll: %v", err)
	}
	if len(destroyed) != 2 || destroyed[0] != 1 || destroyed[1] != 3 {
		t.Fatalf("destroyed versions = %v, want [1 3]", destroyed)
	}
}

func TestBaoCustodyDestroyAllFailsWithoutVersions(t *testing.T) {
	custody := newTestCustody(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"versions": map[string]any{}}})
	})
	if err := custody.DestroyAll(context.Background(), "ref"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("DestroyAll error = %v, want %v", err, ErrUnavailable)
	}
}

func TestBaoCustodyWithSignerRejectsNonEd25519Key(t *testing.T) {
	custody := newTestCustody(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"data": map[string]any{"private_key": base64.StdEncoding.EncodeToString(rsaPrivateKeyPEM(t))}},
		})
	})

	err := custody.WithSigner(context.Background(), "ref", func(ssh.Signer) error {
		t.Error("the signer callback must not run for a non-Ed25519 key")
		return nil
	})
	if !errors.Is(err, ErrIdentity) {
		t.Fatalf("WithSigner error = %v, want %v", err, ErrIdentity)
	}
}

func TestBaoCustodyWithSignerExposesTheKeyOnlyInsideTheCallback(t *testing.T) {
	material, err := GenerateKeyMaterial(bytes.NewReader(make([]byte, 64)))
	if err != nil {
		t.Fatalf("GenerateKeyMaterial: %v", err)
	}
	custody := newTestCustody(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"data": map[string]any{"private_key": base64.StdEncoding.EncodeToString(material.Private)}},
		})
	})

	called := false
	err = custody.WithSigner(context.Background(), "ref", func(signer ssh.Signer) error {
		called = true
		if signer == nil {
			t.Error("signer is nil")
			return nil
		}
		if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
			t.Errorf("signer key type = %q", signer.PublicKey().Type())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithSigner: %v", err)
	}
	if !called {
		t.Fatal("the signer callback did not run")
	}
}
