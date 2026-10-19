package r2dgit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestEncryptedCustodyCASAndDestroyEveryVersion(t *testing.T) {
	var versions []int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "synthetic-worker-token" {
			t.Error("missing trusted worker auth")
		}
		switch r.URL.Path {
		case "/v1/gitkeys/data/opaque-generation":
			var body struct {
				Options struct {
					CAS *int `json:"cas"`
				} `json:"options"`
				Data map[string]string `json:"data"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Options.CAS == nil || *body.Options.CAS != 0 || body.Data["private_key"] == "" {
				t.Error("missing create-only CAS or encrypted-store material")
			}
			_, _ = w.Write([]byte(`{"data":{"version":1}}`))
		case "/v1/gitkeys/metadata/opaque-generation":
			_, _ = w.Write([]byte(`{"data":{"versions":{"1":{"destroyed":false},"2":{"destroyed":true},"3":{"destroyed":false}}}}`))
		case "/v1/gitkeys/destroy/opaque-generation":
			var body struct {
				Versions []int `json:"versions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			versions = body.Versions
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected custody endpoint %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	b, err := newBaoCustody(server.URL, "gitkeys", "synthetic-worker-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	material, err := generateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(material.private)
	if version, err := b.store(context.Background(), "opaque-generation", material); err != nil || version != 1 {
		t.Fatalf("store version=%d err=%v", version, err)
	}
	if err := b.destroyAll(context.Background(), "opaque-generation"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(versions, []int{1, 3}) {
		t.Fatalf("hard destroy skipped versions: %v", versions)
	}
	if strings.Contains(fmt.Sprintf("%#v", b), "synthetic-worker-token") {
		t.Fatal("custody token in diagnostic")
	}
}

func TestCustodyOutageRedirectAndMalformedResponsesFailClosed(t *testing.T) {
	for _, response := range []struct {
		name   string
		status int
		body   string
	}{{"outage", 503, "internal secret details"}, {"redirect", 307, ""}, {"malformed", 200, `{"data":`}, {"missing version", 200, `{"data":{}}`}} {
		t.Run(response.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "https://unapproved.invalid/")
				w.WriteHeader(response.status)
				_, _ = w.Write([]byte(response.body))
			}))
			defer server.Close()
			b, err := newBaoCustody(server.URL, "gitkeys", "synthetic-token", server.Client())
			if err != nil {
				t.Fatal(err)
			}
			material := generatedKey{private: []byte("synthetic-only")}
			if _, err := b.store(context.Background(), "opaque", material); err != ErrUnavailable {
				t.Fatalf("unsafe response accepted: %v", err)
			}
		})
	}
	for _, base := range []string{"http://localhost:8200", "https://user:pass@localhost", "https://localhost/other", "https://localhost?query=x"} {
		if _, err := newBaoCustody(base, "keys", "synthetic", http.DefaultClient); err == nil {
			t.Fatal("unsafe custody config accepted", base)
		}
	}
	b, _ := newBaoCustody("https://unapproved.invalid", "keys", "synthetic", http.DefaultClient)
	if _, err := b.store(context.Background(), "../escape", generatedKey{private: []byte("synthetic-only")}); err != ErrUnavailable {
		t.Fatal("caller-controlled secret path accepted", err)
	}
}

func TestCustodySignerUsesSyntheticKVAndRejectsMalformedMaterial(t *testing.T) {
	material, err := generateKey(bytes.NewReader(bytes.Repeat([]byte{9}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(material.private)
	payload := base64.StdEncoding.EncodeToString(material.private)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/keys/data/synthetic" || r.Header.Get("X-Vault-Token") != "synthetic-token" {
			t.Error("unexpected custody request")
			w.WriteHeader(403)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]string{"private_key": payload}}})
	}))
	defer server.Close()
	custody, err := newBaoCustody(server.URL, "keys", "synthetic-token", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	public, _, _, _, err := ssh.ParseAuthorizedKey([]byte(material.publicKey))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	use := func(signer ssh.Signer) error {
		calls++
		signed, err := signer.Sign(bytes.NewReader(bytes.Repeat([]byte{1}, 64)), []byte("synthetic challenge"))
		if err != nil {
			return err
		}
		return public.Verify([]byte("synthetic challenge"), signed)
	}
	if err := custody.WithSigner(context.Background(), "synthetic", use); err != nil || calls != 1 {
		t.Fatalf("KV signer positive control: %v", err)
	}
	for _, bad := range []string{"", "not base64", base64.StdEncoding.EncodeToString([]byte("not a private key"))} {
		payload = bad
		if err := custody.WithSigner(context.Background(), "synthetic", use); err == nil {
			t.Fatal("invalid KV key accepted")
		}
	}
	if calls != 1 {
		t.Fatal("malformed custody material reached signing callback")
	}
}
