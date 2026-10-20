package r2dgit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateKeyMaterialProducesUsableEd25519Key(t *testing.T) {
	material, err := GenerateKeyMaterial(bytes.NewReader(make([]byte, 64)))
	if err != nil {
		t.Fatalf("GenerateKeyMaterial: %v", err)
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(material.PublicKey))
	if err != nil {
		t.Fatalf("parse generated public key: %v", err)
	}
	if parsed.Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("key type = %q, want %q", parsed.Type(), ssh.KeyAlgoED25519)
	}
	if got, want := material.Fingerprint, ssh.FingerprintSHA256(parsed); got != want {
		t.Fatalf("fingerprint = %q, want %q", got, want)
	}
	if len(material.Private) == 0 {
		t.Fatal("private key material is empty")
	}
	if _, err := ssh.ParsePrivateKey(material.Private); err != nil {
		t.Fatalf("parse generated private key: %v", err)
	}
}

func TestGenerateKeyMaterialRejectsExhaustedReader(t *testing.T) {
	if _, err := GenerateKeyMaterial(bytes.NewReader(nil)); err == nil {
		t.Fatal("expected an error for an exhausted randomness source")
	}
}

func TestKeyMaterialNeverRendersPrivateBytes(t *testing.T) {
	material, err := GenerateKeyMaterial(bytes.NewReader(make([]byte, 64)))
	if err != nil {
		t.Fatalf("GenerateKeyMaterial: %v", err)
	}

	for _, rendered := range []string{material.String(), material.GoString()} {
		if rendered != "[redacted Git key material]" {
			t.Fatalf("rendered key material = %q, want the redaction marker", rendered)
		}
		if strings.Contains(rendered, "PRIVATE KEY") {
			t.Fatalf("rendered key material leaked a PEM header: %q", rendered)
		}
	}

	encoded, err := json.Marshal(material)
	if err != nil {
		t.Fatalf("marshal key material: %v", err)
	}
	if string(encoded) != "{}" {
		t.Fatalf("marshalled key material = %s, want {}", encoded)
	}
}
