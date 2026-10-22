package r2dgit

import (
	"encoding/base64"
	"testing"
)

func TestLoadGitSecretKeyPrefersDedicatedEnv(t *testing.T) {
	t.Setenv("JWT_SECRET", "jwt-only")
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i + 1)
	}
	t.Setenv("MULTICA_GIT_SECRET_KEY", base64.StdEncoding.EncodeToString(raw))

	key, err := LoadGitSecretKey()
	if err != nil {
		t.Fatalf("LoadGitSecretKey: %v", err)
	}
	if string(key) != string(raw) {
		t.Fatal("expected MULTICA_GIT_SECRET_KEY to win over JWT_SECRET")
	}
}

func TestLoadGitSecretKeyDerivesFromJWT(t *testing.T) {
	t.Setenv("MULTICA_GIT_SECRET_KEY", "")
	t.Setenv("JWT_SECRET", "dev-jwt")

	key, err := LoadGitSecretKey()
	if err != nil {
		t.Fatalf("LoadGitSecretKey: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length %d, want 32", len(key))
	}
	again, err := LoadGitSecretKey()
	if err != nil {
		t.Fatalf("LoadGitSecretKey again: %v", err)
	}
	if string(key) != string(again) {
		t.Fatal("derived key should be stable for the same JWT_SECRET")
	}
}

func TestLoadGitSecretKeyRequiresConfiguration(t *testing.T) {
	t.Setenv("MULTICA_GIT_SECRET_KEY", "")
	t.Setenv("JWT_SECRET", "")
	if _, err := LoadGitSecretKey(); err == nil {
		t.Fatal("expected error when no key source is configured")
	}
}
