package r2dgit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func fixtureKey(t *testing.T, generation uint64) KeyGeneration {
	t.Helper()
	// Deterministic bytes are synthetic fixture material, never an enrolled key.
	material, err := generateKey(bytes.NewReader(bytes.Repeat([]byte{byte(generation)}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(material.private)
	k, err := newGeneration("identity-a", "human-a", "provider-a", fmt.Sprintf("internal-reference-%d", generation), generation, material.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func readyFixtureKey(t *testing.T, generation uint64) KeyGeneration {
	t.Helper()
	k := fixtureKey(t, generation)
	k, err := k.stored()
	if err != nil {
		t.Fatal(err)
	}
	k, err = k.verified(Verification{IdentityID: "identity-a", ProviderID: "provider-a", Generation: generation, Login: "human-a", AccountID: "account-a", HostPinned: true, VerifiedAt: fixtureNow})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeyLifecycleAndRotation(t *testing.T) {
	k := fixtureKey(t, 1)
	if k.Public().State != Provisioning {
		t.Fatal(k.Public())
	}
	if _, err := k.verified(Verification{}); err == nil {
		t.Fatal("provisioning verified before custody ack")
	}
	k, err := k.stored()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.stored(); err == nil {
		t.Fatal("duplicate transition accepted")
	}
	proof := Verification{IdentityID: "identity-a", ProviderID: "provider-a", Generation: 1, Login: "human-a", AccountID: "account-a", HostPinned: true, VerifiedAt: fixtureNow}
	for _, alter := range []func(*Verification){func(v *Verification) { v.HostPinned = false }, func(v *Verification) { v.IdentityID = "other" }, func(v *Verification) { v.ProviderID = "other" }, func(v *Verification) { v.Generation++ }, func(v *Verification) { v.Login = "" }} {
		bad := proof
		alter(&bad)
		if _, err := k.verified(bad); err == nil {
			t.Fatal("wrong proof accepted")
		}
	}
	k, err = k.verified(proof)
	if err != nil {
		t.Fatal(err)
	}
	p := k.Public()
	k.public.ConsentProjectIDs = []string{"project-a"}
	consent := k.Public()
	consent.ConsentProjectIDs[0] = "project-b"
	if k.Public().ConsentProjectIDs[0] != "project-a" {
		t.Fatal("public metadata mutated project consent")
	}
	*p.VerifiedAt = fixtureNow.AddDate(1, 0, 0)
	if !k.Public().VerifiedAt.Equal(fixtureNow) {
		t.Fatal("public metadata mutated verification")
	}
	if _, _, err := activateRotation(k, fixtureKey(t, 2)); err == nil {
		t.Fatal("unverified rotation activated")
	}
	old, next, err := activateRotation(k, readyFixtureKey(t, 2))
	if err != nil {
		t.Fatal(err)
	}
	if old.Public().State != Revoked || !old.cleanupPending || next.Public().State != Ready {
		t.Fatal("rotation failed to revoke old generation")
	}
	if _, err := old.stored(); err == nil {
		t.Fatal("revoked generation revived")
	}
	if _, err := old.verified(proof); err == nil {
		t.Fatal("revoked generation reverified")
	}
	if _, _, err := activateRotation(old, next); err == nil {
		t.Fatal("revoked generation reactivated")
	}
	wrong := readyFixtureKey(t, 3)
	wrong.public.UserID = "human-b"
	if _, _, err := activateRotation(next, wrong); err == nil {
		t.Fatal("cross-user rotation accepted")
	}
	wrong = readyFixtureKey(t, 3)
	wrong.public.AccountID = "another-account"
	if _, _, err := activateRotation(next, wrong); err == nil {
		t.Fatal("provider account substitution accepted")
	}
	renamed := readyFixtureKey(t, 3)
	renamed.public.Login = "renamed-human"
	if _, _, err := activateRotation(next, renamed); err != nil {
		t.Fatal("same immutable account ID rejected after login rename", err)
	}
	for _, pair := range [][2]string{{"", "account-a"}, {"account-a", ""}} {
		if sameProviderAccount("human-a", pair[0], "human-a", pair[1]) {
			t.Fatal("ambiguous mixed account proofs accepted")
		}
	}
	if !sameProviderAccount("human-a", "", "human-a", "") || sameProviderAccount("human-a", "", "human-b", "") {
		t.Fatal("SSH-only login pin changed")
	}
}

func TestCredentialResponsesAndDiagnosticsNeverContainSecretReference(t *testing.T) {
	k := readyFixtureKey(t, 1)
	b, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{string(b), fmt.Sprintf("%v", k), fmt.Sprintf("%+v", k), fmt.Sprintf("%#v", k)} {
		if strings.Contains(s, "internal-reference") || strings.Contains(s, "secretRef") || strings.Contains(s, "PRIVATE KEY") {
			t.Fatalf("secret in metadata/diagnostics: %s", s)
		}
		if !strings.Contains(s, "ssh-ed25519") || !strings.Contains(s, "SHA256:") {
			t.Fatal("missing public material")
		}
	}
	material, err := generateKey(bytes.NewReader(bytes.Repeat([]byte{42}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(material.private)
	if fmt.Sprintf("%#v", material) != "[redacted Git key material]" {
		t.Fatal("key diagnostic leaked")
	}
	signer, err := ssh.ParsePrivateKey(material.private)
	if err != nil || ssh.FingerprintSHA256(signer.PublicKey()) != material.fingerprint {
		t.Fatalf("generated custody material does not match public key: %v", err)
	}
	if _, err := generateKey(bytes.NewReader(nil)); err == nil {
		t.Fatal("RNG failure accepted")
	}
}

func TestIdentityOwnerSessionRequirements(t *testing.T) {
	a := IdentityManagerActor{UserID: "human-a", HumanSession: true, CSRFChecked: true, RecentAuth: true}
	if err := a.authorize("human-a"); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*IdentityManagerActor){func(a *IdentityManagerActor) { a.UserID = "human-b" }, func(a *IdentityManagerActor) { a.HumanSession = false }, func(a *IdentityManagerActor) { a.CSRFChecked = false }, func(a *IdentityManagerActor) { a.RecentAuth = false }} {
		bad := a
		alter(&bad)
		if err := bad.authorize("human-a"); err == nil {
			t.Fatal("non-owner/non-session actor accepted")
		}
	}
}

func TestPinnedGitHubPrincipalProof(t *testing.T) {
	banner := "Hi human-a! You've successfully authenticated, but GitHub does not provide shell access.\n"
	if login, err := verifyGitHubSSH("", banner, 1, true); err != nil || login != "human-a" {
		t.Fatalf("documented nonzero success: %q %v", login, err)
	}
	for _, c := range []struct {
		stdout, stderr string
		code           int
		pinned         bool
	}{{"", banner, 0, true}, {"", banner, 255, true}, {"", banner, 1, false}, {"", banner + "extra", 1, true}, {"banner", banner, 1, true}, {"", "Welcome to Gitea", 1, true}, {"", "human-a", 1, true}} {
		if _, err := verifyGitHubSSH(c.stdout, c.stderr, c.code, c.pinned); err == nil {
			t.Fatalf("accepted unreliable proof %+v", c)
		}
	}
}
