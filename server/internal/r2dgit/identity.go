package r2dgit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var ErrIdentity = errors.New("git_identity_unverified")

type KeyState string

const (
	Provisioning        KeyState = "provisioning"
	PendingVerification KeyState = "pending_verification"
	Ready               KeyState = "ready"
	Revoked             KeyState = "revoked"
)

// PublicIdentity is the only credential representation intended for clients.
// Secret references, private key bytes and provider tokens are absent by type.
type PublicIdentity struct {
	ID                string     `json:"id"`
	UserID            string     `json:"user_id"`
	ProviderID        string     `json:"provider_id"`
	Generation        uint64     `json:"generation"`
	PublicKey         string     `json:"public_key"`
	Fingerprint       string     `json:"fingerprint"`
	State             KeyState   `json:"state"`
	AccountID         string     `json:"account_id,omitempty"`
	Login             string     `json:"login,omitempty"`
	VerifiedAt        *time.Time `json:"verified_at,omitempty"`
	Active            bool       `json:"active"`
	CleanupPending    bool       `json:"cleanup_pending"`
	Diagnostic        string     `json:"diagnostic,omitempty"`
	ConsentProjectIDs []string   `json:"consent_project_ids"`
}

// KeyGeneration is a value state machine for trusted custody workers. Persistence
// adapters must CAS transitions and journal provision/destroy intents durably.
// It deliberately has no private-key getter or user-selected secret path.
type KeyGeneration struct {
	public         PublicIdentity
	secretRef      string
	cleanupPending bool
}

func (k KeyGeneration) Public() PublicIdentity {
	p := k.public
	p.ConsentProjectIDs = append([]string(nil), p.ConsentProjectIDs...)
	if p.VerifiedAt != nil {
		at := *p.VerifiedAt
		p.VerifiedAt = &at
	}
	return p
}
func (k KeyGeneration) MarshalJSON() ([]byte, error) { return json.Marshal(k.Public()) }
func (k KeyGeneration) String() string               { b, _ := k.MarshalJSON(); return string(b) }
func (k KeyGeneration) GoString() string             { return k.String() }

// generatedKey never crosses the trusted custody package boundary. No plaintext
// fallback is provided: a caller must store it in encrypted custody, then zero
// its best-effort buffer and persist the pending-verification transition.
type generatedKey struct {
	publicKey, fingerprint string
	private                []byte
}

func (generatedKey) String() string   { return "[redacted Git key material]" }
func (generatedKey) GoString() string { return "[redacted Git key material]" }

func generateKey(random io.Reader) (generatedKey, error) {
	_, private, err := ed25519.GenerateKey(random)
	if err != nil {
		return generatedKey{}, ErrUnavailable
	}
	defer clear(private)
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		return generatedKey{}, ErrUnavailable
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		return generatedKey{}, ErrUnavailable
	}
	defer clear(block.Bytes)
	// The encoded private material remains inside custody workers. Store adapters
	// receive it directly; it is never part of task/profile response models.
	return generatedKey{publicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public))), fingerprint: ssh.FingerprintSHA256(public), private: pem.EncodeToMemory(block)}, nil
}

// generateProductionKey uses the OS CSPRNG. The result is private to this package; future
// custody orchestration must not call this before a durable provision intent.
func generateProductionKey() (generatedKey, error) { return generateKey(rand.Reader) }

func newGeneration(id, userID, providerID, secretRef string, generation uint64, publicKey string) (KeyGeneration, error) {
	if !nonempty(id, userID, providerID, secretRef) || generation == 0 {
		return KeyGeneration{}, ErrIdentity
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(publicKey))
	if err != nil || key.Type() != ssh.KeyAlgoED25519 || len(options) != 0 || len(rest) != 0 {
		return KeyGeneration{}, ErrIdentity
	}
	return KeyGeneration{public: PublicIdentity{ID: id, UserID: userID, ProviderID: providerID, Generation: generation, PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), Fingerprint: ssh.FingerprintSHA256(key), State: Provisioning}, secretRef: secretRef}, nil
}

func (k KeyGeneration) stored() (KeyGeneration, error) {
	if k.public.State != Provisioning || k.secretRef == "" {
		return KeyGeneration{}, ErrIdentity
	}
	k.public.State = PendingVerification
	return k, nil
}

// Verification is produced only by a trusted provider adapter over a pinned
// connection using this exact key generation. AccountID may be empty for an SSH
// provider that only proves a login; an immutable account-link flow is separate.
type Verification struct {
	IdentityID, ProviderID string
	Generation             uint64
	AccountID, Login       string
	HostPinned             bool
	VerifiedAt             time.Time
}

func (k KeyGeneration) verified(v Verification) (KeyGeneration, error) {
	if k.public.State != PendingVerification || !v.HostPinned || v.IdentityID != k.public.ID || v.ProviderID != k.public.ProviderID || v.Generation != k.public.Generation || !nonempty(v.Login) || v.VerifiedAt.IsZero() {
		return KeyGeneration{}, ErrIdentity
	}
	k.public.State = Ready
	k.public.Login = v.Login
	k.public.AccountID = v.AccountID
	at := v.VerifiedAt
	k.public.VerifiedAt = &at
	return k, nil
}

func (k KeyGeneration) revoke() KeyGeneration {
	k.public.State = Revoked
	k.cleanupPending = true
	return k
}

func activateRotation(old, new KeyGeneration) (KeyGeneration, KeyGeneration, error) {
	if old.public.State != Ready || new.public.State != Ready || old.public.ID != new.public.ID || old.public.UserID != new.public.UserID || old.public.ProviderID != new.public.ProviderID || new.public.Generation <= old.public.Generation || old.secretRef == new.secretRef || !sameProviderAccount(old.public.Login, old.public.AccountID, new.public.Login, new.public.AccountID) {
		return KeyGeneration{}, KeyGeneration{}, ErrIdentity
	}
	return old.revoke(), new, nil
}

// A trusted immutable provider ID survives a display-name change. SSH-only
// proofs without that ID pin the login; mixed proof strengths are ambiguous.
func sameProviderAccount(oldLogin, oldID, login, id string) bool {
	if oldID != "" || id != "" {
		return oldID != "" && id != "" && oldID == id
	}
	return nonempty(oldLogin, login) && oldLogin == login
}

// IdentityManagerActor is resolved from human session middleware, including
// session-bound CSRF and recent authentication. PAT/task/daemon actors must not
// be translated into this type by an endpoint adapter.
type IdentityManagerActor struct {
	UserID                                string
	HumanSession, CSRFChecked, RecentAuth bool
}

func (a IdentityManagerActor) authorize(ownerID string) error {
	if !a.HumanSession || !a.CSRFChecked || !a.RecentAuth || !nonempty(ownerID) || a.UserID != ownerID {
		return ErrPrincipal
	}
	return nil
}

var githubSSHBanner = regexp.MustCompile(`^Hi ([A-Za-z0-9][A-Za-z0-9-]{0,38})! You've successfully authenticated, but GitHub does not provide shell access\.$`)

// verifyGitHubSSH recognizes the documented nonzero-success response, only on
// a host-pinned authenticated connection. Raw SSH exit status is never proof.
func verifyGitHubSSH(stdout, stderr string, exitCode int, hostPinned bool) (string, error) {
	if !hostPinned || exitCode != 1 || stdout != "" {
		return "", ErrIdentity
	}
	match := githubSSHBanner.FindStringSubmatch(strings.TrimSuffix(stderr, "\n"))
	if match == nil {
		return "", ErrIdentity
	}
	return match[1], nil
}

var giteaSSHBanner = regexp.MustCompile(`^Hi there, ([A-Za-z0-9][A-Za-z0-9_.-]{0,39})! You've successfully authenticated with the SSH key named [^\r\n]{1,200}\.\nGitea does not provide shell access\. If this is unexpected, please setup Gitea under another SSH user or use container to deploy\.$`)

// The Gitea account-key response differs from deploy/principal keys and exits
// successfully. Match its complete response; exit status alone is not proof.
// Reference: go-gitea/gitea cmd/serv.go runServ's no-command account-key branch.
func verifyGiteaSSH(stdout, stderr string, exitCode int, hostPinned bool) (string, error) {
	if !hostPinned || exitCode != 0 || stdout != "" {
		return "", ErrIdentity
	}
	match := giteaSSHBanner.FindStringSubmatch(strings.TrimSuffix(stderr, "\n"))
	if match == nil {
		return "", ErrIdentity
	}
	return match[1], nil
}
