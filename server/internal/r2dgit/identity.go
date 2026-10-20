package r2dgit

import (
	"crypto/ed25519"
	"encoding/pem"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

// KeyState is the lifecycle of a single key generation.
type KeyState string

const (
	// Provisioning means the key was generated but not yet stored.
	Provisioning KeyState = "provisioning"
	// PendingVerification means the key is stored but the user has not yet
	// proved it authenticates their provider account.
	PendingVerification KeyState = "pending_verification"
	// Ready means the key authenticated against its provider.
	Ready KeyState = "ready"
	// Revoked means the key may no longer be used locally.
	Revoked KeyState = "revoked"
)

// KeyMaterial is the result of generating one key pair.
//
// The private bytes exist only long enough to hand them to an encrypted
// custody adapter. Every rendering and every JSON encoding of this type
// redacts them, so an accidental log or response cannot leak them.
type KeyMaterial struct {
	PublicKey   string `json:"-"`
	Fingerprint string `json:"-"`
	Private     []byte `json:"-"`
}

func (KeyMaterial) String() string   { return "[redacted Git key material]" }
func (KeyMaterial) GoString() string { return "[redacted Git key material]" }

// GenerateKeyMaterial creates an Ed25519 key pair from the supplied
// randomness source.
//
// The private key is cleared as soon as it has been encoded, but Go's garbage
// collector may already have copied those bytes; this is a best-effort
// reduction, not a guarantee.
func GenerateKeyMaterial(random io.Reader) (KeyMaterial, error) {
	if random == nil {
		return KeyMaterial{}, ErrUnavailable
	}
	public, private, err := ed25519.GenerateKey(random)
	if err != nil {
		return KeyMaterial{}, ErrUnavailable
	}
	defer clear(private)

	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		return KeyMaterial{}, ErrUnavailable
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		return KeyMaterial{}, ErrUnavailable
	}
	defer clear(block.Bytes)

	return KeyMaterial{
		PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublic))),
		Fingerprint: ssh.FingerprintSHA256(sshPublic),
		Private:     pem.EncodeToMemory(block),
	}, nil
}
