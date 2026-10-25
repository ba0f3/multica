package r2dgit

import (
	"context"
	"strings"

	"github.com/42wim/sshsig"
)

const (
	giteaSSHVerifyNamespace      = "gitea"
	maxGiteaVerificationTokenLen = 8192
)

// SignGiteaSSHKeyVerification returns an armored SSH signature for Gitea's
// "verify this key" token. The private key never leaves custody; only the
// signature is returned for pasting into Gitea.
func (s *Service) SignGiteaSSHKeyVerification(
	ctx context.Context,
	userID, identityID string,
	generation uint64,
	token string,
) (string, error) {
	if !s.available() {
		return "", ErrUnavailable
	}
	if strings.TrimSpace(userID) == "" {
		return "", ErrPrincipal
	}
	token = strings.TrimSpace(token)
	if token == "" || len(token) > maxGiteaVerificationTokenLen {
		return "", ErrScope
	}

	identity, err := s.identityFor(ctx, userID, identityID)
	if err != nil {
		return "", err
	}
	if identity.Revoked {
		return "", ErrRevoked
	}

	key, err := s.store.GetKey(ctx, identity.ID, generation)
	if err != nil {
		return "", ErrScope
	}
	switch key.State {
	case PendingVerification, Ready:
	case Revoked:
		return "", ErrRevoked
	default:
		return "", ErrScope
	}

	provider, err := s.store.GetProvider(ctx, identity.ProviderID)
	if err != nil {
		return "", ErrScope
	}
	if provider.Kind != "gitea" {
		return "", ErrScope
	}

	var signature string
	err = s.custody.WithPrivatePEM(ctx, key.InternalSecretRef, func(pem []byte) error {
		armored, signErr := sshsig.Sign(pem, strings.NewReader(token), giteaSSHVerifyNamespace)
		if signErr != nil {
			return ErrUnavailable
		}
		signature = string(armored)
		return nil
	})
	if err != nil {
		return "", err
	}
	if signature == "" {
		return "", ErrUnavailable
	}
	return signature, nil
}
