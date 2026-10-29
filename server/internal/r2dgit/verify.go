package r2dgit

import (
	"context"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// githubBanner is the message GitHub sends when an account key authenticates.
// The wording differs from Gitea's, so the two are parsed separately.
var githubBanner = regexp.MustCompile(`^Hi ([A-Za-z0-9][A-Za-z0-9-]{0,38})! You've successfully authenticated, but GitHub does not provide shell access\.$`)

// giteaBanner is the message Gitea sends when an account key authenticates.
// It names the key and continues with the deployment hint, so the whole
// message has to match — a truncated banner is not proof of anything.
// Gitea prints several banner variants across versions; the second line may
// mention password login or container deploy. All forms end after the first
// "Gitea does not provide shell access." sentence with more guidance.
var giteaBanner = regexp.MustCompile(
	`(?s)^Hi there, ([A-Za-z0-9][A-Za-z0-9_.-]{0,39})! You've successfully authenticated with the (?:SSH )?key named [^\r\n]{1,200}\.\nGitea does not provide shell access\..*$`,
)

// ParseProviderLogin extracts the provider account a key authenticated.
//
// The banner is provider-specific: a GitHub message never satisfies Gitea and
// the other way round. A banner that does not match exactly is not proof and
// leaves the identity unverified.
func ParseProviderLogin(kind, banner string) (string, error) {
	trimmed := strings.TrimSuffix(strings.TrimSpace(banner), "\n")
	switch kind {
	case "github":
		match := githubBanner.FindStringSubmatch(trimmed)
		if match == nil {
			return "", ErrIdentity
		}
		return match[1], nil
	case "gitea":
		match := giteaBanner.FindStringSubmatch(trimmed)
		if match == nil {
			return "", ErrIdentity
		}
		return match[1], nil
	default:
		return "", ErrProvider
	}
}

// ProviderSuccessExit reports whether the exit status a provider returned
// means the account key authenticated.
//
// GitHub answers a successful authentication with exit status 1 because it
// refuses shell access; Gitea answers with 0. Treating a zero status from
// GitHub as success would accept a login that proved nothing.
func ProviderSuccessExit(kind string, exitCode int) bool {
	switch kind {
	case "github":
		return exitCode == 1
	case "gitea":
		return exitCode == 0
	default:
		return false
	}
}

// pinnedHostKeyCallback builds a host key check restricted to the provider's
// pinned fingerprints.
//
// A connection whose host key is not pinned is refused: without this check a
// DNS or routing change could send the key to a host the operator never
// approved.
func pinnedHostKeyCallback(pins []string) (ssh.HostKeyCallback, error) {
	allowed := make(map[string]struct{}, len(pins))
	for _, pin := range pins {
		if strings.TrimSpace(pin) == "" {
			return nil, ErrProvider
		}
		allowed[pin] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil, ErrProvider
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if _, ok := allowed[ssh.FingerprintSHA256(key)]; !ok {
			return ErrProvider
		}
		return nil
	}, nil
}

// SSHVerifier proves that a stored key authenticates a provider account.
//
// It opens a fresh connection per verification and never reuses a session,
// so a revoked key cannot keep an authenticated channel alive.
type SSHVerifier struct {
	custody SigningCustody
	timeout time.Duration
}

// NewSSHVerifier builds a verifier that signs the provider handshake with the
// key held in custody.
func NewSSHVerifier(custody SigningCustody) *SSHVerifier {
	return &SSHVerifier{
		custody: custody,
		timeout: 15 * time.Second,
	}
}

// Verify opens a pinned connection to the provider and reads the account the
// key authenticated.
//
// The key is only available inside the custody callback: the verifier never
// holds a signer that outlives the connection.
func (v *SSHVerifier) Verify(ctx context.Context, provider Provider, secretRef string, generation uint64) (string, error) {
	if v == nil || v.custody == nil {
		return "", ErrUnavailable
	}
	if len(provider.HostPins) == 0 || provider.Host == "" || provider.Port < 1 || provider.Port > 65535 {
		return "", ErrProvider
	}
	hostKeyCallback, err := pinnedHostKeyCallback(provider.HostPins)
	if err != nil {
		return "", err
	}

	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	var banner strings.Builder
	var stderr strings.Builder
	var stdout strings.Builder
	var login string
	var exitCode int

	err = v.custody.WithSigner(ctx, secretRef, func(signer ssh.Signer) error {
		if signer == nil || signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
			return ErrIdentity
		}
		address := net.JoinHostPort(provider.Host, strconv.Itoa(provider.Port))
		client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{
			User:            "git",
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: hostKeyCallback,
			BannerCallback: func(message string) error {
				banner.WriteString(message)
				return nil
			},
			Timeout: v.timeout,
		})
		if err != nil {
			if isSSHAuthFailure(err) {
				return ErrIdentity
			}
			return ErrProvider
		}
		defer client.Close()

		session, err := client.NewSession()
		if err != nil {
			return ErrProvider
		}
		defer session.Close()
		session.Stderr = &stderr
		session.Stdout = &stdout
		// Account verification uses the no-command request sent by ssh -T.
		// An exec request such as true is not a supported GitHub Git command.
		if err := session.Shell(); err != nil {
			return ErrProvider
		}
		waitErr := session.Wait()
		if exitStatus, ok := waitErr.(*ssh.ExitError); ok {
			exitCode = exitStatus.ExitStatus()
		} else if waitErr != nil {
			return ErrProvider
		}

		for _, candidate := range []string{banner.String(), stdout.String(), stderr.String()} {
			if strings.TrimSpace(candidate) == "" {
				continue
			}
			parsed, parseErr := ParseProviderLogin(provider.Kind, candidate)
			if parseErr != nil {
				continue
			}
			if !ProviderSuccessExit(provider.Kind, exitCode) {
				return ErrIdentity
			}
			login = parsed
			return nil
		}
		return ErrIdentity
	})
	if err != nil {
		return "", err
	}
	if login == "" {
		return "", ErrIdentity
	}
	return login, nil
}
