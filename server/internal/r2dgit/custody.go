package r2dgit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// KeyCustody stores and destroys private key material in an encrypted secret
// store. There is no local-file fallback: a deployment without a working
// custody adapter cannot create keys.
type KeyCustody interface {
	// Store writes one immutable generation and returns its version. It must
	// never overwrite an existing secret.
	Store(ctx context.Context, ref string, material KeyMaterial) (int, error)
	// DestroyAll permanently removes every version of a secret.
	DestroyAll(ctx context.Context, ref string) error
}

// SigningCustody exposes a key only inside a trusted callback. Neither a
// runner nor a transport subprocess receives a private-key file or an agent
// socket.
type SigningCustody interface {
	WithSigner(ctx context.Context, ref string, fn func(ssh.Signer) error) error
	// WithPrivatePEM exposes the OpenSSH-encoded private key only inside fn.
	WithPrivatePEM(ctx context.Context, ref string, fn func(pem []byte) error) error
}

// EncryptedCustody is a custody adapter that can both store and sign.
type EncryptedCustody interface {
	KeyCustody
	SigningCustody
}

// baoCustody is an OpenBao/Vault KV v2 client. It is a trusted-worker
// primitive: it is not wired to any HTTP route and cannot be reached by a
// task.
type baoCustody struct {
	baseURL string
	mount   string
	token   string
	client  *http.Client
}

func (baoCustody) String() string   { return "[encrypted Git custody]" }
func (baoCustody) GoString() string { return "[encrypted Git custody]" }

// custodySegment bounds every path segment the adapter builds. It rejects
// separators, traversal and empty segments so a ref can never escape the
// configured mount.
var custodySegment = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// NewBaoCustody builds a KV v2 custody adapter.
//
// The base URL must be an HTTPS authority with no credentials, query or
// fragment: the custody token is a bearer secret and must never be sent to a
// host the operator did not name.
func NewBaoCustody(baseURL, mount, token string, client *http.Client) (EncryptedCustody, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil ||
		parsed.Scheme != "https" ||
		parsed.Host == "" ||
		parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" ||
		!custodySegment.MatchString(mount) ||
		strings.TrimSpace(token) == "" ||
		client == nil {
		return nil, ErrUnavailable
	}
	bounded := *client
	// A redirect would carry the custody token to a host the operator did
	// not approve, so redirects are refused instead of followed.
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &baoCustody{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		mount:   mount,
		token:   token,
		client:  &bounded,
	}, nil
}

func (b *baoCustody) request(ctx context.Context, method, kind, ref string, input, output any) error {
	if b == nil || !custodySegment.MatchString(ref) {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	var body []byte
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return ErrUnavailable
		}
		defer clear(encoded)
		body = encoded
	}

	request, err := http.NewRequestWithContext(ctx, method, b.baseURL+"/v1/"+b.mount+"/"+kind+"/"+ref, bytes.NewReader(body))
	if err != nil {
		return ErrUnavailable
	}
	request.Header.Set("X-Vault-Token", b.token)
	request.Header.Set("Content-Type", "application/json")

	response, err := b.client.Do(request)
	if err != nil {
		return ErrUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ErrUnavailable
	}
	if output == nil {
		return nil
	}

	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	defer clear(data)
	if err != nil || len(data) > 1<<20 {
		return ErrUnavailable
	}
	if json.Unmarshal(data, output) != nil {
		return ErrUnavailable
	}
	return nil
}

// Store creates one immutable generation using CAS=0. A duplicate or retried
// provision must reconcile the durable intent instead of overwriting a key.
func (b *baoCustody) Store(ctx context.Context, ref string, material KeyMaterial) (int, error) {
	if len(material.Private) == 0 {
		return 0, ErrIdentity
	}
	input := struct {
		Options struct {
			CAS int `json:"cas"`
		} `json:"options"`
		Data struct {
			PrivateKey string `json:"private_key"`
		} `json:"data"`
	}{}
	input.Data.PrivateKey = base64.StdEncoding.EncodeToString(material.Private)
	var output struct {
		Data struct {
			Version int `json:"version"`
		} `json:"data"`
	}
	if err := b.request(ctx, http.MethodPost, "data", ref, input, &output); err != nil {
		return 0, err
	}
	if output.Data.Version < 1 {
		return 0, ErrUnavailable
	}
	return output.Data.Version, nil
}

func (b *baoCustody) withPrivatePEM(ctx context.Context, ref string, fn func([]byte) error) error {
	if fn == nil {
		return ErrScope
	}
	var output struct {
		Data struct {
			Data struct {
				PrivateKey string `json:"private_key"`
			} `json:"data"`
		} `json:"data"`
	}
	if err := b.request(ctx, http.MethodGet, "data", ref, nil, &output); err != nil {
		return err
	}
	private, err := base64.StdEncoding.DecodeString(output.Data.Data.PrivateKey)
	output.Data.Data.PrivateKey = ""
	if err != nil {
		return ErrUnavailable
	}
	defer clear(private)
	return fn(private)
}

// WithPrivatePEM loads a stored generation and hands PEM bytes to fn while
// they are alive.
func (b *baoCustody) WithPrivatePEM(ctx context.Context, ref string, fn func([]byte) error) error {
	return b.withPrivatePEM(ctx, ref, fn)
}

// WithSigner loads a stored generation and hands it to fn while the decoded
// bytes are alive. Nothing outside the callback can reach the signer.
func (b *baoCustody) WithSigner(ctx context.Context, ref string, fn func(ssh.Signer) error) error {
	if fn == nil {
		return ErrScope
	}
	return b.withPrivatePEM(ctx, ref, func(private []byte) error {
		signer, err := ssh.ParsePrivateKey(private)
		if err != nil {
			return ErrIdentity
		}
		if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
			return ErrIdentity
		}
		return fn(signer)
	})
}

// DestroyAll implements KV v2 hard destruction, not soft deletion. The caller
// must revoke locally before cleanup and keep a durable tombstone until this
// succeeds.
func (b *baoCustody) DestroyAll(ctx context.Context, ref string) error {
	var metadata struct {
		Data struct {
			Versions map[string]struct {
				Destroyed bool `json:"destroyed"`
			} `json:"versions"`
		} `json:"data"`
	}
	if err := b.request(ctx, http.MethodGet, "metadata", ref, nil, &metadata); err != nil {
		return err
	}
	if len(metadata.Data.Versions) == 0 {
		return ErrUnavailable
	}

	versions := make([]int, 0, len(metadata.Data.Versions))
	for raw, version := range metadata.Data.Versions {
		number, err := strconv.Atoi(raw)
		if err != nil || number < 1 {
			return ErrUnavailable
		}
		if !version.Destroyed {
			versions = append(versions, number)
		}
	}
	if len(versions) == 0 {
		return nil
	}
	sort.Ints(versions)
	return b.request(ctx, http.MethodPost, "destroy", ref, struct {
		Versions []int `json:"versions"`
	}{versions}, nil)
}
