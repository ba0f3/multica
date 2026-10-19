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

// baoCustody is a trusted-worker KV v2 primitive, with no local-file fallback.
// It is not wired to routes or key generation. A durable intent/CAS metadata
// adapter and revocation tombstones must precede using it in a live workflow.
type baoCustody struct {
	baseURL, mount, token string
	client                *http.Client
}

func (baoCustody) String() string   { return "[encrypted Git custody]" }
func (baoCustody) GoString() string { return "[encrypted Git custody]" }

func (b *baoCustody) WithSigner(ctx context.Context, ref string, fn func(ssh.Signer) error) error {
	var output struct {
		Data struct {
			Data struct {
				PrivateKey string `json:"private_key"`
			} `json:"data"`
		} `json:"data"`
	}
	if b.request(ctx, http.MethodGet, "data", ref, nil, &output) != nil {
		return ErrUnavailable
	}
	private, err := base64.StdEncoding.DecodeString(output.Data.Data.PrivateKey)
	output.Data.Data.PrivateKey = ""
	if err != nil {
		return ErrUnavailable
	}
	defer clear(private)
	signer, err := ssh.ParsePrivateKey(private)
	if err != nil || signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return ErrIdentity
	}
	return fn(signer)
}

var custodySegment = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func newBaoCustody(baseURL, mount, token string, client *http.Client) (*baoCustody, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || !custodySegment.MatchString(mount) || !nonempty(token) || client == nil {
		return nil, ErrUnavailable
	}
	copyClient := *client
	// Never forward a custody token or private material to a redirected host.
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &baoCustody{baseURL: strings.TrimSuffix(baseURL, "/"), mount: mount, token: token, client: &copyClient}, nil
}

func (b *baoCustody) request(ctx context.Context, method, kind, ref string, input, output any) error {
	if b == nil || !custodySegment.MatchString(ref) {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var body []byte
	if input != nil {
		var err error
		body, err = json.Marshal(input)
		if err != nil {
			return ErrUnavailable
		}
		defer clear(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.baseURL+"/v1/"+b.mount+"/"+kind+"/"+ref, bytes.NewReader(body))
	if err != nil {
		return ErrUnavailable
	}
	req.Header.Set("X-Vault-Token", b.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return ErrUnavailable
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ErrUnavailable
	}
	if output != nil {
		limited := io.LimitReader(resp.Body, (1<<20)+1)
		data, err := io.ReadAll(limited)
		if err != nil || len(data) > 1<<20 {
			return ErrUnavailable
		}
		defer clear(data)
		if json.Unmarshal(data, output) != nil {
			return ErrUnavailable
		}
	}
	return nil
}

// store creates one immutable generation using CAS=0. Duplicate/provision
// retries must reconcile the durable intent; never overwrite an existing key.
func (b *baoCustody) store(ctx context.Context, ref string, material generatedKey) (int, error) {
	if len(material.private) == 0 {
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
	input.Data.PrivateKey = base64.StdEncoding.EncodeToString(material.private)
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

// destroyAll implements KV v2 hard destruction, not soft deletion. The caller
// must revoke locally BEFORE cleanup and retain a durable tombstone/outbox until
// this succeeds; backup reconciliation must still refuse revoked generations.
func (b *baoCustody) destroyAll(ctx context.Context, ref string) error {
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
	for raw, v := range metadata.Data.Versions {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return ErrUnavailable
		}
		if !v.Destroyed {
			versions = append(versions, n)
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
