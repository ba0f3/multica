// Package sourceguard closes legacy deliveries whose historical inputs have no
// sealed provenance. The application installs its primary policy before workers
// start. This guard is independent of the selected protected provider transport.
package sourceguard

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

var ErrUnavailable = errors.New("git_legacy_source_unavailable")
var policy struct {
	sync.RWMutex
	check func(context.Context) error
}

// Install is application composition, never a request-controlled switch.
func Install(check func(context.Context) error) { policy.Lock(); policy.check = check; policy.Unlock() }
func Check(ctx context.Context) error {
	policy.RLock()
	check := policy.check
	policy.RUnlock()
	if check == nil {
		return nil
	} // Unconfigured library; production installs before workers.
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if check(ctx) != nil {
		return ErrUnavailable
	}
	return nil
}

type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

func Do(client Doer, request *http.Request) (*http.Response, error) {
	if err := Check(request.Context()); err != nil {
		return nil, err
	}
	if c, ok := client.(*http.Client); ok {
		return HTTPClient(c).Do(request)
	}
	return client.Do(request)
}

type transport struct{ base http.RoundTripper }

func (t transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := Check(r.Context()); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(r)
}

// Clone the client so queued retries and redirects check the current policy at
// the actual network boundary without mutating a shared caller transport.
func HTTPClient(client *http.Client) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	copy := *client
	base := copy.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	if _, ok := base.(transport); !ok {
		copy.Transport = transport{base}
	}
	return &copy
}

type guardedClient struct{ base Doer }

func (c guardedClient) Do(r *http.Request) (*http.Response, error) { return Do(c.base, r) }
func Client(client Doer) Doer {
	if c, ok := client.(*http.Client); ok {
		return HTTPClient(c)
	}
	return guardedClient{client}
}
