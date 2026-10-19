package sourceguard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestQueuedRetriesAndRedirectsCheckCurrentPolicy(t *testing.T) {
	var blocked atomic.Bool
	var calls atomic.Int32
	Install(func(context.Context) error {
		if blocked.Load() {
			return ErrUnavailable
		}
		return nil
	})
	defer Install(nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/redirect" {
			blocked.Store(true)
			http.Redirect(w, r, "/source", 307)
			return
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	request := func(path string) *http.Request {
		r, err := http.NewRequest("POST", server.URL+path, strings.NewReader("synthetic historical payload"))
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// A request built before revocation cannot use that earlier decision later.
	queued := request("/source")
	response, err := Do(server.Client(), request("/source"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	blocked.Store(true)
	if _, err = Do(server.Client(), queued); err == nil {
		t.Fatal("queued source escaped")
	}
	if calls.Load() != 1 {
		t.Fatal("blocked request reached peer")
	}
	blocked.Store(false)
	if _, err = Do(server.Client(), request("/redirect")); err == nil {
		t.Fatal("redirect reused stale permission")
	}
	if calls.Load() != 2 {
		t.Fatal("redirect forwarded historical payload after revocation")
	}
}
