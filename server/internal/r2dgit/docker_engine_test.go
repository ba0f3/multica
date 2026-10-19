package r2dgit

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDockerEngineRejectsRedirectsAndUnconfirmedRemoval(t *testing.T) {
	var followed atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Store(true); w.WriteHeader(204) }))
	defer target.Close()
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer engine.Close()
	d := DockerEngine{Client: engine.Client(), Endpoint: engine.URL}
	if err := d.Remove(context.Background(), "r2d-synthetic"); err == nil || followed.Load() {
		t.Fatal("engine redirect followed or accepted")
	}
	for _, status := range []int{202, 500, 404, 204} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer server.Close()
			err := (DockerEngine{Client: server.Client(), Endpoint: server.URL}).Remove(context.Background(), "r2d-synthetic")
			if (err == nil) != (status == 404 || status == 204) {
				t.Fatalf("unconfirmed remove result %d: %v", status, err)
			}
		})
	}
}

func TestDockerEngineRejectsMalformedResultsAndResourceSubstitution(t *testing.T) {
	for _, body := range []string{`{"Id":`, strings.Repeat("x", (1<<20)+1)} {
		t.Run(body[:1], func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) }))
			defer server.Close()
			if _, err := (DockerEngine{Client: server.Client(), Endpoint: server.URL}).Inspect(context.Background(), "r2d-synthetic"); err == nil {
				t.Fatal("malformed/oversized inspect accepted")
			}
		})
	}
	var called atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called.Store(true); w.WriteHeader(404) }))
	defer server.Close()
	d := DockerEngine{Client: server.Client(), Endpoint: server.URL}
	for _, name := range []string{"../foreign", "r2d-../foreign", "r2d-foreign?force=true", "foreign"} {
		if err := d.Remove(context.Background(), name); !errors.Is(err, ErrScope) {
			t.Fatalf("unsafe resource %q: %v", name, err)
		}
	}
	if called.Load() {
		t.Fatal("resource substitution reached engine")
	}
	if _, err := d.Inspect(context.Background(), "r2d-synthetic"); !errors.Is(err, errWorkloadAbsent) {
		t.Fatal("missing inspect was not distinguished from confirmed removal")
	}
}
