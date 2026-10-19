package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/multica-ai/multica/server/internal/sourceguard"
	"github.com/resend/resend-go/v2"
)

func TestGuardedMailClientPreservesNormalizationAndChecksActualTransport(t *testing.T) {
	t.Setenv("RESEND_API_KEY", "  'synthetic-mail-key'  ")
	t.Setenv("SMTP_HOST", "")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer synthetic-mail-key" {
			t.Error("mail SDK normalization lost")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"synthetic-mail"}`))
	}))
	defer server.Close()
	service := NewEmailService()
	base, err := url.Parse(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	service.client.BaseURL = base
	payload := &resend.SendEmailRequest{From: "synthetic@fixture.invalid", To: []string{"reader@fixture.invalid"}, Subject: "synthetic", Html: "synthetic historical name"}
	if _, err := service.client.Emails.Send(payload); err != nil {
		t.Fatal(err)
	}
	sourceguard.Install(func(context.Context) error { return sourceguard.ErrUnavailable })
	defer sourceguard.Install(nil)
	if _, err := service.client.Emails.Send(payload); err == nil {
		t.Fatal("SDK request bypassed source hold")
	}
	if calls.Load() != 1 {
		t.Fatal("held body reached peer")
	}
}
