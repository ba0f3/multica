package telegram

import (
	"context"
	"github.com/multica-ai/multica/server/internal/sourceguard"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestLegacyQueuedTelegramSendChecksSourceHoldAtNetwork(t *testing.T) {
	var held atomic.Bool
	var calls atomic.Int32
	sourceguard.Install(func(context.Context) error {
		if held.Load() {
			return sourceguard.ErrUnavailable
		}
		return nil
	})
	defer sourceguard.Install(nil)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(`{"ok":true,"result":true}`))
	}))
	defer server.Close()
	api := &botAPI{client: server.Client(), base: server.URL, token: "synthetic"}
	payload := map[string]string{"text": "synthetic queued history"}
	if err := api.call(context.Background(), "sendMessage", payload, nil); err != nil {
		t.Fatal(err)
	}
	held.Store(true)
	for i := 0; i < 3; i++ {
		if err := api.call(context.Background(), "sendMessage", payload, nil); err == nil {
			t.Fatal("queued retry escaped hold")
		}
	}
	if calls.Load() != 1 {
		t.Fatal("held queued retry reached peer")
	}
}
