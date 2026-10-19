package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/multica-ai/multica/server/internal/analytics"
	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/daemonws"
	"github.com/multica-ai/multica/server/internal/events"
	"github.com/multica-ai/multica/server/internal/realtime"
	"github.com/multica-ai/multica/server/internal/sourceguard"
)

func TestR2DGitS5ActualRouterAndLiveWebsocketDenyUnknownHistory(t *testing.T) {
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": testUserID, "email": integrationTestEmail, "name": integrationTestName, "sid": "synthetic-s5-session", "auth_time": time.Now().Unix(), "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}).SignedString(auth.JWTSecret())
	if err != nil {
		t.Fatal(err)
	}
	hub := realtime.NewHub()
	go hub.Run()
	bus := events.New()
	router, h := NewRouterWithOptions(testPool, hub, bus, analytics.NoopClient{}, nil, RouterOptions{})
	server := httptest.NewServer(router)
	defer server.Close()
	request := func(method, path string, want int) {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		if res.StatusCode != want {
			t.Fatalf("%s %s: %d %s", method, path, res.StatusCode, raw)
		}
		for _, cookie := range res.Cookies() {
			if strings.HasPrefix(cookie.Name, "CloudFront-") {
				t.Fatal("held route minted source cookie")
			}
		}
	}
	request("GET", "/api/me", 200)
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/ws?workspace_id="+testWorkspaceID, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err = conn.WriteJSON(map[string]any{"type": "auth", "payload": map[string]string{"token": token}}); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, ack, err := conn.ReadMessage()
	if err != nil || !strings.Contains(string(ack), "auth_ack") {
		t.Fatal("WS auth", err, string(ack))
	}
	deadline := time.Now().Add(2 * time.Second)
	for !hub.HasLocalSubscribers(realtime.ScopeWorkspace, testWorkspaceID) {
		if !time.Now().Before(deadline) {
			t.Fatal("authenticated socket did not subscribe")
		}
		time.Sleep(time.Millisecond)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	hub.BroadcastToWorkspace(testWorkspaceID, []byte(`{"type":"synthetic:s5","payload":"before-hold"}`))
	_, positive, err := conn.ReadMessage()
	if err != nil || !strings.Contains(string(positive), "before-hold") {
		t.Fatal("WS positive control", err, string(positive))
	}
	var deliveries atomic.Int32
	bus.Subscribe("synthetic:s5", func(events.Event) { deliveries.Add(1) })
	bus.Publish(events.Event{Type: "synthetic:s5", WorkspaceID: testWorkspaceID})
	if deliveries.Load() != 1 {
		t.Fatal("bus positive")
	}
	if _, err = testPool.Exec(context.Background(), `INSERT INTO r2d_git_source_quarantine(kind,subject_id) VALUES('audience',$1)`, testUserID); err != nil {
		t.Fatal(err)
	}
	defer testPool.Exec(context.Background(), `DELETE FROM r2d_git_source_quarantine WHERE kind='audience' AND subject_id=$1`, testUserID)
	for _, path := range []string{"/api/me", "/api/share-links/synthetic", "/api/search-index/snapshot", "/api/issues/search", "/uploads/users/legacy/history.txt", "/api/config"} {
		request("GET", path, 403)
	}
	request("POST", "/auth/verify-code", 403)
	request("POST", "/auth/google", 403)
	request("GET", "/api/me/git-identities", 200)
	request("GET", "/health", 200)
	if sourceguard.Check(context.Background()) == nil {
		t.Fatal("legacy network guard not composed")
	}
	bus.Publish(events.Event{Type: "synthetic:s5", WorkspaceID: "unrelated-workspace"})
	if deliveries.Load() != 1 {
		t.Fatal("cross-workspace event escaped")
	}
	if code, _, err := h.DaemonRPCHandler(context.Background(), daemonws.ClientIdentity{}, "tasks.claim", nil); code != 403 || err == nil {
		t.Fatal("existing daemon RPC escaped", code, err)
	}
	// Bypass the event bus with a previously captured frame: the actual WS writer
	// still checks current policy before writing it to this existing connection.
	hub.BroadcastToWorkspace(testWorkspaceID, []byte(`{"type":"synthetic:s5","payload":"held-history"}`))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, body, err := conn.ReadMessage()
	if err == nil || strings.Contains(string(body), "held-history") {
		t.Fatal("captured WS frame escaped hold", err, string(body))
	}
}

func TestSourceAuthorityWithoutDatabaseKeepsInstalledPolicy(t *testing.T) {
	var calls atomic.Int32
	sourceguard.Install(func(context.Context) error { calls.Add(1); return nil })
	defer sourceAuthority(testPool, nil)
	sourceAuthority(nil, nil)
	if err := sourceguard.Check(context.Background()); err != nil || calls.Load() != 1 {
		t.Fatal("route-only construction replaced live delivery policy", err, calls.Load())
	}
}
