package r2dgit

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestResponsesGatewayPerUserAndFixedContract(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var payload map[string]any
		if json.NewDecoder(r.Body).Decode(&payload) != nil || len(payload) != 5 || payload["store"] != false || payload["stream"] != false || payload["max_output_tokens"] != float64(8192) || r.URL.Path != "/v1/responses" {
			t.Error("unbounded upstream contract")
		}
		auth := r.Header.Get("Authorization")
		wantModel := "model-a"
		if auth == "Bearer synthetic-b" {
			wantModel = "model-b"
		} else if auth != "Bearer synthetic-a" {
			t.Error("wrong credential")
		}
		if payload["model"] != wantModel {
			t.Error("cross-user model selection")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "completed", "output": []any{map[string]any{"type": "reasoning"}, map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": wantModel}}}}})
	}))
	defer server.Close()
	now := time.Now()
	accounts := []ModelAccount{{UserID: "a", Model: "model-a", Token: "synthetic-a", ProjectIDs: []string{"project"}, ExpiresAt: now.Add(time.Hour)}, {UserID: "b", Model: "model-b", Token: "synthetic-b", ProjectIDs: []string{"project"}, ExpiresAt: now.Add(time.Hour)}}
	g, err := NewResponsesGateway(server.URL+"/v1/responses", server.Client(), accounts, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	accounts[0].ProjectIDs[0] = "forged"
	for _, user := range []string{"a", "b", "admin"} {
		text, err := g.Generate(context.Background(), BoundOperation{UserID: user, ContextID: "ctx-" + user, TaskID: "task-" + user, AttemptID: "attempt-" + user}, "project", "synthetic source")
		if user == "admin" {
			if err == nil {
				t.Fatal("missing user inherited credential")
			}
		} else if err != nil || text != "model-"+user {
			t.Fatalf("wrong user result: %q %v", text, err)
		}
	}
	if _, err := g.Generate(context.Background(), BoundOperation{UserID: "a", ContextID: "ctx", TaskID: "task", AttemptID: "attempt"}, "foreign", "source"); err == nil {
		t.Fatal("cross-project source accepted")
	}
	if calls.Load() != 2 {
		t.Fatal("unauthorized request reached upstream")
	}
	now = now.Add(2 * time.Hour)
	if _, err := g.Generate(context.Background(), BoundOperation{UserID: "a", ContextID: "ctx", TaskID: "task", AttemptID: "attempt"}, "project", "source"); err == nil {
		t.Fatal("expired account reused")
	}
	if raw, err := json.Marshal(accounts[0]); err == nil || len(raw) != 0 {
		t.Fatal("model authorization serialized")
	}
}

func TestSecretHTTPConstructorsRejectTLSBypasses(t *testing.T) {
	for _, mode := range []string{"insecure", "dial-tls", "dial-tls-context", "hostname"} {
		t.Run(mode, func(t *testing.T) {
			transport := &http.Transport{TLSClientConfig: &tls.Config{}}
			switch mode {
			case "insecure":
				transport.TLSClientConfig.InsecureSkipVerify = true
			case "dial-tls":
				transport.DialTLS = func(string, string) (net.Conn, error) { t.Fatal("direct TLS dial reached"); return nil, ErrUnavailable }
			case "dial-tls-context":
				transport.DialTLSContext = func(context.Context, string, string) (net.Conn, error) {
					t.Fatal("direct TLS dial reached")
					return nil, ErrUnavailable
				}
			case "hostname":
				transport.TLSClientConfig.ServerName = "foreign.invalid"
			}
			client := &http.Client{Transport: transport}
			if _, err := NewResponsesGateway("https://selected.invalid/v1/responses", client, []ModelAccount{{UserID: "a", Model: "synthetic", Token: "synthetic", ProjectIDs: []string{"p"}, ExpiresAt: time.Now().Add(time.Hour)}}, time.Now); err == nil {
				t.Fatal("model constructor accepted TLS bypass")
			}
			if _, err := NewGitHubWritePolicy(&Service{Now: time.Now}, "https://selected.invalid", client, []GitHubPolicyAccount{{UserID: "a", Token: "synthetic", ExpiresAt: time.Now().Add(time.Hour)}}); err == nil {
				t.Fatal("policy constructor accepted TLS bypass")
			}
		})
	}
}

func TestResponsesGatewayRejectsUnsupportedAndUncertainResponses(t *testing.T) {
	for _, mode := range []string{"tool", "refusal", "incomplete", "overflow", "redirect", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "tool":
					io.WriteString(w, `{"status":"completed","output":[{"type":"function_call"}]}`)
				case "refusal":
					io.WriteString(w, `{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"refusal"}]}]}`)
				case "incomplete":
					io.WriteString(w, `{"status":"incomplete","output":[]}`)
				case "overflow":
					io.WriteString(w, strings.Repeat("x", (1<<20)+1))
				case "redirect":
					http.Redirect(w, r, "https://forbidden.invalid", http.StatusTemporaryRedirect)
				case "cancel":
					<-r.Context().Done()
				}
			}))
			defer server.Close()
			g, err := NewResponsesGateway(server.URL+"/v1/responses", server.Client(), []ModelAccount{{UserID: "a", Model: "synthetic", Token: "synthetic-only", ProjectIDs: []string{"p"}, ExpiresAt: time.Now().Add(time.Hour)}}, time.Now)
			if err != nil {
				t.Fatal(err)
			}
			ctx, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer stop()
			if _, err := g.Generate(ctx, BoundOperation{UserID: "a", ContextID: "c", TaskID: "t", AttemptID: "a"}, "p", "source"); err == nil {
				t.Fatal("unsupported upstream result succeeded")
			}
		})
	}
}
