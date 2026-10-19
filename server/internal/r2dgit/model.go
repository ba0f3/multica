package r2dgit

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// ModelAccount is trusted, per-user deployment configuration. It is never
// accepted from a task, serialized or discovered from an environment/login.
type ModelAccount struct {
	UserID, Model, Token string
	ProjectIDs           []string
	ExpiresAt            time.Time
}

func (ModelAccount) String() string               { return "[protected model authorization]" }
func (ModelAccount) GoString() string             { return "[protected model authorization]" }
func (ModelAccount) MarshalJSON() ([]byte, error) { return nil, ErrScope }

type ResponsesGateway struct {
	endpoint string
	client   *http.Client
	accounts map[string]ModelAccount
	now      func() time.Time
}

func (*ResponsesGateway) String() string   { return "[protected Responses gateway]" }
func (*ResponsesGateway) GoString() string { return "[protected Responses gateway]" }

// NewResponsesGateway allows an operator-selected HTTPS authority only. The
// workload supplies text, not a URL, model, token, tools or conversation ID.
// Client injection is trusted composition (synthetic TLS in tests).
func NewResponsesGateway(endpoint string, client *http.Client, accounts []ModelAccount, now func() time.Time) (*ResponsesGateway, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "/v1/responses" || u.RawQuery != "" || u.Fragment != "" || now == nil || len(accounts) == 0 {
		return nil, ErrUnavailable
	}
	bounded, err := trustedHTTPSClient(client, 25*time.Second, u.Hostname())
	if err != nil {
		return nil, err
	}
	g := &ResponsesGateway{endpoint: endpoint, client: bounded, accounts: map[string]ModelAccount{}, now: now}
	for _, account := range accounts {
		if !nonempty(account.UserID, account.Model, account.Token) || strings.ContainsAny(account.Token, "\r\n") || len(account.Model) > 128 || len(account.ProjectIDs) == 0 || !now().Before(account.ExpiresAt) {
			return nil, ErrPrincipal
		}
		if _, exists := g.accounts[account.UserID]; exists {
			return nil, ErrConflict
		}
		account.ProjectIDs = append([]string(nil), account.ProjectIDs...)
		g.accounts[account.UserID] = account
	}
	return g, nil
}

func (g *ResponsesGateway) Generate(ctx context.Context, op BoundOperation, project, input string) (string, error) {
	if g == nil || !nonempty(op.UserID, op.ContextID, op.TaskID, op.AttemptID, project) || len(input) == 0 || len(input) > 64<<10 || !utf8.ValidString(input) {
		return "", ErrScope
	}
	account, found := g.accounts[op.UserID]
	allowed := false
	for _, id := range account.ProjectIDs {
		if id == project {
			allowed = true
		}
	}
	if !found || !allowed || !g.now().Before(account.ExpiresAt) {
		return "", ErrPrincipal
	}
	ctx, stop := context.WithDeadline(ctx, account.ExpiresAt)
	defer stop()
	payload := struct {
		Model           string `json:"model"`
		Input           string `json:"input"`
		Store           bool   `json:"store"`
		Stream          bool   `json:"stream"`
		MaxOutputTokens int    `json:"max_output_tokens"`
	}{account.Model, input, false, false, 8192}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", ErrScope
	}
	defer clear(raw)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, g.endpoint, bytes.NewReader(raw))
	if err != nil {
		return "", ErrUnavailable
	}
	r.Header.Set("Authorization", "Bearer "+account.Token)
	r.Header.Set("Content-Type", "application/json")
	response, err := g.client.Do(r)
	if err != nil {
		return "", ErrProvider
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
		return "", ErrProvider
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	defer clear(body)
	if err != nil || len(body) > 1<<20 {
		return "", ErrProvider
	}
	var result struct {
		Status string `json:"status"`
		Output []struct {
			Type    string `json:"type"`
			Role    string `json:"role"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if json.Unmarshal(body, &result) != nil || result.Status != "completed" {
		return "", ErrProvider
	}
	var text strings.Builder
	for _, item := range result.Output {
		if item.Type == "reasoning" {
			continue
		}
		if item.Type != "message" || item.Role != "assistant" {
			return "", ErrScope
		}
		for _, part := range item.Content {
			if part.Type != "output_text" || len(part.Text) > (64<<10)-text.Len() {
				return "", ErrScope
			}
			text.WriteString(part.Text)
		}
	}
	if text.Len() == 0 || !utf8.ValidString(text.String()) || ctx.Err() != nil || !g.now().Before(account.ExpiresAt) {
		return "", ErrProvider
	}
	return text.String(), nil
}
