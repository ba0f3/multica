package r2dgit

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type GitHubPolicyAccount struct {
	UserID, Token string
	ExpiresAt     time.Time
}

func (GitHubPolicyAccount) String() string               { return "[GitHub policy authorization]" }
func (GitHubPolicyAccount) GoString() string             { return "[GitHub policy authorization]" }
func (GitHubPolicyAccount) MarshalJSON() ([]byte, error) { return nil, ErrScope }

// GitHubWritePolicy supports existing unprotected feature branches. Creating
// a missing branch cannot prove absence of classic protection patterns through
// this REST contract and therefore denies. No PAT/admin fallback is discovered.
type GitHubWritePolicy struct {
	service  *Service
	endpoint string
	client   *http.Client
	accounts map[string]GitHubPolicyAccount
}

func (*GitHubWritePolicy) String() string   { return "[GitHub write policy]" }
func (*GitHubWritePolicy) GoString() string { return "[GitHub write policy]" }

func NewGitHubWritePolicy(s *Service, endpoint string, client *http.Client, accounts []GitHubPolicyAccount) (*GitHubWritePolicy, error) {
	u, err := url.Parse(endpoint)
	if s == nil || u == nil || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || len(accounts) == 0 {
		return nil, ErrUnavailable
	}
	bounded, err := trustedHTTPSClient(client, 5*time.Second, u.Hostname())
	if err != nil {
		return nil, err
	}
	p := &GitHubWritePolicy{service: s, endpoint: endpoint, client: bounded, accounts: map[string]GitHubPolicyAccount{}}
	for _, account := range accounts {
		if !nonempty(account.UserID, account.Token) || strings.ContainsAny(account.Token, "\r\n") || !s.Now().Before(account.ExpiresAt) {
			return nil, ErrPrincipal
		}
		if _, exists := p.accounts[account.UserID]; exists {
			return nil, ErrConflict
		}
		p.accounts[account.UserID] = account
	}
	return p, nil
}

func (p *GitHubWritePolicy) CheckGitWritePolicy(ctx context.Context, op BoundOperation) error {
	account, ok := p.accounts[op.UserID]
	if !ok || !p.service.Now().Before(account.ExpiresAt) || op.Operation != Write || !validWriteRef(op.Ref) {
		return ErrScope
	}
	ctx, stop := context.WithTimeout(ctx, 4*time.Second)
	defer stop()
	target, err := p.service.ResolveGitOperation(ctx, op)
	if err != nil || target.Provider.Kind != "github" || target.Provider.Host != "github.com" {
		return ErrScope
	}
	parts := strings.Split(strings.TrimSuffix(target.Repository, ".git"), "/")
	if len(parts) != 2 || !nonempty(parts[0], parts[1]) {
		return ErrScope
	}
	var accountID, login string
	if err = p.service.Store.DB.QueryRow(ctx, `SELECT k.account_id,k.login FROM r2d_git_identity i JOIN r2d_git_key k ON k.identity_id=i.id AND k.generation=i.active_generation WHERE i.id=$1 AND i.user_id=$2 AND i.active_generation=$3 AND NOT i.revoked AND k.state='ready'`, op.IdentityID, op.UserID, op.Generation).Scan(&accountID, &login); err != nil {
		return ErrIdentity
	}
	get := func(path string, out any) error {
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, p.endpoint+path, nil)
		if err != nil {
			return ErrProvider
		}
		r.Header.Set("Authorization", "Bearer "+account.Token)
		r.Header.Set("Accept", "application/vnd.github+json")
		r.Header.Set("X-GitHub-Api-Version", "2026-03-10")
		response, err := p.client.Do(r)
		if err != nil {
			return ErrProvider
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") || response.Header.Get("Link") != "" {
			return ErrProvider
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
		defer clear(raw)
		if err != nil || len(raw) > 64<<10 || json.Unmarshal(raw, out) != nil {
			return ErrProvider
		}
		return nil
	}
	var who struct {
		ID    uint64 `json:"id"`
		Login string `json:"login"`
	}
	if get("/user", &who) != nil || who.ID == 0 || (accountID != "" && accountID != strconv.FormatUint(who.ID, 10)) || (accountID == "" && who.Login != login) {
		return ErrIdentity
	}
	base := "/repos/" + url.PathEscape(parts[0]) + "/" + url.PathEscape(parts[1])
	var repository struct {
		DefaultBranch string `json:"default_branch"`
	}
	branch := strings.TrimPrefix(op.Ref, "refs/heads/")
	if get(base, &repository) != nil || repository.DefaultBranch == "" || branch == repository.DefaultBranch {
		return ErrScope
	}
	var metadata struct {
		Name      string `json:"name"`
		Protected *bool  `json:"protected"`
	}
	if get(base+"/branches/"+url.PathEscape(branch), &metadata) != nil || metadata.Name != branch || metadata.Protected == nil || *metadata.Protected {
		return ErrScope
	}
	var rules []json.RawMessage
	if get(base+"/rules/branches/"+url.PathEscape(branch), &rules) != nil || rules == nil || len(rules) != 0 || ctx.Err() != nil || !p.service.Now().Before(account.ExpiresAt) {
		return ErrScope
	}
	return nil
}

func (s *Service) CheckGitWritePolicy(ctx context.Context, op BoundOperation) error {
	if s.WritePolicy == nil {
		return ErrUnavailable
	}
	check := func() error {
		r, g, err := loadRun(ctx, s.Store.DB, op.ContextID, s.Now())
		if err != nil {
			return err
		}
		current, err := s.Current(ctx, r.spec, g.spec)
		if err != nil || !currentIssuable(current, r, g) || r.spec.Binding.OriginatorUserID != op.UserID || r.spec.Binding.TaskID != op.TaskID || r.spec.AttemptID != op.AttemptID || g.spec.IdentityID != op.IdentityID || g.spec.CredentialGeneration != op.Generation || g.spec.RepositoryID != op.RepositoryID || g.spec.ProviderID != op.ProviderID || !hasOp(g.spec, Write) {
			return ErrScope
		}
		for _, ref := range g.spec.WriteRefs {
			if ref == op.Ref {
				return nil
			}
		}
		return ErrScope
	}
	if err := check(); err != nil {
		return err
	}
	if err := s.WritePolicy.CheckGitWritePolicy(ctx, op); err != nil {
		return err
	}
	return check()
}
