package r2dgit

import (
	"context"
	"strings"
)

// CreateProviderInput is the operator-supplied configuration of one Git SSH host.
type CreateProviderInput struct {
	Label    string
	Kind     string
	Host     string
	Port     int
	HostPins []string
}

// CreateProvider registers a Git SSH host every user on this server may use.
//
// Providers are deployment-scoped, not workspace-scoped: one row serves all
// workspaces on the instance.
func (s *Service) CreateProvider(ctx context.Context, input CreateProviderInput) (PublicProvider, error) {
	if !s.available() {
		return PublicProvider{}, ErrUnavailable
	}
	label := strings.TrimSpace(input.Label)
	host := strings.TrimSpace(strings.ToLower(input.Host))
	kind := strings.TrimSpace(strings.ToLower(input.Kind))
	if label == "" || host == "" || kind == "" {
		return PublicProvider{}, ErrScope
	}
	if kind != "github" && kind != "gitea" {
		return PublicProvider{}, ErrScope
	}
	port := input.Port
	if port <= 0 {
		port = 22
	}
	if port >= 65536 {
		return PublicProvider{}, ErrScope
	}
	pins := normalizeHostPins(input.HostPins)
	if len(pins) == 0 {
		discovered, err := DiscoverSSHHostKeys(ctx, host, port)
		if err != nil {
			return PublicProvider{}, err
		}
		pins = discovered
	}
	if _, err := pinnedHostKeyCallback(pins); err != nil {
		return PublicProvider{}, ErrScope
	}

	existing, err := s.store.ListAllProviders(ctx)
	if err != nil {
		return PublicProvider{}, err
	}
	for _, provider := range existing {
		if strings.EqualFold(provider.Kind, kind) &&
			strings.EqualFold(provider.Host, host) &&
			provider.Port == port {
			return PublicProvider{}, ErrConflict
		}
	}

	created, err := s.store.CreateProvider(ctx, Provider{
		ID:       s.newID(),
		Label:    label,
		Kind:     kind,
		Host:     host,
		Port:     port,
		HostPins: pins,
		Enabled:  true,
	})
	if err != nil {
		return PublicProvider{}, err
	}
	return PublicProvider{
		ID:    created.ID,
		Label: created.Label,
		Kind:  created.Kind,
		Host:  created.Host,
		Port:  created.Port,
	}, nil
}

// DiscoverProviderHostKeys exposes SSH host key fingerprints for the UI.
func (s *Service) DiscoverProviderHostKeys(ctx context.Context, host string, port int) ([]string, error) {
	if !s.available() {
		return nil, ErrUnavailable
	}
	return DiscoverSSHHostKeys(ctx, host, port)
}

func normalizeHostPins(pins []string) []string {
	out := make([]string, 0, len(pins))
	seen := map[string]struct{}{}
	for _, pin := range pins {
		pin = strings.TrimSpace(pin)
		if pin == "" {
			continue
		}
		if _, ok := seen[pin]; ok {
			continue
		}
		seen[pin] = struct{}{}
		out = append(out, pin)
	}
	return out
}
