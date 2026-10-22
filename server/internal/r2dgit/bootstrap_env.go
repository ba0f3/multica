package r2dgit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
)

// SeededGitHubProviderID matches migration 900117 so env bootstrap updates the
// default GitHub row instead of creating a second one.
const SeededGitHubProviderID = "a0000000-0000-4000-8000-000000000001"

// ProviderSpec is one Git SSH endpoint allowed on this deployment.
type ProviderSpec struct {
	Kind  string
	Host  string
	Port  int
	Label string
}

// ParseGitProvidersEnv reads MULTICA_GIT_PROVIDERS.
//
// Comma-separated entries:
//
//	github
//	gitea:git.example.com
//	gitea:git.example.com:2222
func ParseGitProvidersEnv(raw string) ([]ProviderSpec, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var out []ProviderSpec
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		spec, err := parseProviderEntry(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, spec)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("MULTICA_GIT_PROVIDERS is empty after parsing")
	}
	return out, nil
}

func parseProviderEntry(entry string) (ProviderSpec, error) {
	kind := strings.ToLower(strings.TrimSpace(entry))
	host := ""
	port := 22

	if strings.Contains(kind, ":") {
		parts := strings.SplitN(kind, ":", 3)
		kind = strings.TrimSpace(parts[0])
		if len(parts) < 2 || strings.TrimSpace(parts[1]) == "" {
			return ProviderSpec{}, fmt.Errorf("invalid git provider entry %q", entry)
		}
		host = strings.TrimSpace(strings.ToLower(parts[1]))
		if len(parts) == 3 && strings.TrimSpace(parts[2]) != "" {
			parsed, err := strconv.Atoi(strings.TrimSpace(parts[2]))
			if err != nil || parsed <= 0 || parsed >= 65536 {
				return ProviderSpec{}, fmt.Errorf("invalid port in git provider entry %q", entry)
			}
			port = parsed
		}
	}

	switch kind {
	case "github":
		if host == "" {
			host = "github.com"
		} else if host != "github.com" {
			return ProviderSpec{}, fmt.Errorf("github entry must be %q or github:github.com", entry)
		}
		return ProviderSpec{Kind: "github", Host: host, Port: port, Label: "GitHub"}, nil
	case "gitea":
		if host == "" {
			return ProviderSpec{}, fmt.Errorf("gitea entry needs a host: gitea:example.com")
		}
		label := host
		if port != 22 {
			label = fmt.Sprintf("%s:%d", host, port)
		}
		return ProviderSpec{Kind: "gitea", Host: host, Port: port, Label: label}, nil
	default:
		return ProviderSpec{}, fmt.Errorf("unknown git provider kind %q in %q", kind, entry)
	}
}

func providerKey(kind, host string, port int) string {
	return strings.ToLower(kind) + "\x00" + strings.ToLower(host) + "\x00" + strconv.Itoa(port)
}

// BootstrapProvidersFromEnv syncs r2d_git_provider from MULTICA_GIT_PROVIDERS.
//
// Each listed provider is enabled with fresh SSH host key pins (scanned from this
// process). Every other provider row is disabled. When raw is empty, the table is
// left unchanged.
func BootstrapProvidersFromEnv(ctx context.Context, store Store, newID func() string, raw string) error {
	specs, err := ParseGitProvidersEnv(raw)
	if err != nil {
		return err
	}
	if specs == nil {
		return nil
	}
	if newID == nil {
		newID = func() string { return "" }
	}

	wanted := map[string]struct{}{}
	for _, spec := range specs {
		wanted[providerKey(spec.Kind, spec.Host, spec.Port)] = struct{}{}

		pins := defaultHostPinsForProvider(spec.Kind, spec.Host)
		if len(pins) == 0 {
			discovered, err := DiscoverSSHHostKeys(ctx, spec.Host, spec.Port)
			if err != nil {
				slog.Warn("git credentials: could not scan SSH host keys",
					"kind", spec.Kind, "host", spec.Host, "port", spec.Port, "error", err)
				continue
			}
			pins = discovered
		}
		if _, err := pinnedHostKeyCallback(pins); err != nil {
			slog.Warn("git credentials: host key pins rejected",
				"kind", spec.Kind, "host", spec.Host, "port", spec.Port, "error", err)
			continue
		}

		existing, err := store.GetProviderByKindHostPort(ctx, spec.Kind, spec.Host, spec.Port)
		switch {
		case err == nil:
			existing.Label = spec.Label
			existing.HostPins = pins
			existing.Enabled = true
			if _, err := store.UpdateProvider(ctx, existing); err != nil {
				return err
			}
		case errors.Is(err, ErrScope):
			id := newID()
			if spec.Kind == "github" && spec.Host == "github.com" && spec.Port == 22 {
				id = SeededGitHubProviderID
			}
			if strings.TrimSpace(id) == "" {
				return fmt.Errorf("git provider bootstrap needs an id generator")
			}
			_, err = store.CreateProvider(ctx, Provider{
				ID:       id,
				Label:    spec.Label,
				Kind:     spec.Kind,
				Host:     spec.Host,
				Port:     spec.Port,
				HostPins: pins,
				Enabled:  true,
			})
			if err != nil {
				return err
			}
		default:
			return err
		}
	}

	all, err := store.ListAllProviders(ctx)
	if err != nil {
		return err
	}
	for _, provider := range all {
		if _, ok := wanted[providerKey(provider.Kind, provider.Host, provider.Port)]; ok {
			continue
		}
		if !provider.Enabled {
			continue
		}
		provider.Enabled = false
		if _, err := store.UpdateProvider(ctx, provider); err != nil {
			return err
		}
	}
	return nil
}
