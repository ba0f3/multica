package sandbox

import "strings"

// IsolatedToolProviders are the only runtimes supported inside the protected
// tool boundary for Git security MVP.
var IsolatedToolProviders = map[string]bool{
	"codex":       true,
	"cursor":      true,
	"opencode":    true,
	"claude":      true,
	"antigravity": true,
}

// ProviderSupportsIsolatedTools reports whether a provider may run inside the
// Docker/bwrap worker boundary.
func ProviderSupportsIsolatedTools(provider string) bool {
	return IsolatedToolProviders[strings.ToLower(strings.TrimSpace(provider))]
}

// ProviderRequiresDockerBackend reports whether the provider's isolated support
// depends on the Docker task home (config/credentials seeded into the
// per-task home). bwrap keeps its host-home policy, so these providers are
// refused there rather than running without auth.
func ProviderRequiresDockerBackend(provider string) bool {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "claude", "antigravity":
		return true
	default:
		return false
	}
}
