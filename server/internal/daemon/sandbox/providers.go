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
