package sandbox

import (
	"strings"

	"github.com/multica-ai/multica/server/pkg/agent"
)

// ProviderSupportsNativeHost is deliberately narrower than Docker support.
// Each admitted provider requires a verified installation and profile resolver.
func ProviderSupportsNativeHost(provider string) bool {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "codex", "cursor", "opencode":
		return true
	default:
		return false
	}
}

// ProviderSupportsIsolatedTools reports whether a provider may run inside the
// Docker/bwrap worker boundary. A provider is supported when its normalized
// name is a Multica-supported backend (agent.SupportedTypes) or a built-in
// runtime identity (agent.IsBuiltinRuntime). Empty and unknown names are
// refused.
func ProviderSupportsIsolatedTools(provider string) bool {
	name := strings.ToLower(strings.TrimSpace(provider))
	if name == "" {
		return false
	}
	return agent.IsSupportedType(name) || agent.IsBuiltinRuntime(name)
}
