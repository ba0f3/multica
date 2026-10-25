package sandbox

import (
	"strings"

	"github.com/multica-ai/multica/server/pkg/agent"
)

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

// ProviderRequiresDockerBackend reports whether the provider's isolated support
// depends on the Docker task home (config/credentials seeded into the
// per-task home). Only the legacy bwrap set — codex, cursor, opencode — keeps
// its host-home policy; every other supported provider is seeded into the
// per-task home and refused on bwrap rather than running without auth.
func ProviderRequiresDockerBackend(provider string) bool {
	if !ProviderSupportsIsolatedTools(provider) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "codex", "cursor", "opencode":
		return false
	default:
		return true
	}
}
