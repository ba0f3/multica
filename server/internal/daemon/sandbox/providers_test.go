package sandbox

import "testing"

func TestProviderSupportsIsolatedTools(t *testing.T) {
	for _, provider := range []string{"codex", "cursor", "opencode", "claude", "antigravity", "CODEX"} {
		if !ProviderSupportsIsolatedTools(provider) {
			t.Fatalf("expected %q to be supported", provider)
		}
	}
	for _, provider := range []string{"", "hermes", "pi"} {
		if ProviderSupportsIsolatedTools(provider) {
			t.Fatalf("expected %q to be unsupported", provider)
		}
	}
}

func TestProviderRequiresDockerBackend(t *testing.T) {
	for _, provider := range []string{"claude", "antigravity", "CLAUDE"} {
		if !ProviderRequiresDockerBackend(provider) {
			t.Fatalf("expected %q to require docker", provider)
		}
	}
	for _, provider := range []string{"codex", "cursor", "opencode", ""} {
		if ProviderRequiresDockerBackend(provider) {
			t.Fatalf("expected %q not to require docker", provider)
		}
	}
}
