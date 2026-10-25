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
