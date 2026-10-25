package sandbox

import (
	"strings"
	"testing"

	"github.com/multica-ai/multica/server/pkg/agent"
)

// allSupportedProviders is every provider the isolated tool boundary admits:
// the Multica-supported backends plus the built-in runtime identities.
func allSupportedProviders() []string {
	return append([]string{"omp"}, agent.SupportedTypes...)
}

func TestProviderSupportsIsolatedTools(t *testing.T) {
	for _, provider := range allSupportedProviders() {
		if !ProviderSupportsIsolatedTools(provider) {
			t.Fatalf("expected %q to be supported", provider)
		}
		if !ProviderSupportsIsolatedTools(strings.ToUpper(provider)) {
			t.Fatalf("expected %q (uppercased) to be supported", provider)
		}
	}
	for _, provider := range []string{"", "nonsense"} {
		if ProviderSupportsIsolatedTools(provider) {
			t.Fatalf("expected %q to be unsupported", provider)
		}
	}
}

func TestProviderRequiresDockerBackend(t *testing.T) {
	bwrap := map[string]bool{"codex": true, "cursor": true, "opencode": true}
	for _, provider := range allSupportedProviders() {
		want := !bwrap[provider]
		if got := ProviderRequiresDockerBackend(provider); got != want {
			t.Fatalf("ProviderRequiresDockerBackend(%q) = %v, want %v", provider, got, want)
		}
		if got := ProviderRequiresDockerBackend(strings.ToUpper(provider)); got != want {
			t.Fatalf("ProviderRequiresDockerBackend(%q uppercased) = %v, want %v", provider, got, want)
		}
	}
}

func TestProviderRequiresDockerBackendRejectsUnknown(t *testing.T) {
	for _, provider := range []string{"", "nonsense"} {
		if ProviderRequiresDockerBackend(provider) {
			t.Fatalf("expected unknown provider %q not to require docker", provider)
		}
	}
}
