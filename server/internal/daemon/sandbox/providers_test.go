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

func TestProviderSupportsNativeHost(t *testing.T) {
	admitted := map[string]bool{"codex": true, "cursor": true, "opencode": true, "mcode": true}
	for _, provider := range append(allSupportedProviders(), "", "nonsense") {
		if got := ProviderSupportsNativeHost(provider); got != admitted[provider] {
			t.Fatalf("native %q=%v", provider, got)
		}
	}
}
