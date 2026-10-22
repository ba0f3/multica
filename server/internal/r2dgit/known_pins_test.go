package r2dgit

import "testing"

func TestDefaultHostPinsForGitHub(t *testing.T) {
	pins := defaultHostPinsForProvider("github", "github.com")
	if len(pins) != len(DefaultGitHubHostPins) {
		t.Fatalf("pins = %d, want %d", len(pins), len(DefaultGitHubHostPins))
	}
	if defaultHostPinsForProvider("gitea", "github.com") != nil {
		t.Fatal("expected no default pins for gitea on github.com")
	}
}
