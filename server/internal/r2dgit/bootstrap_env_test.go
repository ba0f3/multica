package r2dgit

import (
	"context"
	"testing"
)

func TestParseGitProvidersEnv(t *testing.T) {
	specs, err := ParseGitProvidersEnv("github, gitea:git.example.com:2222")
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 2 {
		t.Fatalf("specs = %d, want 2", len(specs))
	}
	if specs[0].Kind != "github" || specs[0].Host != "github.com" {
		t.Fatalf("github spec = %+v", specs[0])
	}
	if specs[1].Kind != "gitea" || specs[1].Host != "git.example.com" || specs[1].Port != 2222 {
		t.Fatalf("gitea spec = %+v", specs[1])
	}
}

func TestBootstrapProvidersFromEnvEnablesListedProvider(t *testing.T) {
	store := &fakeStore{
		providers: map[string]Provider{
			"old": {ID: "old", Kind: "gitea", Host: "retired.example.com", Port: 22, Enabled: true},
		},
	}
	pins := defaultHostPinsForProvider("github", "github.com")
	if err := BootstrapProvidersFromEnv(context.Background(), store, func() string { return "new-github-id" }, "github"); err != nil {
		t.Fatal(err)
	}
	var githubEnabled bool
	for _, p := range store.providers {
		if p.Kind == "github" && p.Host == "github.com" && p.Enabled {
			githubEnabled = true
			if len(p.HostPins) != len(pins) {
				t.Fatalf("host pins = %d, want %d", len(p.HostPins), len(pins))
			}
		}
		if p.ID == "old" && p.Enabled {
			t.Fatal("retired provider should be disabled")
		}
	}
	if !githubEnabled {
		t.Fatal("expected github provider enabled")
	}
}
