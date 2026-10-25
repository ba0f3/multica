package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerAgentBinaryBind(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "opencode")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	containerExec, bind, err := DockerAgentBinaryBind(binary)
	if err != nil {
		t.Fatalf("DockerAgentBinaryBind: %v", err)
	}
	if containerExec != "/usr/local/bin/opencode" {
		t.Fatalf("container exec = %q, want /usr/local/bin/opencode", containerExec)
	}
	if !strings.Contains(bind, binary+":/usr/local/bin/opencode:ro") {
		t.Fatalf("bind = %q", bind)
	}
}

func TestProviderUsesDockerAgentBinary(t *testing.T) {
	for _, provider := range []string{"codex", "cursor", "opencode", "claude", "antigravity", "CODEX"} {
		if !ProviderUsesDockerAgentBinary(provider) {
			t.Fatalf("expected %q to use docker agent binary bind", provider)
		}
	}
	if ProviderUsesDockerAgentBinary("hermes") {
		t.Fatal("hermes should not use docker agent binary bind")
	}
}
