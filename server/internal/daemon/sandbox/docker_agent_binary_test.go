package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/multica-ai/multica/server/pkg/agent"
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

func TestDockerAgentBinaryBindRequiresPath(t *testing.T) {
	if _, _, err := DockerAgentBinaryBind(""); err == nil {
		t.Fatal("expected a clear error for an empty executable path")
	}
}

func TestDockerCursorAgentBindsWholeInstallation(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"cursor-agent", "node", "index.js"} {
		mode := os.FileMode(0o644)
		if name != "index.js" {
			mode = 0o755
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("test"), mode); err != nil {
			t.Fatal(err)
		}
	}
	containerExec, bind, err := DockerCursorAgentBinds(filepath.Join(dir, "cursor-agent"))
	if err != nil {
		t.Fatalf("DockerCursorAgentBinds: %v", err)
	}
	if containerExec != "/usr/local/lib/multica/cursor-agent/cursor-agent" {
		t.Fatalf("container exec = %q", containerExec)
	}
	if want := dir + ":/usr/local/lib/multica/cursor-agent:ro"; bind != want {
		t.Fatalf("bind = %q, want %q", bind, want)
	}
}

func TestProviderUsesDockerAgentBinary(t *testing.T) {
	supported := append([]string{"omp"}, agent.SupportedTypes...)
	for _, provider := range supported {
		if !ProviderUsesDockerAgentBinary(provider) {
			t.Fatalf("expected %q to use docker agent binary bind", provider)
		}
	}
	for _, provider := range []string{"", "nonsense"} {
		if ProviderUsesDockerAgentBinary(provider) {
			t.Fatalf("expected %q not to use docker agent binary bind", provider)
		}
	}
}
