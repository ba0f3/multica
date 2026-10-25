package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerMcodeRuntimeBindsVersionedInstall(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(binDir, "mcode")
	if err := os.WriteFile(launcher, []byte("#!/bin/sh\nroot=$(CDPATH= cd -- \"$(dirname -- \"$0\")/..\" && pwd -P)\nrelease=$(tr -d '\\r\\n' < \"$root/current\")\nexec \"$root/releases/$release/.mcode-launcher\" \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "releases", "1.2.3"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "current"), []byte("1.2.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "releases", "1.2.3", ".mcode-launcher"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	binds, err := DockerMcodeRuntimeBinds(launcher)
	if err != nil {
		t.Fatalf("DockerMcodeRuntimeBinds: %v", err)
	}
	joined := strings.Join(binds, "\n")
	for _, want := range []string{
		DockerBind(filepath.Join(root, "current"), "/usr/local/current", "ro"),
		DockerBind(filepath.Join(root, "releases"), "/usr/local/releases", "ro"),
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("MCode runtime binds missing %q:\n%s", want, joined)
		}
	}
}

func TestDockerMcodeRuntimeBindsIgnoreUnrelatedExecutable(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "mcode")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec mcode-runtime\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	binds, err := DockerMcodeRuntimeBinds(bin)
	if err != nil {
		t.Fatalf("DockerMcodeRuntimeBinds: %v", err)
	}
	if len(binds) != 0 {
		t.Fatalf("unrelated executable binds = %v, want none", binds)
	}
}
