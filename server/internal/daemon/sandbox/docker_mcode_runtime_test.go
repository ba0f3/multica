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

func TestDockerMcodeContainerAgentBindSelectsCompatibleNode(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(binDir, "mcode")
	contents := "#!/bin/sh\nroot=$(CDPATH= cd -- \"$(dirname -- \"$0\")/..\" && pwd -P)\nrelease=$(tr -d '\\r\\n' < \"$root/current\")\nexec \"$root/releases/$release/.mcode-launcher\" \"$@\"\n"
	if err := os.WriteFile(launcher, []byte(contents), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "releases", "1.2.3", "lib", "node_modules", "@minimax-ai", "code"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "current"), []byte("1.2.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "releases", "1.2.3", ".mcode-launcher"), []byte("#!/bin/sh\nnode='/host-only/node'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	shimPath := filepath.Join(t.TempDir(), "mcode")

	containerExec, binds, handled, err := DockerMcodeContainerAgentBind(launcher, shimPath)
	if err != nil {
		t.Fatalf("DockerMcodeContainerAgentBind: %v", err)
	}
	if !handled {
		t.Fatal("managed MCode installation was not recognized")
	}
	if containerExec != "/usr/local/bin/mcode" {
		t.Fatalf("container executable = %q", containerExec)
	}
	shim, err := os.ReadFile(shimPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(shim), `exec "$node" "$cli" "$@"`) {
		t.Fatalf("container launcher does not execute with the selected Node runtime:\n%s", shim)
	}
	if strings.Contains(string(shim), "/host-only/node") {
		t.Fatalf("container launcher inherited host Node path:\n%s", shim)
	}
	for _, want := range []string{
		"/usr/local/bin/node",
		"/usr/local/lib/multica/node-runtimes/24/node",
		"/usr/local/lib/multica/node-runtimes/26/node",
		"new Database(\":memory:\")",
	} {
		if !strings.Contains(string(shim), want) {
			t.Errorf("container launcher does not probe compatible Node runtimes with %q:\n%s", want, shim)
		}
	}
	joined := strings.Join(binds, "\n")
	for _, want := range []string{
		shimPath + ":/usr/local/bin/mcode:ro",
		filepath.Join(root, "current") + ":/usr/local/current:ro",
		filepath.Join(root, "releases") + ":/usr/local/releases:ro",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("MCode container binds missing %q:\n%s", want, joined)
		}
	}
}
