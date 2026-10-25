//go:build linux

package sandbox

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func nativeELFFixture(t *testing.T) (NativeRuntimeRequest, string, string) {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler is required for ELF metadata fixtures")
	}
	home := t.TempDir()
	prefix := filepath.Join(home, "brew")
	libDir := filepath.Join(prefix, "Cellar", "fixture", "1", "lib")
	node := filepath.Join(prefix, "Cellar", "node", "1", "bin", "node")
	loader := filepath.Join(prefix, "lib", "ld.so")
	for _, dir := range []string{libDir, filepath.Dir(node), filepath.Dir(loader), filepath.Join(prefix, "opt")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	file, err := elf.Open("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	var systemLoader string
	for _, p := range file.Progs {
		if p.Type == elf.PT_INTERP {
			data := make([]byte, p.Filesz)
			_, _ = p.ReadAt(data, 0)
			systemLoader = strings.TrimRight(string(data), "\x00")
		}
	}
	_ = file.Close()
	if systemLoader == "" {
		t.Skip("fixture requires a dynamically linked system shell")
	}
	data, err := os.ReadFile(systemLoader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(loader, data, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "Cellar", "fixture", "1"), filepath.Join(prefix, "opt", "fixture")); err != nil {
		t.Fatal(err)
	}
	compile := func(name, source string, args ...string) {
		t.Helper()
		path := filepath.Join(home, name+".c")
		_ = os.WriteFile(path, []byte(source), 0600)
		if output, err := exec.Command(cc, append([]string{path}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("compile fixture: %v: %s", err, output)
		}
	}
	compile("dependency", "int dependency(void){return 7;}", "-shared", "-fPIC", "-Wl,-soname,libdependency.so.1", "-o", filepath.Join(libDir, "libdependency.so.1"))
	compile("fixture", "extern int dependency(void); int fixture(void){return dependency();}", "-shared", "-fPIC", "-Wl,-soname,libfixture.so.1", "-Wl,-rpath,$ORIGIN", "-L"+libDir, "-l:libdependency.so.1", "-o", filepath.Join(libDir, "libfixture.so.1"))
	compile("node", "#include <stdio.h>\nextern int fixture(void); int main(void){printf(\"0.6.%d\\n\",fixture());return 0;}", "-Wl,--dynamic-linker,"+loader, "-Wl,--disable-new-dtags", "-Wl,-rpath,"+filepath.Join(prefix, "opt", "fixture", "lib"), "-L"+libDir, "-l:libfixture.so.1", "-Wl,-rpath-link,"+libDir, "-o", node)
	return NativeRuntimeRequest{Provider: "mcode", Home: home, Executable: node}, loader, libDir
}

func TestNativeELFCollectsOriginalLoaderAndTransitiveRunpaths(t *testing.T) {
	request, loader, libDir := nativeELFFixture(t)
	result := NativeRuntime{}
	var watch []nativeWatch
	if err := resolveNativeELF(request, request.Executable, &result, &watch); err != nil {
		t.Fatal(err)
	}
	sources := map[string]bool{}
	for _, mount := range result.ReadOnly {
		if !mount.ReadOnly || mount.Source != mount.Target {
			t.Fatalf("dependency identity changed: %+v", mount)
		}
		sources[mount.Source] = true
	}
	canonicalLoader, _ := filepath.EvalSymlinks(loader)
	for _, path := range []string{canonicalLoader, filepath.Join(libDir, "libfixture.so.1"), filepath.Join(libDir, "libdependency.so.1")} {
		if !sources[path] {
			t.Errorf("original ELF dependency missing: %s", path)
		}
	}
	found := false
	for _, link := range result.Links {
		found = found || strings.HasSuffix(link.Path, "/opt/fixture")
	}
	if !found {
		t.Fatal("library alias was not preserved")
	}
}
