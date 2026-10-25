//go:build linux

package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNativeNetworkPreservesSymlinkedResolverFileOnly(t *testing.T) {
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	target := filepath.Join(root, "run", "systemd", "resolve", "stub-resolv.conf")
	for _, dir := range []string{etc, filepath.Dir(target)} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(target, []byte("nameserver 127.0.0.53\n"), 0600); err != nil {
		t.Fatal(err)
	}
	resolver := filepath.Join(etc, "resolv.conf")
	if err := os.Symlink(filepath.Join("..", "run", "systemd", "resolve", "stub-resolv.conf"), resolver); err != nil {
		t.Fatal(err)
	}
	mounts, err := runtimeNetworkMounts([]string{resolver})
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 1 || mounts[0].Source != target || mounts[0].Target != target || !mounts[0].ReadOnly {
		t.Fatalf("resolver grant must name exactly its canonical file: %+v", mounts)
	}
}

func TestNativeNetworkRejectsUnavailableOrDirectoryResolver(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{root, filepath.Join(root, "absent")} {
		if _, err := runtimeNetworkMounts([]string{path}); err == nil {
			t.Fatalf("invalid resolver accepted: %s", path)
		}
	}
}

func TestNativeNetworkPinsRegularResolverFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(file, []byte("nameserver 127.0.0.53\n"), 0600); err != nil {
		t.Fatal(err)
	}
	mounts, err := runtimeNetworkMounts([]string{file})
	if err != nil || len(mounts) != 1 || mounts[0].Source != file || !mounts[0].ReadOnly {
		t.Fatalf("regular resolver file grant: %+v, %v", mounts, err)
	}
}
