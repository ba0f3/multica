package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerUserMappingRequiresExplicitNumericGroup(t *testing.T) {
	root := t.TempDir()
	if _, err := DockerUserIdentityBinds(root, "1000"); err == nil || !strings.Contains(err.Error(), "UID:GID") {
		t.Fatalf("UID-only override must preserve image identity or fail explicitly, got %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("invalid identity wrote partial files")
	}
}

func TestDockerUserMappingKeepsRequestedIDsAndNamedUsers(t *testing.T) {
	for _, user := range []string{"1002:1002", "0:0", "65532:65532", "node"} {
		t.Run(user, func(t *testing.T) {
			root := t.TempDir()
			binds, err := DockerUserIdentityBinds(root, user)
			if err != nil {
				t.Fatal(err)
			}
			if user == "node" {
				if len(binds) != 0 {
					t.Fatal("named image account was overridden")
				}
				return
			}
			data, err := os.ReadFile(filepath.Join(root, "docker-passwd"))
			if err != nil || !strings.Contains(string(data), "agent:x:"+user+"::/home/agent:/bin/bash") {
				t.Fatalf("numeric identity changed: %v", err)
			}
			if len(binds) != 2 {
				t.Fatal("passwd/group must both be read-only mounts")
			}
			for _, bind := range binds {
				if !strings.HasSuffix(bind, ":ro") {
					t.Fatal("identity file writable in worker")
				}
			}
		})
	}
}
