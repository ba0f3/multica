package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMcodeAuthMountPreservesIdentityAndPrivateSessions(t *testing.T) {
	source := t.TempDir()
	home := t.TempDir()
	binds, env, err := DockerMcodeAuthBinds(home, source)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{DockerBind(home, filepath.Dir(source), "rw"), DockerBind(filepath.Join(home, ".minimax"), source, "rw"), DockerBind(filepath.Join(source, "auth"), filepath.Join(source, "auth"), "rw")}
	if len(binds) != len(want) {
		t.Fatalf("binds=%v", binds)
	}
	for i, b := range binds {
		if b != want[i] {
			t.Fatalf("bind[%d]=%q want %q", i, b, want[i])
		}
	}
	for _, key := range []string{"MINIMAX_DATA_DIR", "MAVIS_DATA_DIR"} {
		if env[key] != source {
			t.Fatalf("%s changed credential namespace", key)
		}
	}
	if err := os.WriteFile(filepath.Join(source, "host-session"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".minimax", "host-session")); !os.IsNotExist(err) {
		t.Fatal("host runtime state exposed in task data")
	}
}

func TestMcodeAuthMountRejectsSymlinkAndMissingProfileIdentity(t *testing.T) {
	source := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(source, "auth")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{source, "", "relative", "/"} {
		if _, _, err := DockerMcodeAuthBinds(t.TempDir(), path); err == nil {
			t.Fatalf("accepted unsafe profile %q", path)
		}
	}
}

func TestMcodeMigrationLockParentIsPrivateAndWritable(t *testing.T) {
	home := t.TempDir()
	profile := filepath.Join(t.TempDir(), ".minimax")
	binds, _, err := DockerMcodeAuthBinds(home, profile)
	if err != nil {
		t.Fatal(err)
	}
	want := DockerBind(home, filepath.Dir(profile), "rw")
	found := false
	for _, bind := range binds {
		if bind == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("MCode cannot create its sibling migration lock: missing private parent mount %q; binds=%v", want, binds)
	}
}
