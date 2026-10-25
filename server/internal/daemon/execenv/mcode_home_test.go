package execenv

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMcodeHomeDoesNotForkRotatingCredentials(t *testing.T) {
	host := t.TempDir()
	t.Setenv("HOME", host)
	t.Setenv("MINIMAX_DATA_DIR", "")
	t.Setenv("MAVIS_DATA_DIR", "")
	source := filepath.Join(host, ".minimax")
	for path, content := range map[string]string{
		"auth/prod/en/mcode-public/auth.json":       "rotating credential",
		"auth/prod/en/mcode-public/auth-state.json": "authenticated",
		"v2/sqlite/runtime-state.db":                "host runtime database",
		"config.yaml":                               "model: minimax",
		"preferences/mcode-region.json":             `{"region":"en"}`,
		"v2/sessions/host-session.json":             "host history",
	} {
		target := filepath.Join(source, path)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		home := t.TempDir()
		staleLock := filepath.Join(home, ".minimax.lock")
		if err := os.Mkdir(staleLock, 0700); err != nil {
			t.Fatal(err)
		}
		staleAuth := filepath.Join(home, ".minimax", "auth")
		if err := os.MkdirAll(staleAuth, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(staleAuth, "auth.json"), []byte("obsolete task token"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := prepareGenericProviderHome("mcode", home, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(staleLock); !os.IsNotExist(err) {
			t.Fatalf("stale migration lock survived prepare: %v", err)
		}
		if _, err := os.Stat(filepath.Join(home, ".minimax", "v2")); !os.IsNotExist(err) {
			t.Fatalf("host runtime state copied: %v", err)
		}
		if _, err := os.Stat(filepath.Join(home, ".minimax", "auth")); !os.IsNotExist(err) {
			t.Fatalf("task received a fork of rotating auth: %v", err)
		}
		if _, err := os.Stat(filepath.Join(home, ".minimax", "v2", "sessions")); !os.IsNotExist(err) {
			t.Fatalf("task received unrelated host history: %v", err)
		}
		if _, err := os.Stat(filepath.Join(home, ".minimax", "config.yaml")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMcodeDataDirHonorsNativeOverride(t *testing.T) {
	host := t.TempDir()
	custom := t.TempDir()
	t.Setenv("HOME", host)
	t.Setenv("MINIMAX_DATA_DIR", custom)
	t.Setenv("MAVIS_DATA_DIR", "")
	got, err := resolveMcodeDataDir()
	if err != nil || got != custom {
		t.Fatalf("source=%q err=%v", got, err)
	}
	if err := os.WriteFile(filepath.Join(custom, "config.yaml"), []byte("custom"), 0600); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if err := prepareGenericProviderHome("mcode", home, nil); err != nil {
		t.Fatal(err)
	}
	gotData, err := os.ReadFile(filepath.Join(home, ".minimax", "config.yaml"))
	if err != nil || string(gotData) != "custom" {
		t.Fatalf("config=%q err=%v", gotData, err)
	}
}

func TestMcodeStaleAuthCleanupCannotFollowTaskSymlinks(t *testing.T) {
	host := t.TempDir()
	t.Setenv("HOME", host)
	t.Setenv("MINIMAX_DATA_DIR", "")
	t.Setenv("MAVIS_DATA_DIR", "")
	outside := t.TempDir()
	auth := filepath.Join(outside, "auth")
	if err := os.Mkdir(auth, 0700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(auth, "auth.json")
	if err := os.WriteFile(secret, []byte("outside credential"), 0600); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, ".minimax")); err != nil {
		t.Fatal(err)
	}
	if err := prepareGenericProviderHome("mcode", home, nil); err == nil {
		t.Fatal("followed a task symlink outside HOME")
	}
	data, err := os.ReadFile(secret)
	if err != nil || string(data) != "outside credential" {
		t.Fatalf("cleanup changed external credentials: %q %v", data, err)
	}
}

func TestMcodeReusePreservesTaskRuntimeAndHostMigrationLock(t *testing.T) {
	host := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", host)
	t.Setenv("MINIMAX_DATA_DIR", "")
	t.Setenv("MAVIS_DATA_DIR", "")
	hostLock := filepath.Join(host, ".minimax.lock")
	taskLock := filepath.Join(home, ".minimax.lock")
	for _, lock := range []string{hostLock, taskLock} {
		if err := os.Mkdir(lock, 0700); err != nil {
			t.Fatal(err)
		}
	}
	relative := filepath.Join(".minimax", "v2", "sqlite", "runtime-state.db")
	for root, content := range map[string]string{host: "host runtime", home: "task session history"} {
		path := filepath.Join(root, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := prepareGenericProviderHome("mcode", home, nil); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(home, relative)); err != nil || string(data) != "task session history" {
		t.Fatalf("task runtime changed: %q %v", data, err)
	}
	if _, err := os.Stat(hostLock); err != nil {
		t.Fatalf("host process lock changed: %v", err)
	}
	if _, err := os.Stat(taskLock); !os.IsNotExist(err) {
		t.Fatalf("stale task migration lock retained: %v", err)
	}
}
