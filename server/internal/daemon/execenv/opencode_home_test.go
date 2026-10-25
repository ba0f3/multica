package execenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareOpenCodeIsolatedHomeCopiesConfigAndAuthData(t *testing.T) {
	srcConfig := filepath.Join(t.TempDir(), "config", "opencode")
	srcData := filepath.Join(t.TempDir(), "data", "opencode")
	if err := os.MkdirAll(srcConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(srcData, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcConfig, "opencode.json"), []byte(`{"model":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcData, "opencode.db"), []byte("auth database"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("XDG_CONFIG_HOME", filepath.Dir(srcConfig))
	t.Setenv("XDG_DATA_HOME", filepath.Dir(srcData))
	taskHome := t.TempDir()
	if err := prepareOpenCodeIsolatedHome(taskHome, "", nil); err != nil {
		t.Fatalf("prepareOpenCodeIsolatedHome: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(taskHome, ".config", "opencode", "opencode.json"))
	if err != nil {
		t.Fatalf("read copied config: %v", err)
	}
	if string(got) != `{"model":"x"}` {
		t.Fatalf("copied config = %q", string(got))
	}
	got, err = os.ReadFile(filepath.Join(taskHome, ".local", "share", "opencode", "opencode.db"))
	if err != nil {
		t.Fatalf("read copied OpenCode auth database: %v", err)
	}
	if string(got) != "auth database" {
		t.Fatalf("copied OpenCode auth database = %q", got)
	}
}

func TestReuseOpenCodeSeedsMissingHomeAndPreservesSessionData(t *testing.T) {
	source := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(source, "config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(source, "data"))
	for path, content := range map[string]string{
		filepath.Join(source, "config", "opencode", "opencode.json"): `{"model":"x"}`,
		filepath.Join(source, "data", "opencode", "opencode.db"):     "host auth database",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	workDir := filepath.Join(root, "workdir")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	params := ReuseParams{WorkDir: workDir, Provider: "opencode", IsolatedToolBoundary: true}
	if Reuse(params, testLogger()) == nil {
		t.Fatal("Reuse returned nil")
	}
	database := filepath.Join(root, "home", ".local", "share", "opencode", "opencode.db")
	if data, err := os.ReadFile(database); err != nil || string(data) != "host auth database" {
		t.Fatalf("provider switch did not seed auth: data=%q error=%v", data, err)
	}
	if err := os.WriteFile(database, []byte("task session and refreshed auth"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "data", "opencode", "opencode.db-wal"), []byte("host WAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	if Reuse(params, testLogger()) == nil {
		t.Fatal("second Reuse returned nil")
	}
	if data, err := os.ReadFile(database); err != nil || string(data) != "task session and refreshed auth" {
		t.Fatalf("reuse overwrote task sessions: data=%q error=%v", data, err)
	}
	if _, err := os.Stat(database + "-wal"); !os.IsNotExist(err) {
		t.Fatalf("reuse mixed host WAL with task database: %v", err)
	}
}

func TestOpenCodeWorkerExportsCurrentAuthWithoutCopyingSessionDatabase(t *testing.T) {
	source := t.TempDir()
	t.Setenv("HOME", source)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(source, ".config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(source, ".local", "share"))
	executable := filepath.Join(source, "opencode")
	script := "#!/bin/sh\n[ \"$*\" = 'auth export --standalone' ] || exit 9\ncat \"$HOME/export.json\"\n"
	if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	db := filepath.Join(home, ".local", "share", "opencode", "opencode.db")
	if err := os.MkdirAll(filepath.Dir(db), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(db, []byte("existing task sessions"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, credential := range []string{`{"credentials":[{"token":"first"}]}`, `{"credentials":[{"token":"second"}]}`} {
		if err := os.WriteFile(filepath.Join(source, "export.json"), []byte(credential), 0600); err != nil {
			t.Fatal(err)
		}
		if err := prepareOpenCodeIsolatedHome(home, executable, nil); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(root, "opencode-credentials.json"))
		if err != nil || string(data) != credential {
			t.Fatalf("credential export not refreshed: %q %v", data, err)
		}
		data, err = os.ReadFile(db)
		if err != nil || string(data) != "existing task sessions" {
			t.Fatalf("task database changed: %q %v", data, err)
		}
	}
}

func TestOpenCodeCredentialExportRejectsInvalidOutputWithoutLeakingSecrets(t *testing.T) {
	for _, body := range []string{"echo SECRET-TOKEN; exit 1", "echo SECRET-TOKEN"} {
		cli := filepath.Join(t.TempDir(), "opencode")
		if err := os.WriteFile(cli, []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
			t.Fatal(err)
		}
		err := exportOpenCodeCredentials(cli, filepath.Join(t.TempDir(), "credentials.json"))
		if err == nil || strings.Contains(err.Error(), "SECRET-TOKEN") {
			t.Fatalf("unsafe export error=%v", err)
		}
	}
}
