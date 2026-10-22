package execenv

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareOpenCodeIsolatedHomeCopiesConfig(t *testing.T) {
	srcConfig := filepath.Join(t.TempDir(), "config", "opencode")
	if err := os.MkdirAll(srcConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcConfig, "opencode.json"), []byte(`{"model":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("XDG_CONFIG_HOME", filepath.Dir(srcConfig))
	taskHome := t.TempDir()
	if err := prepareOpenCodeIsolatedHome(taskHome, nil); err != nil {
		t.Fatalf("prepareOpenCodeIsolatedHome: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(taskHome, ".config", "opencode", "opencode.json"))
	if err != nil {
		t.Fatalf("read copied config: %v", err)
	}
	if string(got) != `{"model":"x"}` {
		t.Fatalf("copied config = %q", string(got))
	}
}
