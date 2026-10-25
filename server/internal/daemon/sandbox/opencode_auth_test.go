package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkerOpenCodeCredentialImportUsesPrivateHome(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "credentials.json")
	if err := os.WriteFile(input, []byte(`{"credentials":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(root, "opencode")
	script := "#!/bin/sh\n[ \"$*\" = 'auth import --standalone' ] || exit 5\ncat > \"$HOME/imported.json\"\n"
	if err := os.WriteFile(cli, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	manifest := Manifest{Provider: "opencode", Config: Config{ExecutablePath: cli, Env: map[string]string{"HOME": root, OpenCodeCredentialsEnv: input}}}
	if err := importWorkerOpenCodeCredentials(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "imported.json"))
	if err != nil || string(data) != `{"credentials":[]}` {
		t.Fatalf("imported credential mismatch: %q %v", data, err)
	}
	if err := os.WriteFile(cli, []byte("#!/bin/sh\necho SECRET-CREDENTIAL >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	err = importWorkerOpenCodeCredentials(context.Background(), manifest)
	if err == nil || strings.Contains(err.Error(), "SECRET-CREDENTIAL") {
		t.Fatalf("unsafe import error: %v", err)
	}
}
