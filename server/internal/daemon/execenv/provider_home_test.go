package execenv

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrepareClaudeIsolatedHomeCopiesConfigAndSkipsBulkyDirs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	claude := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claude, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(rel, content string) {
		t.Helper()
		path := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".claude/.credentials.json", `{"token":"secret"}`)
	write(".claude/settings.json", `{"theme":"dark"}`)
	write(".claude/projects/p1/conversation.json", "bulky")
	write(".claude/logs/app.log", "bulky")
	write(".claude.json", `{"mcpServers":{}}`)

	taskHome := t.TempDir()
	if err := prepareClaudeIsolatedHome(taskHome, nil); err != nil {
		t.Fatalf("prepareClaudeIsolatedHome: %v", err)
	}

	for _, want := range []string{".claude/.credentials.json", ".claude/settings.json", ".claude.json"} {
		if _, err := os.Stat(filepath.Join(taskHome, want)); err != nil {
			t.Errorf("expected %s to be copied: %v", want, err)
		}
	}
	for _, skip := range []string{".claude/projects", ".claude/logs"} {
		if _, err := os.Stat(filepath.Join(taskHome, skip)); !os.IsNotExist(err) {
			t.Errorf("expected %s to be skipped, found it", skip)
		}
	}
}

func TestPrepareClaudeIsolatedHomeDoesNotOverwriteOnSecondPrepare(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	claude := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claude, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(claude, ".credentials.json"), []byte(`{"token":"host-v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	taskHome := t.TempDir()
	if err := prepareClaudeIsolatedHome(taskHome, nil); err != nil {
		t.Fatalf("first prepareClaudeIsolatedHome: %v", err)
	}
	// The task home refreshes its own credential after the first copy.
	target := filepath.Join(taskHome, ".claude", ".credentials.json")
	if err := os.WriteFile(target, []byte(`{"token":"task-refreshed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// The host credential moves on; a second prepare must not roll it back.
	if err := os.WriteFile(filepath.Join(claude, ".credentials.json"), []byte(`{"token":"host-v2"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareClaudeIsolatedHome(taskHome, nil); err != nil {
		t.Fatalf("second prepareClaudeIsolatedHome: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"token":"task-refreshed"}` {
		t.Fatalf("second prepare overwrote the task credential: %q", string(got))
	}
}

func TestPrepareClaudeIsolatedHomeMissingSourceIsNonFatal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// No ~/.claude and no ~/.claude.json at all.
	taskHome := t.TempDir()
	if err := prepareClaudeIsolatedHome(taskHome, nil); err != nil {
		t.Fatalf("prepareClaudeIsolatedHome with missing source: %v", err)
	}
}

func TestPrepareAntigravityIsolatedHomeCopiesAuthAndBrainSkipsDisposable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	gemini := filepath.Join(home, ".gemini")
	write := func(rel, content string) {
		t.Helper()
		path := filepath.Join(gemini, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("oauth_creds.json", `{"refresh":"r"}`)
	write("antigravity-cli/config.json", `{"model":"g"}`)
	write("antigravity-cli/brain/session-1/transcript.json", "conversation")
	write("antigravity-cli/cache/blob", "disposable")
	write("antigravity-cli/history/log", "disposable")

	taskHome := t.TempDir()
	if err := prepareAntigravityIsolatedHome(taskHome, nil); err != nil {
		t.Fatalf("prepareAntigravityIsolatedHome: %v", err)
	}

	for _, want := range []string{
		".gemini/oauth_creds.json",
		".gemini/antigravity-cli/config.json",
		".gemini/antigravity-cli/brain/session-1/transcript.json",
	} {
		if _, err := os.Stat(filepath.Join(taskHome, want)); err != nil {
			t.Errorf("expected %s to be copied: %v", want, err)
		}
	}
	for _, skip := range []string{".gemini/antigravity-cli/cache", ".gemini/antigravity-cli/history"} {
		if _, err := os.Stat(filepath.Join(taskHome, skip)); !os.IsNotExist(err) {
			t.Errorf("expected %s to be skipped, found it", skip)
		}
	}
}

func TestPrepareAntigravityIsolatedHomeMissingSourceIsNonFatal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	taskHome := t.TempDir()
	if err := prepareAntigravityIsolatedHome(taskHome, nil); err != nil {
		t.Fatalf("prepareAntigravityIsolatedHome with missing source: %v", err)
	}
}

func TestPrepareCursorIsolatedHomeCopiesCLIAuth(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	authDir := filepath.Join(configHome, "cursor")
	if err := os.MkdirAll(authDir, 0o700); err != nil {
		t.Fatal(err)
	}
	authPath := filepath.Join(authDir, "auth.json")
	if err := os.WriteFile(authPath, []byte(`{"accessToken":"test-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	taskHome := t.TempDir()
	if err := prepareCursorIsolatedHome(taskHome, nil); err != nil {
		t.Fatalf("prepareCursorIsolatedHome: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(taskHome, ".config", "cursor", "auth.json"))
	if err != nil {
		t.Fatalf("read copied Cursor auth: %v", err)
	}
	if string(got) != `{"accessToken":"test-token"}` {
		t.Fatalf("copied Cursor auth = %q", got)
	}
}

func TestPrepareClaudeIsolatedHomeHonorsConfigDir(t *testing.T) {
	home := t.TempDir()
	configDir := filepath.Join(t.TempDir(), "custom-claude")
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", configDir)
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, ".credentials.json"), []byte(`{"token":"x"}`), 0o600); err != nil {
		t.Fatalf("write credentials: %v", err)
	}
	taskHome := t.TempDir()
	if err := prepareClaudeIsolatedHome(taskHome, nil); err != nil {
		t.Fatalf("prepareClaudeIsolatedHome: %v", err)
	}
	if _, err := os.Stat(filepath.Join(taskHome, ".claude", ".credentials.json")); err != nil {
		t.Fatalf("credentials from CLAUDE_CONFIG_DIR not copied: %v", err)
	}
}

func TestPrepareGenericProviderHomeCopiesMcodeConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	write := func(rel, content string) {
		t.Helper()
		path := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(".mcode/config.json", `{"token":"secret"}`)
	write(".minimax/credentials.json", `{"key":"k"}`)
	write(".config/mcode/settings.json", `{}`)

	taskHome := t.TempDir()
	if err := prepareGenericProviderHome("mcode", taskHome, nil); err != nil {
		t.Fatalf("prepareGenericProviderHome(mcode): %v", err)
	}

	for _, want := range []string{".mcode/config.json", ".minimax/credentials.json", ".config/mcode/settings.json"} {
		if _, err := os.Stat(filepath.Join(taskHome, want)); err != nil {
			t.Errorf("expected %s to be copied: %v", want, err)
		}
	}
}

func TestPrepareGenericProviderHomeMissingSourceIsNonFatal(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	taskHome := t.TempDir()
	if err := prepareGenericProviderHome("mcode", taskHome, nil); err != nil {
		t.Fatalf("prepareGenericProviderHome with missing source: %v", err)
	}
}

func TestPrepareGenericProviderHomeDoesNotOverwriteOnSecondPrepare(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	mcode := filepath.Join(home, ".mcode")
	if err := os.MkdirAll(mcode, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mcode, "config.json"), []byte(`{"token":"host-v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	taskHome := t.TempDir()
	if err := prepareGenericProviderHome("mcode", taskHome, nil); err != nil {
		t.Fatalf("first prepareGenericProviderHome: %v", err)
	}
	// The task home refreshes its own credential after the first copy.
	target := filepath.Join(taskHome, ".mcode", "config.json")
	if err := os.WriteFile(target, []byte(`{"token":"task-refreshed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// The host credential moves on; a second prepare must not roll it back.
	if err := os.WriteFile(filepath.Join(mcode, "config.json"), []byte(`{"token":"host-v2"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareGenericProviderHome("mcode", taskHome, nil); err != nil {
		t.Fatalf("second prepareGenericProviderHome: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"token":"task-refreshed"}` {
		t.Fatalf("second prepare overwrote the task credential: %q", string(got))
	}
}

func TestPrepareGenericProviderHomeSkipsSockets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets are not available on windows")
	}
	// t.TempDir includes the test name and can exceed Unix socket path limits.
	home, err := os.MkdirTemp("", "mcode-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	t.Setenv("HOME", home)
	minimax := filepath.Join(home, ".minimax")
	runDir := filepath.Join(minimax, "run")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatalf("mkdir minimax run: %v", err)
	}
	if err := os.WriteFile(filepath.Join(minimax, "config.json"), []byte(`{"region":"cn"}`), 0o600); err != nil {
		t.Fatalf("write minimax config: %v", err)
	}
	lease, err := net.Listen("unix", filepath.Join(runDir, "mcode-auth-lease-v1.sock"))
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer lease.Close()

	taskHome := t.TempDir()
	if err := prepareGenericProviderHome("mcode", taskHome, nil); err != nil {
		t.Fatalf("prepareGenericProviderHome: %v", err)
	}
	if _, err := os.Stat(filepath.Join(taskHome, ".minimax", "config.json")); err != nil {
		t.Fatalf("regular config not copied: %v", err)
	}
	if _, err := os.Stat(filepath.Join(taskHome, ".minimax", "run", "mcode-auth-lease-v1.sock")); !os.IsNotExist(err) {
		t.Fatalf("socket should not be copied, stat err = %v", err)
	}
}
