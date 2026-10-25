package execenv

import (
	"os"
	"path/filepath"
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
