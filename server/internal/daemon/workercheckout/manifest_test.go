package workercheckout

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/multica-ai/multica/server/internal/testutil"
)

var (
	validSHA1   = strings.Repeat("a", 40)
	validSHA256 = strings.Repeat("b", 64)
)

func TestManifestPath(t *testing.T) {
	t.Run("task config root", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "task-config")
		t.Setenv("MULTICA_TASK_CONFIG_ROOT", root)

		got, err := ManifestPath()
		if err != nil {
			t.Fatalf("ManifestPath: %v", err)
		}
		if want := filepath.Join(root, ManifestFileName); got != want {
			t.Errorf("ManifestPath() = %q, want %q", got, want)
		}
	})

	t.Run("home fallback", func(t *testing.T) {
		home := t.TempDir()
		testutil.RedirectUserHome(t, home)
		t.Setenv("MULTICA_TASK_CONFIG_ROOT", "")

		got, err := ManifestPath()
		if err != nil {
			t.Fatalf("ManifestPath: %v", err)
		}
		if want := filepath.Join(home, ".multica", ManifestFileName); got != want {
			t.Errorf("ManifestPath() = %q, want %q", got, want)
		}
	})

	t.Run("relative task config root", func(t *testing.T) {
		t.Setenv("MULTICA_TASK_CONFIG_ROOT", filepath.Join("relative", "task-config"))

		if got, err := ManifestPath(); err == nil {
			t.Fatalf("ManifestPath() = %q, want an absolute path error", got)
		}
	})
}

func TestManifestRoundTrip(t *testing.T) {
	cache := newBareCache(t)
	dir := t.TempDir()
	path := filepath.Join(dir, ManifestFileName)
	want := Manifest{Repos: []Entry{
		{
			URL:       "https://example.com/one.git",
			Ref:       "main",
			CommitSHA: validSHA1,
			CachePath: cache,
		},
		{
			URL:       "ssh://git@example.com/two.git",
			CommitSHA: validSHA256,
			CachePath: cache,
		},
	}}

	if err := WriteManifest(path, want); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat manifest: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Errorf("manifest mode = %#o, want 0644", got)
	}

	got, err := ReadManifest(path)
	if err != nil {
		t.Fatalf("ReadManifest: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round-trip manifest = %#v, want %#v", got, want)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read manifest dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != ManifestFileName {
		t.Errorf("manifest dir contains %v, want only %q", entries, ManifestFileName)
	}
}

func TestReadManifestRejectsUnknownField(t *testing.T) {
	cache := newBareCache(t)
	path := writeManifestValue(t, map[string]any{"repos": []map[string]any{{
		"url":        "https://example.com/one.git",
		"commit_sha": validSHA1,
		"cache_path": cache,
		"unexpected": true,
	}}})

	if _, err := ReadManifest(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("ReadManifest error = %v, want an unknown field error", err)
	}
}

func TestReadManifestRejectsRelativeCachePath(t *testing.T) {
	path := writeManifestValue(t, map[string]any{"repos": []map[string]any{{
		"url":        "https://example.com/one.git",
		"commit_sha": validSHA1,
		"cache_path": filepath.Join("relative", "cache.git"),
	}}})

	if _, err := ReadManifest(path); err == nil || !strings.Contains(err.Error(), "cache_path") {
		t.Fatalf("ReadManifest error = %v, want a cache_path validation error", err)
	}
}

func TestReadManifestRejectsTrailingData(t *testing.T) {
	cache := newBareCache(t)
	valid := writeManifestValue(t, map[string]any{"repos": []map[string]any{{
		"url":        "https://example.com/one.git",
		"commit_sha": validSHA1,
		"cache_path": cache,
	}}})
	data, err := os.ReadFile(valid)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	path := writeManifestJSON(t, string(data)+"{}")

	if _, err := ReadManifest(path); err == nil {
		t.Fatal("ReadManifest accepted trailing JSON, want an error")
	}
}

func TestFind(t *testing.T) {
	first := Entry{URL: "https://example.com/a.git", CommitSHA: validSHA1, CachePath: "/cache/a.git"}
	second := Entry{URL: "https://example.com/b.git", CommitSHA: validSHA256, CachePath: "/cache/b.git"}
	manifest := Manifest{Repos: []Entry{first, second}}

	got, err := Find(manifest, first.URL)
	if err != nil {
		t.Fatalf("Find(%q): %v", first.URL, err)
	}
	if !reflect.DeepEqual(got, first) {
		t.Errorf("Find(%q) = %#v, want %#v", first.URL, got, first)
	}

	unknown := "https://example.com/missing.git"
	_, err = Find(manifest, unknown)
	if err == nil {
		t.Fatal("Find accepted an unknown URL, want an error")
	}
	for _, want := range []string{unknown, first.URL, second.URL} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Find error %q does not name %q", err, want)
		}
	}

	duplicate := Entry{URL: first.URL, CommitSHA: validSHA1, CachePath: "/cache/duplicate.git"}
	got, err = Find(Manifest{Repos: []Entry{first, duplicate}}, first.URL)
	if err != nil {
		t.Fatalf("Find duplicate URL: %v", err)
	}
	if !reflect.DeepEqual(got, first) {
		t.Errorf("Find duplicate URL = %#v, want the first entry %#v", got, first)
	}
}

func TestValidateEntry(t *testing.T) {
	t.Run("accepts a real bare repo", func(t *testing.T) {
		cache := newBareCache(t)
		for _, sha := range []string{validSHA1, validSHA256} {
			entry := Entry{URL: "https://example.com/one.git", CommitSHA: sha, CachePath: cache}
			if err := ValidateEntry(entry); err != nil {
				t.Errorf("ValidateEntry(%s) = %v, want nil", sha, err)
			}
		}
	})

	cache := newBareCache(t)
	missingHead := newBareCache(t)
	if err := os.Remove(filepath.Join(missingHead, "HEAD")); err != nil {
		t.Fatalf("remove HEAD: %v", err)
	}
	missingObjects := newBareCache(t)
	if err := os.RemoveAll(filepath.Join(missingObjects, "objects")); err != nil {
		t.Fatalf("remove objects: %v", err)
	}
	notADirectory := filepath.Join(t.TempDir(), "repo.git")
	if err := os.WriteFile(notADirectory, []byte("not a repo"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	missingDirectory := filepath.Join(t.TempDir(), "missing.git")

	tests := []struct {
		name    string
		entry   Entry
		wantErr string
	}{
		{
			name:    "missing cache path",
			entry:   Entry{CommitSHA: validSHA1},
			wantErr: "cache_path",
		},
		{
			name:    "nonexistent cache path",
			entry:   Entry{CommitSHA: validSHA1, CachePath: missingDirectory},
			wantErr: "cache_path",
		},
		{
			name:    "relative cache path",
			entry:   Entry{CommitSHA: validSHA1, CachePath: filepath.Join("relative", "cache.git")},
			wantErr: "absolute",
		},
		{
			name:    "unclean cache path",
			entry:   Entry{CommitSHA: validSHA1, CachePath: cache + string(filepath.Separator) + "nested" + string(filepath.Separator) + ".."},
			wantErr: "clean",
		},
		{
			name:    "cache path is not a directory",
			entry:   Entry{CommitSHA: validSHA1, CachePath: notADirectory},
			wantErr: "not a directory",
		},
		{
			name:    "cache without HEAD",
			entry:   Entry{CommitSHA: validSHA1, CachePath: missingHead},
			wantErr: "HEAD",
		},
		{
			name:    "cache without objects",
			entry:   Entry{CommitSHA: validSHA1, CachePath: missingObjects},
			wantErr: "objects",
		},
		{
			name:    "empty commit sha",
			entry:   Entry{CachePath: cache},
			wantErr: "commit_sha",
		},
		{
			name:    "short commit sha",
			entry:   Entry{CommitSHA: strings.Repeat("a", 39), CachePath: cache},
			wantErr: "commit_sha",
		},
		{
			name:    "long commit sha",
			entry:   Entry{CommitSHA: strings.Repeat("a", 65), CachePath: cache},
			wantErr: "commit_sha",
		},
		{
			name:    "uppercase commit sha",
			entry:   Entry{CommitSHA: strings.ToUpper(validSHA1), CachePath: cache},
			wantErr: "commit_sha",
		},
		{
			name:    "non-hex commit sha",
			entry:   Entry{CommitSHA: strings.Repeat("g", 40), CachePath: cache},
			wantErr: "commit_sha",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEntry(tt.entry)
			if err == nil {
				t.Fatal("ValidateEntry accepted an invalid entry, want an error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ValidateEntry error = %v, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func newBareCache(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "repo.git")
	cmd := exec.Command("git", "init", "--bare", "-q", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("git init --bare failed: %s: %v", out, err)
	}
	return path
}

func writeManifestValue(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	return writeManifestJSON(t, string(data))
}

func writeManifestJSON(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ManifestFileName)
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}
