// Package workercheckout creates task workdir checkouts from bare repository
// caches prepared by the daemon.
package workercheckout

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ManifestFileName is the task-scoped file the daemon writes and the in-worker
// CLI reads. In Docker workers it is bind-mounted read-only at
// ~/.multica/repo-cache.json.
const ManifestFileName = "repo-cache.json"

// taskConfigRootEnv mirrors the CLI's task-local config root. It is declared
// here instead of importing internal/cli so this package can be consumed by
// the CLI without an import cycle.
const taskConfigRootEnv = "MULTICA_TASK_CONFIG_ROOT"

// Entry is one task repo the daemon prepared. CachePath is the absolute host
// path of the bare cache, which the worker sees at the same path.
type Entry struct {
	URL       string `json:"url"`
	Ref       string `json:"ref,omitempty"`
	CommitSHA string `json:"commit_sha"`
	CachePath string `json:"cache_path"`
}

// Manifest is the full set of repos available to one task attempt.
type Manifest struct {
	Repos []Entry `json:"repos"`
}

var commitSHAPattern = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)

// ManifestPath returns the manifest location: below MULTICA_TASK_CONFIG_ROOT
// when the daemon set it, otherwise the interactive ~/.multica directory.
func ManifestPath() (string, error) {
	root := strings.TrimSpace(os.Getenv(taskConfigRootEnv))
	if root != "" {
		root = filepath.Clean(root)
		if !filepath.IsAbs(root) {
			return "", fmt.Errorf("%s must be an absolute path", taskConfigRootEnv)
		}
		return filepath.Join(root, ManifestFileName), nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve the task repo cache manifest path: %w", err)
	}
	return filepath.Join(home, ".multica", ManifestFileName), nil
}

// WriteManifest atomically publishes manifest at path. The file is
// bind-mounted read-only into Docker workers, so 0o644 keeps it readable when
// the worker runs as a fixed non-root user.
func WriteManifest(path string, manifest Manifest) error {
	data, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("encode the task repo cache manifest: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create the task repo cache manifest temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return fmt.Errorf("set the task repo cache manifest permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write the task repo cache manifest: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write the task repo cache manifest: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("publish the task repo cache manifest: %w", err)
	}
	return nil
}

// ReadManifest strictly decodes a manifest and validates every entry: the file
// is the worker's only source for cache paths, so unknown fields and invalid
// paths must not be tolerated.
func ReadManifest(path string) (Manifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("open the task repo cache manifest: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()

	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode the task repo cache manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Manifest{}, errors.New("decode the task repo cache manifest: unexpected trailing JSON")
		}
		return Manifest{}, fmt.Errorf("decode the task repo cache manifest: %w", err)
	}

	for i, entry := range manifest.Repos {
		if err := ValidateEntry(entry); err != nil {
			return Manifest{}, fmt.Errorf("validate the task repo cache manifest entry %d (%s): %w", i, entry.URL, err)
		}
	}
	return manifest, nil
}

// Find returns the entry for url. URLs are compared exactly: the daemon and
// the worker must agree on the task repo identifier.
func Find(manifest Manifest, url string) (Entry, error) {
	for _, entry := range manifest.Repos {
		if entry.URL == url {
			return entry, nil
		}
	}

	allowed := make([]string, 0, len(manifest.Repos))
	for _, entry := range manifest.Repos {
		allowed = append(allowed, fmt.Sprintf("%q", entry.URL))
	}
	if len(allowed) == 0 {
		allowed = append(allowed, "(none)")
	}
	return Entry{}, fmt.Errorf("repo %q is not in the task repo cache manifest; allowed URLs: %s", url, strings.Join(allowed, ", "))
}

// ValidateEntry is the worker-side gate for a cache path. It accepts only an
// absolute, cleaned path to an existing bare repository and a full lowercase
// object ID, so a tampered manifest cannot point the worker at an arbitrary
// directory or a truncated commit.
func ValidateEntry(entry Entry) error {
	if entry.CachePath == "" {
		return errors.New("cache_path is required")
	}
	if !filepath.IsAbs(entry.CachePath) {
		return fmt.Errorf("cache_path must be absolute: %q", entry.CachePath)
	}
	if cleaned := filepath.Clean(entry.CachePath); cleaned != entry.CachePath {
		return fmt.Errorf("cache_path must be clean: %q (want %q)", entry.CachePath, cleaned)
	}

	info, err := os.Stat(entry.CachePath)
	if err != nil {
		return fmt.Errorf("stat cache_path %q: %w", entry.CachePath, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cache_path %q is not a directory", entry.CachePath)
	}

	head, err := os.Stat(filepath.Join(entry.CachePath, "HEAD"))
	if err != nil {
		return fmt.Errorf("cache_path %q has no HEAD: %w", entry.CachePath, err)
	}
	if head.IsDir() {
		return fmt.Errorf("cache_path %q has a directory at HEAD", entry.CachePath)
	}

	objects, err := os.Stat(filepath.Join(entry.CachePath, "objects"))
	if err != nil {
		return fmt.Errorf("cache_path %q has no objects directory: %w", entry.CachePath, err)
	}
	if !objects.IsDir() {
		return fmt.Errorf("cache_path %q objects is not a directory", entry.CachePath)
	}

	if !commitSHAPattern.MatchString(entry.CommitSHA) {
		return fmt.Errorf("commit_sha %q must be 40 or 64 lowercase hex characters", entry.CommitSHA)
	}
	return nil
}
