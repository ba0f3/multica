package repocache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DependentsDirName stores records of workdirs borrowing objects from one
// execution user's bare caches. Records live beside that user's repositories.
const DependentsDirName = ".dependents"

// dependentRecordLen is the number of hex characters of the workdir hash kept
// in a record filename. It only has to be long enough that two workdirs on one
// machine do not collide; the workdir inside the record is the real identity.
const dependentRecordLen = 16

// Dependent records that a task workdir depends on bare caches: its checkouts
// point objects/info/alternates at them, so evicting or pruning those caches
// while the workdir exists would break it — including across daemon restarts,
// after the process that created the checkout is gone.
type Dependent struct {
	WorkDir    string   `json:"workdir"`
	CachePaths []string `json:"cache_paths"`
	TaskID     string   `json:"task_id,omitempty"`
	AttemptID  string   `json:"attempt_id,omitempty"`
}

// dependentsDir is where one execution user's dependent records live.
func (c *Cache) dependentsDir(scope Scope) string {
	root, _ := c.ScopeRoot(scope)
	return filepath.Join(root, DependentsDirName)
}

// dependentRecordPath is the file identifying workDir. The workdir is hashed
// rather than escaped into the name: it is an absolute path that filesystem
// filename limits can reject, and the hash keeps the name fixed-size.
func (c *Cache) dependentRecordPath(scope Scope, workDir string) string {
	sum := sha256.Sum256([]byte(workDir))
	name := hex.EncodeToString(sum[:])[:dependentRecordLen] + ".json"
	return filepath.Join(c.dependentsDir(scope), name)
}

// RecordDependents durably records that dep.WorkDir depends on dep.CachePaths.
// A later record for the same workdir replaces the earlier one: the caller
// reports the complete current set for that workdir, not an increment.
//
// The write is atomic (temp file + rename), so a scan running concurrently
// reads either the previous record or the new one, never a partial file.
func (c *Cache) RecordDependents(scope Scope, dep Dependent) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	workDir, err := absoluteCleanPath("workdir", dep.WorkDir)
	if err != nil {
		return err
	}
	root, err := c.ScopeRoot(scope)
	if err != nil {
		return err
	}
	cachePaths := make([]string, 0, len(dep.CachePaths))
	for _, path := range dep.CachePaths {
		cleaned, err := absoluteCleanPath("cache path", path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, cleaned)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return fmt.Errorf("repo cache dependent is outside the execution user store: %s", cleaned)
		}
		cachePaths = append(cachePaths, cleaned)
	}
	dep.WorkDir = workDir
	dep.CachePaths = cachePaths

	data, err := json.Marshal(dep)
	if err != nil {
		return fmt.Errorf("encode repo cache dependents: %w", err)
	}

	dir := c.dependentsDir(scope)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create repo cache dependents dir: %w", err)
	}
	// The temp name deliberately does not end in .json: a leftover from a
	// crashed write must never be picked up as a record by
	// LiveDependentCachePaths.
	tmp, err := os.CreateTemp(dir, ".record-*")
	if err != nil {
		return fmt.Errorf("create repo cache dependents temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write repo cache dependents: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("write repo cache dependents: %w", err)
	}
	if err := os.Rename(tmpName, c.dependentRecordPath(scope, workDir)); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("publish repo cache dependents: %w", err)
	}
	return nil
}

// absoluteCleanPath validates that path is absolute and returns its cleaned
// form. Records are matched against the cache's own absolute paths, so a
// relative path would silently retain nothing.
func absoluteCleanPath(field, path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("record repo cache dependents: %s must be absolute: %q", field, path)
	}
	return filepath.Clean(path), nil
}

// LiveDependentCachePaths returns every cache path named by a dependent record
// whose workdir still exists. It is the retention side of RecordDependents:
// the cache GC must not evict or prune any path in this set.
//
// Records of workdirs that are gone are deleted as they are found, so the
// answer survives daemon restarts without accumulating forever. A malformed
// record is skipped: records are daemon-written, so one can only mean
// corruption, and skipping it can shorten retention but never retain a cache
// for a workdir that has no record. Only a directory that exists but cannot be
// read fails the scan; a missing cache root simply has no dependents.
func (c *Cache) LiveDependentCachePaths() (map[string]struct{}, error) {
	live := make(map[string]struct{})

	workspaces, err := os.ReadDir(c.root)
	if err != nil {
		if os.IsNotExist(err) {
			return live, nil
		}
		return nil, fmt.Errorf("read repo cache root: %w", err)
	}
	for _, workspace := range workspaces {
		if !workspace.IsDir() {
			continue
		}
		owners, err := os.ReadDir(filepath.Join(c.root, workspace.Name()))
		if err != nil {
			return nil, err
		}
		for _, owner := range owners {
			if !owner.IsDir() || strings.HasSuffix(owner.Name(), ".git") {
				continue
			}
			dir := filepath.Join(c.root, workspace.Name(), owner.Name(), DependentsDirName)
			records, err := os.ReadDir(dir)
			if err != nil {
				if os.IsNotExist(err) {
					continue // no dependent workdirs in this workspace
				}
				return nil, fmt.Errorf("read repo cache dependents %s: %w", dir, err)
			}
			for _, record := range records {
				if record.IsDir() || !strings.HasSuffix(record.Name(), ".json") {
					continue
				}
				scanDependentRecord(filepath.Join(dir, record.Name()), live)
			}
		}
	}
	return live, nil
}

// scanDependentRecord adds the cache paths of one record to live, and removes
// the record when its workdir no longer exists.
func scanDependentRecord(path string, live map[string]struct{}) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var dep Dependent
	if err := json.Unmarshal(data, &dep); err != nil {
		return
	}
	// A relative workdir would resolve against the daemon's working directory
	// rather than the path the record was written for.
	if !filepath.IsAbs(dep.WorkDir) {
		return
	}
	if _, err := os.Stat(dep.WorkDir); err != nil {
		if os.IsNotExist(err) {
			// Best-effort: a failed removal only means the next scan retries it.
			_ = os.Remove(path)
			return
		}
		// The workdir is still there but unreadable (permissions, I/O). It
		// cannot be proven gone, and eviction is irreversible, so retain.
	}
	for _, cachePath := range dep.CachePaths {
		if cleaned := filepath.Clean(cachePath); filepath.IsAbs(cleaned) {
			live[cleaned] = struct{}{}
		}
	}
}
