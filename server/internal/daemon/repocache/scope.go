package repocache

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Scope identifies the server-proven owner of a repository store.
type Scope struct {
	WorkspaceID string
	UserID      string
}

func (s Scope) Validate() error {
	for _, field := range []struct{ name, value string }{{"workspace", s.WorkspaceID}, {"execution user", s.UserID}} {
		if field.value == "" || field.value == "." || field.value == ".." || strings.ContainsAny(field.value, "/\\:\x00") || strings.TrimSpace(field.value) != field.value {
			return fmt.Errorf("repo cache requires a valid %s ID; update the backend and retry the task", field.name)
		}
	}
	return nil
}

// ScopeRoot rejects aliases that would join stores belonging to different users.
func (c *Cache) ScopeRoot(scope Scope) (string, error) {
	if err := scope.Validate(); err != nil {
		return "", err
	}
	for _, path := range []string{filepath.Join(c.root, scope.WorkspaceID), filepath.Join(c.root, scope.WorkspaceID, scope.UserID)} {
		info, err := os.Lstat(path)
		if err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
			return "", fmt.Errorf("repo cache owner path must be a directory without symlinks: %s", path)
		}
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	return filepath.Join(c.root, scope.WorkspaceID, scope.UserID), nil
}

// Scopes enumerates user stores, excluding legacy workspace-wide bare caches.
func (c *Cache) Scopes(workspaceID string) ([]Scope, error) {
	if err := (Scope{WorkspaceID: workspaceID, UserID: "validate"}).Validate(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(c.root, workspaceID))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var scopes []Scope
	for _, entry := range entries {
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || strings.HasSuffix(entry.Name(), ".git") {
			continue
		}
		scope := Scope{WorkspaceID: workspaceID, UserID: entry.Name()}
		if _, err := c.ScopeRoot(scope); err != nil {
			return nil, err
		}
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

func rejectRepoAlias(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("repo cache entry must be an owned directory without symlinks: %s", path)
	}
	return nil
}
