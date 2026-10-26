package daemon

import (
	"github.com/multica-ai/multica/server/internal/daemon/repocache"
	"path/filepath"
	"strings"
)

func (t Task) repoScope() repocache.Scope {
	return repocache.Scope{WorkspaceID: t.WorkspaceID, UserID: t.ExecutionUserID}
}

func (d *Daemon) repoScopeForPath(path string) (repocache.Scope, bool) {
	rel, err := filepath.Rel(filepath.Join(d.cfg.WorkspacesRoot, ".repos"), path)
	if err != nil {
		return repocache.Scope{}, false
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) != 3 {
		return repocache.Scope{}, false
	}
	scope := repocache.Scope{WorkspaceID: parts[0], UserID: parts[1]}
	return scope, scope.Validate() == nil
}

func (d *Daemon) repoCacheScopes(workspaceID string) ([]repocache.Scope, error) {
	if cache, ok := d.repoCache.(interface {
		Scopes(string) ([]repocache.Scope, error)
	}); ok {
		return cache.Scopes(workspaceID)
	}
	return nil, nil
}
