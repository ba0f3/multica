package repocache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PreparedRepo describes a repository that has been fetched into the
// workspace cache and resolved to a concrete commit.
type PreparedRepo struct {
	URL       string
	Ref       string // requested ref; empty means the remote default branch
	CommitSHA string
	BarePath  string // absolute host path of the bare cache
}

// Prepare makes every repo available in the workspace cache and resolves the
// commit each one should be checked out at.
//
// SyncContext tolerates fetch failures so the daemon can keep working from an
// older snapshot. Prepare is the strict counterpart used when a task is about
// to receive code: a failed clone, fetch, or ref resolution returns an error
// naming the repo URL and no PreparedRepo at all. Callers can therefore trust
// every returned CommitSHA to reflect the remote state seen by this call.
func (c *Cache) Prepare(ctx context.Context, workspaceID string, repos []RepoInfo) ([]PreparedRepo, error) {
	if workspaceID == "" {
		return nil, errors.New("prepare repos: empty workspace ID")
	}
	if len(repos) == 0 {
		return nil, nil
	}
	for _, repo := range repos {
		if strings.TrimSpace(repo.URL) == "" {
			return nil, errors.New("prepare repos: empty repository URL")
		}
	}

	wsDir := filepath.Join(c.root, workspaceID)
	if err := os.MkdirAll(wsDir, 0o755); err != nil {
		return nil, fmt.Errorf("create workspace cache dir: %w", err)
	}

	prepared := make([]PreparedRepo, 0, len(repos))
	for _, repo := range repos {
		preparedRepo, err := c.prepareRepo(ctx, workspaceID, repo)
		if err != nil {
			return nil, fmt.Errorf("prepare repo %s: %w", repo.URL, err)
		}
		prepared = append(prepared, preparedRepo)
	}
	return prepared, nil
}

// prepareRepo clones or fetches one repo under its lock, then resolves the
// requested ref (or the remote default branch) to a commit SHA.
func (c *Cache) prepareRepo(ctx context.Context, workspaceID string, repo RepoInfo) (PreparedRepo, error) {
	barePath := c.BarePath(workspaceID, repo.URL)

	repoLock := c.lockForRepo(barePath)
	if err := repoLock.LockContext(ctx); err != nil {
		return PreparedRepo{}, err
	}
	defer repoLock.Unlock()

	if isBareRepo(barePath) {
		// Record the active CA bundle before fetching, exactly as SyncContext
		// does: a cache cloned before the server sent private CAs would
		// otherwise fetch with the trust it had at clone time.
		c.configureRepoCABundleLogged(ctx, barePath)
		if err := gitFetchContext(ctx, barePath); err != nil {
			return PreparedRepo{}, err
		}
	} else if err := gitCloneBareContext(ctx, repo.URL, barePath); err != nil {
		return PreparedRepo{}, err
	}

	baseRef, err := resolveBaseRefContext(ctx, barePath, repo.Ref)
	if err != nil {
		return PreparedRepo{}, err
	}
	sha, err := resolveCommitContext(ctx, barePath, baseRef)
	if err != nil {
		return PreparedRepo{}, err
	}

	return PreparedRepo{
		URL:       repo.URL,
		Ref:       repo.Ref,
		CommitSHA: sha,
		BarePath:  barePath,
	}, nil
}
