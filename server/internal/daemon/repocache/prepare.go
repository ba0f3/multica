package repocache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sync/errgroup"
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
func (c *Cache) Prepare(ctx context.Context, scope Scope, repos []RepoInfo) ([]PreparedRepo, error) {
	if err := scope.Validate(); err != nil {
		return nil, err
	}
	if len(repos) == 0 {
		return nil, nil
	}
	for _, repo := range repos {
		if strings.TrimSpace(repo.URL) == "" {
			return nil, errors.New("prepare repos: empty repository URL")
		}
	}

	wsDir, err := c.ScopeRoot(scope)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(wsDir, 0o755); err != nil {
		return nil, fmt.Errorf("create workspace cache dir: %w", err)
	}

	prepared := make([]PreparedRepo, len(repos))
	group, prepareCtx := errgroup.WithContext(ctx)
	group.SetLimit(4)
	for i, repo := range repos {
		group.Go(func() error {
			preparedRepo, err := c.prepareRepo(prepareCtx, scope, repo)
			if err != nil {
				return fmt.Errorf("prepare repo %s: %w", repo.URL, err)
			}
			prepared[i] = preparedRepo
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return prepared, nil
}

// prepareRepo clones or fetches one repo under its lock, then resolves the
// requested ref (or the remote default branch) to a commit SHA.
func (c *Cache) prepareRepo(ctx context.Context, scope Scope, repo RepoInfo) (PreparedRepo, error) {
	barePath := c.BarePath(scope, repo.URL)
	if err := rejectRepoAlias(barePath); err != nil {
		return PreparedRepo{}, err
	}

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
