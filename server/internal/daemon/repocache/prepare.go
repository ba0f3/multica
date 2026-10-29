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

// AccessFailures lists repositories whose remote refused access. Prepare may
// return these alongside successfully refreshed repositories.
type AccessFailures struct {
	Repos  []string
	Causes []error
}

func (e *AccessFailures) Error() string {
	return "repository access unavailable: " + strings.Join(e.Repos, ", ")
}
func (e *AccessFailures) Unwrap() []error { return e.Causes }

func repositoryAccessDenied(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	message := strings.ToLower(err.Error())
	// A signing service failure prevents authentication even with a valid key.
	if strings.Contains(message, "signing failed") || strings.Contains(message, "agent refused operation") {
		return false
	}
	for _, pattern := range []string{"permission denied (publickey", "repository not found", "authentication failed", "could not read username", "requested url returned error: 401", "requested url returned error: 403", "remote: access denied", "remote: you are not allowed", "gitea: unauthorized", "gitea: access denied", "gitea: user permission denied", "gitea: repository does not exist"} {
		if strings.Contains(message, pattern) {
			return true
		}
	}
	return false
}

// Prepare refreshes repositories independently. Access refusals are returned
// alongside successful results; transport, ref and local failures remain fatal.
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
	failures := make([]error, len(repos))
	var group errgroup.Group
	group.SetLimit(4)
	for i, repo := range repos {
		group.Go(func() error {
			prepared[i], failures[i] = c.prepareRepo(ctx, scope, repo)
			return nil
		})
	}
	_ = group.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	available := make([]PreparedRepo, 0, len(repos))
	access := &AccessFailures{}
	for i, err := range failures {
		if err == nil {
			available = append(available, prepared[i])
			continue
		}
		wrapped := fmt.Errorf("prepare repo %s: %w", repos[i].URL, err)
		if !repositoryAccessDenied(err) {
			return nil, wrapped
		}
		access.Repos = append(access.Repos, repos[i].URL)
		access.Causes = append(access.Causes, wrapped)
	}
	if len(access.Repos) > 0 {
		return available, access
	}
	return available, nil
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
