package daemon

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/multica-ai/multica/server/internal/daemon/workercheckout"
)

// taskRepoPrepareError adds provider-specific recovery steps to an otherwise
// opaque Git error while preserving the original error for logs and callers.
func taskRepoPrepareError(task Task, err error) error {
	if err == nil || !strings.Contains(err.Error(), "Repository not found") {
		return err
	}
	for _, repo := range task.Repos {
		if repositoryHost(repo.URL) != "github.com" || !strings.Contains(err.Error(), repo.URL) {
			continue
		}
		return fmt.Errorf("%w\nGitHub reported that the repository was not found. Check or verify the repository URL. If it is private, connect a GitHub credential in Multica, add its SSH public key to the GitHub account or repository deploy keys, then run Check connection", err)
	}
	return err
}

// taskWithPreparedRepos limits every downstream repo grant to refreshed caches.
func (d *Daemon) taskWithPreparedRepos(task Task, prepared []workercheckout.Entry) Task {
	key := func(url string) string {
		if path := d.repoCache.BarePath(task.repoScope(), url); path != "" {
			return path
		}
		return strings.TrimSpace(url)
	}
	allowed := make(map[string]bool, len(prepared))
	for _, entry := range prepared {
		allowed[key(entry.URL)] = true
	}
	repos := make([]RepoData, 0, len(task.Repos))
	denied := make(map[string]bool)
	for _, repo := range task.Repos {
		if allowed[key(repo.URL)] {
			repos = append(repos, repo)
		} else if strings.TrimSpace(repo.URL) != "" {
			task.SkippedRepos = append(task.SkippedRepos, repo.URL)
			denied[key(repo.URL)] = true
		}
	}
	task.Repos = repos
	if len(task.SkippedRepos) == 0 {
		return task
	}
	// Old workdirs can contain full copies of repositories now denied access.
	task.PriorWorkDir, task.PriorSessionID = "", ""
	resources := make([]ProjectResourceData, 0, len(task.ProjectResources))
	for _, resource := range task.ProjectResources {
		if resource.ResourceType == "github_repo" {
			var ref struct {
				URL string `json:"url"`
			}
			if json.Unmarshal(resource.ResourceRef, &ref) == nil && denied[key(ref.URL)] {
				continue
			}
		}
		resources = append(resources, resource)
	}
	task.ProjectResources = resources
	return task
}
