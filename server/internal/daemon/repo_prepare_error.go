package daemon

import (
	"fmt"
	"strings"
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
