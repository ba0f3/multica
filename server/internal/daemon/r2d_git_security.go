package daemon

import "errors"

var errProtectedGitUnsupported = errors.New("git_runtime_ineligible: protected Git execution is unavailable on this daemon")

func validateProtectedGitTask(task Task) error {
	if task.RequiredGitSecurity != "" {
		return errProtectedGitUnsupported
	}
	return nil
}
