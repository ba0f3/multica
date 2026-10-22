package r2dgit

import "strings"

// isSSHAuthFailure reports whether the SSH client failed to authenticate with
// the provider using the stored key (as opposed to a network or host-key error).
func isSSHAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "no supported methods remain")
}
