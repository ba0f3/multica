package agent

import (
	"errors"
	"fmt"
)

// ErrOpenCodeIsolatedExternalServer reports that a task in the isolated tool
// boundary attempted to reach an external OpenCode service via --server.
var ErrOpenCodeIsolatedExternalServer = errors.New(
	"opencode: --server is not allowed inside the isolated tool boundary; the OpenCode service must run in the task worker")

// enforceOpenCodeIsolatedLaunch applies argv rules for Docker/bwrap workers.
// External --server URLs would let the agent reach a host-side or shared
// background service outside the boundary; 2.x runs get --standalone so the
// service stays in the worker process tree.
func enforceOpenCodeIsolatedLaunch(args []string, usesV2 bool) ([]string, error) {
	server, standalone := opencodeConnectionFromArgs(args)
	if server != "" {
		return nil, fmt.Errorf("%w (url redacted)", ErrOpenCodeIsolatedExternalServer)
	}
	if usesV2 && !standalone {
		args = append(args, "--standalone")
	}
	return args, nil
}
