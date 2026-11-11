package sandbox

import (
	"fmt"
	"strings"

	"github.com/multica-ai/multica/server/internal/daemon/execenv"
)

var nativeScopedProfileSeedSkipDirs = map[string]map[string]bool{
	"codex": dirSet("sessions", "multica-sessions"),
	"cursor": dirSet(
		"snapshots",
		"logs",
	),
	"opencode": dirSet("log", "shell", "snapshot", "worktree", "tool-output", "repos"),
}

func dirSet(names ...string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set
}

// seedNativeExecutionProfile copies the runtime owner's logged-in provider state
// into a per-execution-user writable tree (issue #109 F4). Host selector env vars
// are ignored for the destination layout, so credentials must be seeded explicitly.
func seedNativeExecutionProfile(request NativeRuntimeRequest, scopedPaths []string) error {
	if strings.TrimSpace(request.ExecutionUserID) == "" {
		return nil
	}
	operator := request
	operator.ExecutionUserID = ""
	var operatorRuntime NativeRuntime
	operatorRuntime.Env = make(map[string]string)
	var scopedRuntime NativeRuntime
	scopedRuntime.Env = make(map[string]string)
	operatorSpecs, err := nativeProfilePathSpecs(operator, &operatorRuntime)
	if err != nil {
		return err
	}
	scopedSpecs, err := nativeProfilePathSpecs(request, &scopedRuntime)
	if err != nil {
		return err
	}
	scopedByRole := make(map[string]string, len(scopedSpecs))
	for _, spec := range scopedSpecs {
		scopedByRole[spec.role] = spec.path
	}
	if len(scopedPaths) != len(scopedSpecs) {
		return fmt.Errorf("native sandbox: scoped profile path count mismatch")
	}
	skip := nativeScopedProfileSeedSkipDirs[request.Provider]
	for _, spec := range operatorSpecs {
		dest, ok := scopedByRole[spec.role]
		if !ok {
			continue
		}
		if err := execenv.MirrorProviderTree(spec.path, dest, skip, nil); err != nil {
			return fmt.Errorf("seed native profile role %q from %q: %w", spec.role, spec.path, err)
		}
		if request.Provider == "opencode" && spec.role == "opencode_data" {
			if err := execenv.PruneOpenCodeDatabase(dest); err != nil {
				return fmt.Errorf("seed native profile opencode data: %w", err)
			}
		}
	}
	return nil
}
