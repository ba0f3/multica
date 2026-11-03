package sandbox

import (
	"fmt"
	"path/filepath"
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

func operatorProfilePaths(request NativeRuntimeRequest) ([]string, error) {
	operator := request
	operator.ExecutionUserID = ""
	var runtime NativeRuntime
	runtime.Env = make(map[string]string)
	return nativeProfilePaths(operator, &runtime)
}

func operatorSourceForScopedProfilePath(request NativeRuntimeRequest, scopedPath string) (string, bool) {
	operatorPaths, err := operatorProfilePaths(request)
	if err != nil {
		return "", false
	}
	scopedHome := nativeExecutionProfileHome(request)
	operatorHome := nativeExecutionProfileHome(NativeRuntimeRequest{Home: request.Home})
	rel, err := filepath.Rel(scopedHome, scopedPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", false
	}
	candidate := filepath.Join(operatorHome, rel)
	for _, path := range operatorPaths {
		if path == candidate {
			return path, true
		}
	}
	base := filepath.Base(scopedPath)
	for _, path := range operatorPaths {
		if filepath.Base(path) == base {
			return path, true
		}
	}
	return "", false
}

// seedNativeExecutionProfile copies the runtime owner's logged-in provider state
// into a per-execution-user writable tree (issue #109 F4). Host selector env vars
// are ignored for the destination layout, so credentials must be seeded explicitly.
func seedNativeExecutionProfile(request NativeRuntimeRequest, scopedPaths []string) error {
	if strings.TrimSpace(request.ExecutionUserID) == "" {
		return nil
	}
	skip := nativeScopedProfileSeedSkipDirs[request.Provider]
	for _, dest := range scopedPaths {
		src, ok := operatorSourceForScopedProfilePath(request, dest)
		if !ok {
			continue
		}
		if err := execenv.MirrorProviderTree(src, dest, skip, nil); err != nil {
			return fmt.Errorf("seed native profile from %q: %w", src, err)
		}
	}
	return nil
}
