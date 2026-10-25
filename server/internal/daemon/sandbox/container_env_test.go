package sandbox

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/multica-ai/multica/server/internal/daemon/workercheckout"
)

func TestContainerEnvRewritesTaskConfigRoot(t *testing.T) {
	env := ContainerEnv(map[string]string{
		"MULTICA_TASK_CONFIG_ROOT": "/host/task-multica",
		"MULTICA_CONFIG_ROOT":      "/host/config",
		"CLAUDE_CONFIG_DIR":        "/host/.claude",
	})
	configRoot := filepath.Join(HomePath, ".multica")
	if got := env["MULTICA_TASK_CONFIG_ROOT"]; got != configRoot {
		t.Errorf("MULTICA_TASK_CONFIG_ROOT = %q, want %q", got, configRoot)
	}
	if got := env["MULTICA_CONFIG_ROOT"]; got != configRoot {
		t.Errorf("MULTICA_CONFIG_ROOT = %q, want %q", got, configRoot)
	}
	if got := env["MULTICA_ISOLATED_TOOL_BOUNDARY"]; got != "1" {
		t.Errorf("MULTICA_ISOLATED_TOOL_BOUNDARY = %q, want 1", got)
	}
	if got := env["MULTICA_HOST_REPO_CHECKOUT"]; got != "disabled" {
		t.Errorf("MULTICA_HOST_REPO_CHECKOUT = %q, want disabled", got)
	}
	// Claude Code reads ~/.claude; the task-home copy seeds it at /home/agent,
	// so an explicit host CLAUDE_CONFIG_DIR must not survive into the container.
	if got := env["CLAUDE_CONFIG_DIR"]; got != filepath.Join(HomePath, ".claude") {
		t.Errorf("CLAUDE_CONFIG_DIR = %q, want %q", got, filepath.Join(HomePath, ".claude"))
	}
}

func TestDockerRepoCacheBindsDeduplicatesCleanedPaths(t *testing.T) {
	binds, err := DockerRepoCacheBinds(
		[]workercheckout.Entry{
			{URL: "https://example.com/a", CachePath: "/cache/a"},
			{URL: "https://example.com/b", CachePath: "/cache/b"},
		},
		[]string{"/cache/a", "/cache/c"},
	)
	if err != nil {
		t.Fatalf("DockerRepoCacheBinds: %v", err)
	}
	if len(binds) != 3 {
		t.Fatalf("binds = %v, want 3 unique binds", binds)
	}
	joined := strings.Join(binds, "\n")
	for _, want := range []string{
		"/cache/a:/cache/a:ro",
		"/cache/b:/cache/b:ro",
		"/cache/c:/cache/c:ro",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("binds missing %q:\n%s", want, joined)
		}
	}
}

func TestDockerRepoCacheBindsRejectsRelativeAndDotDotPaths(t *testing.T) {
	for _, path := range []string{
		"relative/cache",
		"../cache",
		"/cache/../escape",
	} {
		if _, err := DockerRepoCacheBinds(nil, []string{path}); err == nil {
			t.Errorf("DockerRepoCacheBinds accepted unsafe path %q", path)
		}
	}
}
