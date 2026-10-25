package sandbox

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildDockerRunArgsPinsSecurityAndResourceFlags(t *testing.T) {
	args, err := BuildDockerRunArgs(DockerRunSpec{
		DockerPath:    "docker",
		Image:         "multica/task-worker:test",
		ContainerName: "multica-attempt-abc",
		NetworkMode:   "bridge",
		MemoryBytes:   512 << 20,
		PIDsLimit:     256,
		NanoCPUs:      2_000_000_000,
		User:          "1000:1000",
		Workdir:       CheckoutPath,
		Env:           map[string]string{"HOME": HomePath, "PATH": "/usr/bin"},
		Binds:         []string{"/host/repo:/workspace/repo:rw", "/host/home:/home/agent:rw"},
		Labels:        map[string]string{"multica.attempt": "abc"},
	}, "multica", WorkerArg)
	if err != nil {
		t.Fatalf("BuildDockerRunArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"run", "--rm", "-i", "--init",
		"--security-opt", "no-new-privileges",
		"--cap-drop", "ALL",
		"--name", "multica-attempt-abc",
		"--network", "bridge",
		"--memory", "536870912",
		"--pids-limit", "256",
		"--cpus", "2.000",
		"--user", "1000:1000",
		"--workdir", CheckoutPath,
		"-v", "/host/repo:/workspace/repo:rw",
		"-e", "HOME=/home/agent",
		"--label", "multica.attempt=abc",
		"multica/task-worker:test",
		WorkerArg,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("docker argv missing %q:\n%s", want, joined)
		}
	}
}

func TestContainerEnvRewritesManagedPaths(t *testing.T) {
	env := ContainerEnv(map[string]string{
		"SSH_AUTH_SOCK":       "/host/profile/git-agent/task/sock",
		"MULTICA_CONFIG_ROOT": "/host/config",
		"CODEX_HOME":          "/host/codex",
		"CURSOR_DATA_DIR":     "/host/cursor",
		"PATH":                "/home/user/.local/bin:/usr/bin",
		"MULTICA_TOKEN":       "mat_test",
	})
	if env["HOME"] != HomePath || env["SSH_AUTH_SOCK"] != AgentSocketPath {
		t.Fatalf("HOME/SSH_AUTH_SOCK not rewritten: %+v", env)
	}
	if env["MULTICA_CONFIG_ROOT"] != filepath.Join(HomePath, ".multica") {
		t.Fatalf("MULTICA_CONFIG_ROOT = %q", env["MULTICA_CONFIG_ROOT"])
	}
	if env["MULTICA_TOKEN"] != "mat_test" {
		t.Fatalf("task token must survive rewrite")
	}
	if strings.Contains(env["PATH"], "/home/user") {
		t.Fatalf("PATH still references host home: %q", env["PATH"])
	}
}

func TestSanitizeContainerName(t *testing.T) {
	if got := SanitizeContainerName("task/1 attempt"); got != "multica-attempt-task-1-attempt" {
		t.Fatalf("got %q", got)
	}
}
