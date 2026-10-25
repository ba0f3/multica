package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/daemon/execenv"
	"github.com/multica-ai/multica/server/internal/daemon/sandbox"
	"github.com/multica-ai/multica/server/internal/daemon/workercheckout"
	"github.com/multica-ai/multica/server/pkg/agent"
)

func TestDockerBackendBuildsRunWithPrivateMounts(t *testing.T) {
	env, fakeCodex, joined := dockerBackendArgv(t, nil, nil)
	for _, want := range []string{
		"run", "--rm", "-i",
		"--name", sandbox.SanitizeContainerName("attempt-docker-1"),
		"-v", env.WorkDir + ":" + sandbox.CheckoutPath + ":rw",
		"-v", filepath.Join(env.RootDir, "home") + ":" + sandbox.HomePath + ":rw",
		"-v", fakeCodex + ":/usr/local/bin/codex:ro",
		"multica/task-worker:test",
		sandbox.WorkerArg,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("docker argv missing %q:\n%s", want, joined)
		}
	}
}

// TestDockerBackendBindsClaudeAndAntigravity verifies the two newly admitted
// providers pass the gate, their resolved host binaries are bind-mounted
// read-only at /usr/local/bin/<basename>, and Claude's task-local --settings
// file is mounted and rewritten to the in-container path.
func TestDockerBackendBindsClaudeAndAntigravity(t *testing.T) {
	for _, provider := range []string{"claude", "antigravity"} {
		t.Run(provider, func(t *testing.T) {
			argvRecord := filepath.Join(t.TempDir(), "argv")
			manifestRecord := filepath.Join(t.TempDir(), "manifest")
			fakeDocker := filepath.Join(t.TempDir(), "docker")
			dockerScript := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argvRecord + "\nhead -n1 > " + manifestRecord + "\nprintf '%s\\n' '{\"type\":\"result\",\"result\":{\"Status\":\"completed\",\"Output\":\"ok\"}}'\n"
			if err := os.WriteFile(fakeDocker, []byte(dockerScript), 0o755); err != nil {
				t.Fatalf("write fake docker: %v", err)
			}

			daemon := newSandboxTestDaemon(t, "bwrap")
			daemon.cfg.TaskSandboxBackend = "docker"
			daemon.cfg.DockerCLIPath = fakeDocker
			daemon.cfg.DockerTaskImage = "multica/task-worker:test"
			env := newSandboxTestEnv(t)

			binName := provider
			if provider == "antigravity" {
				binName = "agy"
			}
			hostBinary := filepath.Join(t.TempDir(), binName)
			if err := os.WriteFile(hostBinary, []byte("#!/bin/sh\n"), 0o755); err != nil {
				t.Fatalf("write fake %s: %v", binName, err)
			}

			config := agent.Config{TaskID: "task-1", ExecutablePath: hostBinary}
			var wantSettingsBind string
			if provider == "claude" {
				settings := filepath.Join(env.RootDir, "claude-runtime-skill-settings.json")
				if err := os.WriteFile(settings, []byte(`{"disabled":[]}`), 0o600); err != nil {
					t.Fatalf("write settings: %v", err)
				}
				env.ClaudeSettingsPath = settings
				wantSettingsBind = settings + ":" + sandbox.ClaudeSettingsPath + ":ro"
			}

			backend, err := daemon.sandboxedBackend(provider, config, env, "", "", "attempt-"+provider, nil, nil)
			if err != nil {
				t.Fatalf("sandboxedBackend(%s): %v", provider, err)
			}
			if backend == nil {
				t.Fatalf("expected docker backend for %s", provider)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			session, err := backend.Execute(ctx, "prompt", agent.ExecOptions{ClaudeSettingsPath: env.ClaudeSettingsPath})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			_, result := collectSandboxSession(ctx, t, session)
			if result.Status != "completed" {
				t.Fatalf("result = %+v", result)
			}

			argvRaw, err := os.ReadFile(argvRecord)
			if err != nil {
				t.Fatalf("read argv: %v", err)
			}
			joined := string(argvRaw)
			binds := strings.Join(dockerBinds(joined), "\n")
			wantBinaryBind := hostBinary + ":/usr/local/bin/" + binName + ":ro"
			if !strings.Contains(binds, wantBinaryBind) {
				t.Errorf("docker argv missing binary bind %q:\n%s", wantBinaryBind, binds)
			}
			if wantSettingsBind != "" && !strings.Contains(binds, wantSettingsBind) {
				t.Errorf("docker argv missing settings bind %q:\n%s", wantSettingsBind, binds)
			}

			manifestRaw, err := os.ReadFile(manifestRecord)
			if err != nil {
				t.Fatalf("read manifest: %v", err)
			}
			var manifest sandbox.Manifest
			if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
				t.Fatalf("decode manifest: %v\n%s", err, manifestRaw)
			}
			if got := manifest.Config.ExecutablePath; got != "/usr/local/bin/"+binName {
				t.Errorf("manifest executable = %q, want /usr/local/bin/%s", got, binName)
			}
			if provider == "claude" {
				if got := manifest.Exec.ClaudeSettingsPath; got != sandbox.ClaudeSettingsPath {
					t.Errorf("manifest claude_settings_path = %q, want %q", got, sandbox.ClaudeSettingsPath)
				}
			}
		})
	}
}

// TestDockerBackendDoesNotBindHostWorkingDirectory guards the empty
// OpenclawConfigPath case: filepath.Dir("") is ".", and a relative docker
// bind source resolves against the daemon's working directory. On a systemd
// user unit that is the daemon user's home, which would hand every worker a
// read-write mount of ~/.ssh and ~/.multica.
func TestDockerBackendDoesNotBindHostWorkingDirectory(t *testing.T) {
	_, _, joined := dockerBackendArgv(t, nil, nil)
	lines := strings.Split(joined, "\n")
	for i, line := range lines {
		if line != "-v" || i+1 >= len(lines) {
			continue
		}
		bind := lines[i+1]
		source := bind
		if idx := strings.Index(bind, ":"); idx >= 0 {
			source = bind[:idx]
		}
		if source == "." {
			t.Fatalf("docker bind %q mounts the daemon working directory", bind)
		}
		if strings.Contains(bind, sandbox.HomePath+"/.openclaw") {
			t.Fatalf("docker bind %q mounts openclaw state into the worker", bind)
		}
	}
}

// dockerBackendArgv runs one codex attempt through a fake docker CLI and
// returns the execution environment, mounted agent binary, and captured argv.
// Optional setup callbacks mutate the environment before the backend is built,
// so tests can, for example, set WorkerCABundlePath.
func dockerBackendArgv(t *testing.T, repos []workercheckout.Entry, extraCachePaths []string, setup ...func(*execenv.Environment)) (*execenv.Environment, string, string) {
	t.Helper()
	record := filepath.Join(t.TempDir(), "argv")
	fakeDocker := filepath.Join(t.TempDir(), "docker")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + record + "\nwhile [ $# -gt 0 ]; do case \"$1\" in multica/task-worker:test) shift; break;; *) shift;; esac; done\nread _\nprintf '%s\\n' '{\"type\":\"result\",\"result\":{\"Status\":\"completed\",\"Output\":\"ok\"}}'\n"
	if err := os.WriteFile(fakeDocker, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	daemon := newSandboxTestDaemon(t, "bwrap")
	daemon.cfg.TaskSandboxBackend = "docker"
	daemon.cfg.DockerCLIPath = fakeDocker
	daemon.cfg.DockerTaskImage = "multica/task-worker:test"
	env := newSandboxTestEnv(t)
	for _, fn := range setup {
		fn(env)
	}

	fakeCodex := filepath.Join(t.TempDir(), "codex")
	if err := os.WriteFile(fakeCodex, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write fake codex: %v", err)
	}
	backend, err := daemon.sandboxedBackend("codex", agent.Config{
		TaskID:         "task-1",
		ExecutablePath: fakeCodex,
	}, env, "", "", "attempt-docker-1", repos, extraCachePaths)
	if err != nil {
		t.Fatalf("sandboxedBackend: %v", err)
	}
	if backend == nil {
		t.Fatal("expected docker backend")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := backend.Execute(ctx, "prompt", agent.ExecOptions{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	_, result := collectSandboxSession(ctx, t, session)
	if result.Status != "completed" {
		t.Fatalf("result = %+v", result)
	}

	raw, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	return env, fakeCodex, string(raw)
}

func collectSandboxSession(ctx context.Context, t *testing.T, session *agent.Session) ([]agent.Message, agent.Result) {
	t.Helper()
	var messages []agent.Message
	for {
		select {
		case message, ok := <-session.Messages:
			if !ok {
				session.Messages = nil
				continue
			}
			messages = append(messages, message)
		case result, ok := <-session.Result:
			if !ok {
				t.Fatal("result channel closed")
			}
			return messages, result
		case <-ctx.Done():
			t.Fatal("timed out waiting for worker result")
		}
	}
}

func TestProtectedModeFailsClosedWithoutSandbox(t *testing.T) {
	daemon := &Daemon{logger: newDiscardLogger()}
	daemon.cfg.TaskProtectedMode = true
	backend, err := daemon.sandboxedBackend("codex", agent.Config{}, newSandboxTestEnv(t), "", "", "attempt-1", nil, nil)
	if err == nil {
		t.Fatal("expected protected mode to refuse host execution")
	}
	if backend != nil {
		t.Fatal("backend should be nil")
	}
}

// dockerBinds extracts the values of every `-v` flag from the newline-joined
// fake docker argv.
func dockerBinds(joined string) []string {
	lines := strings.Split(joined, "\n")
	var binds []string
	for i := 0; i < len(lines); i++ {
		if lines[i] == "-v" && i+1 < len(lines) {
			binds = append(binds, lines[i+1])
			i++
		}
	}
	return binds
}

// dockerEnv extracts the KEY=VALUE pairs of every `-e` flag from the
// newline-joined fake docker argv.
func dockerEnv(joined string) map[string]string {
	lines := strings.Split(joined, "\n")
	env := map[string]string{}
	for i := 0; i < len(lines); i++ {
		if lines[i] == "-e" && i+1 < len(lines) {
			kv := lines[i+1]
			if idx := strings.Index(kv, "="); idx >= 0 {
				env[kv[:idx]] = kv[idx+1:]
			}
			i++
		}
	}
	return env
}

func TestDockerBackendMountsRepoCacheReadOnly(t *testing.T) {
	reposRoot := t.TempDir()
	cacheA := filepath.Join(reposRoot, "workspace-1", "repo-a")
	cacheB := filepath.Join(reposRoot, "workspace-1", "repo-b")
	sibling := filepath.Join(reposRoot, "workspace-1", "repo-sibling")
	for _, dir := range []string{cacheA, cacheB, sibling} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("create %s: %v", dir, err)
		}
	}

	env, _, joined := dockerBackendArgv(t, []workercheckout.Entry{
		{URL: "https://example.com/a", CachePath: cacheA},
		{URL: "https://example.com/b", CachePath: cacheB},
	}, nil)

	binds := dockerBinds(joined)
	joinedBinds := strings.Join(binds, "\n")
	for _, want := range []string{
		cacheA + ":" + cacheA + ":ro",
		cacheB + ":" + cacheB + ":ro",
		filepath.Join(env.RootDir, workercheckout.ManifestFileName) + ":" + sandbox.RepoManifestPath + ":ro",
	} {
		if !strings.Contains(joinedBinds, want) {
			t.Errorf("docker argv missing bind %q:\n%s", want, joinedBinds)
		}
	}
	if strings.Contains(joinedBinds, sibling+":") {
		t.Errorf("a sibling repo under .repos was mounted:\n%s", joinedBinds)
	}
	if strings.Contains(joinedBinds, reposRoot+":") {
		t.Errorf("the whole .repos tree was mounted:\n%s", joinedBinds)
	}
}

func TestDockerBackendRejectsRepoCacheOverlappingWorkdir(t *testing.T) {
	env := newSandboxTestEnv(t)
	homeDir := filepath.Join(env.RootDir, "home")
	tempDir := filepath.Join(env.RootDir, "tmp")

	fakeDocker := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(fakeDocker, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	daemon := newSandboxTestDaemon(t, "bwrap")
	daemon.cfg.TaskSandboxBackend = "docker"
	daemon.cfg.DockerCLIPath = fakeDocker
	daemon.cfg.DockerTaskImage = "multica/task-worker:test"

	for _, cachePath := range []string{
		env.WorkDir,                          // equals the workdir
		filepath.Join(env.WorkDir, "nested"), // inside the workdir
		filepath.Dir(env.WorkDir),            // contains the workdir
		homeDir,                              // equals the home
		tempDir,                              // equals the temp
		env.MulticaConfigRoot,                // equals the config root
	} {
		_, err := daemon.sandboxedBackend("codex", agent.Config{TaskID: "task-1"}, env, "", "", "attempt-1",
			[]workercheckout.Entry{{URL: "https://example.com/a", CachePath: cachePath}}, nil)
		if err == nil {
			t.Errorf("cache path %q overlapping a sandbox root was accepted", cachePath)
			continue
		}
		if !errors.Is(err, errSandboxUnavailable) {
			t.Errorf("cache path %q: err = %v, want errSandboxUnavailable", cachePath, err)
		}
	}
}

func TestIsolatedMarkersReachDockerEnv(t *testing.T) {
	_, _, joined := dockerBackendArgv(t, nil, nil)
	env := dockerEnv(joined)
	if env["MULTICA_HOST_REPO_CHECKOUT"] != "disabled" {
		t.Errorf("MULTICA_HOST_REPO_CHECKOUT = %q, want disabled", env["MULTICA_HOST_REPO_CHECKOUT"])
	}
	if env["MULTICA_ISOLATED_TOOL_BOUNDARY"] != "1" {
		t.Errorf("MULTICA_ISOLATED_TOOL_BOUNDARY = %q, want 1", env["MULTICA_ISOLATED_TOOL_BOUNDARY"])
	}
}

func TestDockerBackendMountsCABundleReadOnly(t *testing.T) {
	env, _, joined := dockerBackendArgv(t, nil, nil, func(env *execenv.Environment) {
		env.WorkerCABundlePath = filepath.Join(env.RootDir, "ca-bundle.pem")
	})

	binds := dockerBinds(joined)
	wantBind := env.WorkerCABundlePath + ":" + sandbox.RepoCABundlePath + ":ro"
	found := false
	for _, bind := range binds {
		if bind == wantBind {
			found = true
		}
	}
	if !found {
		t.Errorf("docker argv missing bind %q:\n%s", wantBind, strings.Join(binds, "\n"))
	}

	caEnv := dockerEnv(joined)
	for _, key := range []string{"GIT_SSL_CAINFO", "SSL_CERT_FILE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE"} {
		if caEnv[key] != sandbox.RepoCABundlePath {
			t.Errorf("%s = %q, want %q", key, caEnv[key], sandbox.RepoCABundlePath)
		}
	}
}

func TestDockerBackendOmitsCABundleWhenUnset(t *testing.T) {
	_, _, joined := dockerBackendArgv(t, nil, nil)

	for _, bind := range dockerBinds(joined) {
		if strings.Contains(bind, sandbox.RepoCABundlePath) {
			t.Errorf("unexpected CA bundle bind %q", bind)
		}
	}
	caEnv := dockerEnv(joined)
	for _, key := range []string{"GIT_SSL_CAINFO", "SSL_CERT_FILE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE"} {
		if _, ok := caEnv[key]; ok {
			t.Errorf("%s = %q, want unset", key, caEnv[key])
		}
	}
}

// TestDockerBackendBindsGenericProviderAndSamePathMounts verifies the newly
// admitted providers bind their host CLI read-only at /usr/local/bin/<basename>,
// and that the per-task QwenPaw workspace and the OpenClaw config/include are
// bound at their own absolute paths so their absolute references stay valid
// inside the container.
func TestDockerBackendBindsGenericProviderAndSamePathMounts(t *testing.T) {
	t.Run("mcode binary", func(t *testing.T) {
		mcode := filepath.Join(t.TempDir(), "mcode")
		if err := os.WriteFile(mcode, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("write fake mcode: %v", err)
		}
		joined := dockerBackendArgvForProvider(t, "mcode", agent.Config{TaskID: "task-1", ExecutablePath: mcode})
		if !strings.Contains(joined, mcode+":/usr/local/bin/mcode:ro") {
			t.Errorf("docker argv missing mcode binary bind:\n%s", joined)
		}
	})

	t.Run("qwenpaw workspace", func(t *testing.T) {
		qwenpaw := filepath.Join(t.TempDir(), "qwenpaw")
		if err := os.MkdirAll(qwenpaw, 0o700); err != nil {
			t.Fatal(err)
		}
		bin := filepath.Join(t.TempDir(), "qwenpaw")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("write fake qwenpaw: %v", err)
		}
		joined := dockerBackendArgvForProvider(t, "qwenpaw", agent.Config{TaskID: "task-1", ExecutablePath: bin}, func(env *execenv.Environment) {
			env.QwenpawWorkspace = qwenpaw
		})
		if !strings.Contains(joined, qwenpaw+":"+qwenpaw+":rw") {
			t.Errorf("docker argv missing qwenpaw same-path bind:\n%s", joined)
		}
	})

	t.Run("openclaw config and include", func(t *testing.T) {
		cfgDir := t.TempDir()
		cfg := filepath.Join(cfgDir, "config.json")
		if err := os.WriteFile(cfg, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		includeRoot := filepath.Join(t.TempDir(), "include")
		if err := os.MkdirAll(includeRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		bin := filepath.Join(t.TempDir(), "openclaw")
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("write fake openclaw: %v", err)
		}
		joined := dockerBackendArgvForProvider(t, "openclaw", agent.Config{TaskID: "task-1", ExecutablePath: bin}, func(env *execenv.Environment) {
			env.OpenclawConfigPath = cfg
			env.OpenclawIncludeRoot = includeRoot
		})
		if !strings.Contains(joined, cfg+":"+cfg+":ro") {
			t.Errorf("docker argv missing openclaw config same-path bind:\n%s", joined)
		}
		if !strings.Contains(joined, includeRoot+":"+includeRoot+":ro") {
			t.Errorf("docker argv missing openclaw include same-path bind:\n%s", joined)
		}
	})
}

// dockerBackendArgvForProvider runs one attempt for an arbitrary provider
// through a fake docker CLI and returns the captured argv. Optional setup
// callbacks mutate the execution environment before the backend is built.
func dockerBackendArgvForProvider(t *testing.T, provider string, config agent.Config, setup ...func(*execenv.Environment)) string {
	t.Helper()
	record := filepath.Join(t.TempDir(), "argv")
	fakeDocker := filepath.Join(t.TempDir(), "docker")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + record + "\nhead -n1 > /dev/null\nprintf '%s\\n' '{\"type\":\"result\",\"result\":{\"Status\":\"completed\",\"Output\":\"ok\"}}'\n"
	if err := os.WriteFile(fakeDocker, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	daemon := newSandboxTestDaemon(t, "bwrap")
	daemon.cfg.TaskSandboxBackend = "docker"
	daemon.cfg.DockerCLIPath = fakeDocker
	daemon.cfg.DockerTaskImage = "multica/task-worker:test"
	env := newSandboxTestEnv(t)
	for _, fn := range setup {
		fn(env)
	}
	backend, err := daemon.sandboxedBackend(provider, config, env, "", "", "attempt-"+provider, nil, nil)
	if err != nil {
		t.Fatalf("sandboxedBackend(%s): %v", provider, err)
	}
	if backend == nil {
		t.Fatalf("expected docker backend for %s", provider)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := backend.Execute(ctx, "prompt", agent.ExecOptions{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	_, result := collectSandboxSession(ctx, t, session)
	if result.Status != "completed" {
		t.Fatalf("result = %+v", result)
	}
	raw, err := os.ReadFile(record)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	return string(raw)
}
