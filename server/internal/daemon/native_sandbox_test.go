//go:build linux

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/daemon/repocache"
	"github.com/multica-ai/multica/server/internal/daemon/sandbox"
	"github.com/multica-ai/multica/server/internal/daemon/workercheckout"
	"github.com/multica-ai/multica/server/pkg/agent"
)

type fakeNativeScope struct {
	err     error
	stopped int
}

func (s *fakeNativeScope) Preflight(context.Context) error { return s.err }
func (s *fakeNativeScope) Command(_ string, argv []string) (*exec.Cmd, error) {
	if s.err != nil {
		return nil, s.err
	}
	return exec.Command(argv[0], argv[1:]...), nil
}
func (s *fakeNativeScope) Stop(context.Context, string) error { s.stopped++; return nil }

func TestNativeBackendPreservesFourProviderPathsAndWarmResolution(t *testing.T) {
	for _, provider := range []string{"codex", "cursor", "opencode"} {
		t.Run(provider, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			d := newSandboxTestDaemon(t, "bwrap")
			t.Setenv("HOME", home)
			scope := &fakeNativeScope{}
			d.nativeScope = scope
			calls := 0
			d.nativeResolver = sandbox.NewNativeRuntimeResolver(func(context.Context, string, string) (string, error) { calls++; return "2.1.4", nil })
			record := filepath.Join(t.TempDir(), "manifest")
			argv := filepath.Join(t.TempDir(), "argv")
			fake := filepath.Join(t.TempDir(), "bwrap")
			t.Setenv("NATIVE_MANIFEST", record)
			t.Setenv("NATIVE_ARGV", argv)
			script := `#!/bin/sh
printf '%s\n' "$@" > "$NATIVE_ARGV"
read line
printf '%s\n' "$line" > "$NATIVE_MANIFEST"
printf '%s\n' '{"type":"worker_ready"}' '{"type":"cli_started"}' '{"type":"result","result":{"Status":"completed","SessionID":"fixture-session"}}'
`
			if err := os.WriteFile(fake, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			d.cfg.BwrapPath = fake
			exe := filepath.Join(home, "install", "bin", provider)
			if err := os.MkdirAll(filepath.Dir(exe), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
				t.Fatal(err)
			}

			env := newSandboxTestEnv(t)
			cache := filepath.Join(d.cfg.WorkspacesRoot, ".repos", "ws", "fixture.git")
			if err := os.MkdirAll(cache, 0700); err != nil {
				t.Fatal(err)
			}
			entries := []workercheckout.Entry{{URL: "https://example.test/team/repo.git", CachePath: cache}}
			if err := workercheckout.WriteManifest(filepath.Join(env.RootDir, workercheckout.ManifestFileName), workercheckout.Manifest{Repos: entries}); err != nil {
				t.Fatal(err)
			}
			for i := range 2 {
				backend, err := d.sandboxedBackend(provider, agent.Config{ExecutablePath: exe, TaskID: "task", Env: map[string]string{"HOME": "/other-user", "CODEX_HOME": "/other-user/.codex"}}, env, "", "", "attempt-native", entries, nil)
				if err != nil {
					t.Fatal(err)
				}
				session, err := backend.Execute(t.Context(), "hello", agent.ExecOptions{})
				if err != nil {
					t.Fatal(err)
				}
				for range session.Messages {
				}
				result := <-session.Result
				if result.Status != "completed" {
					t.Fatalf("result: %+v", result)
				}
				data, err := os.ReadFile(record)
				if err != nil {
					t.Fatal(err)
				}
				manifest, err := sandbox.ReadManifest(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				if manifest.Config.ExecutablePath != exe || manifest.Config.Env["HOME"] != home || manifest.Exec.Cwd != env.WorkDir {
					t.Fatalf("original identity lost: %+v", manifest)
				}
				if provider == "codex" && manifest.Config.CodexVersion != "2.1.4" {
					t.Fatalf("Codex version did not match selected executable: %s", manifest.Config.CodexVersion)
				}
				args, _ := os.ReadFile(argv)
				if !strings.Contains(string(args), cache+"\n"+cache) || !strings.Contains(string(args), "--ro-bind") {
					t.Fatalf("repo cache absent: %s", args)
				}
				if calls != 1 {
					t.Fatalf("warm launch %d re-probed installed CLI: calls=%d", i, calls)
				}
			}
			if err := os.WriteFile(exe, []byte("#!/bin/sh\n# upgraded installation\nexit 0\n"), 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := d.sandboxedBackend(provider, agent.Config{ExecutablePath: exe}, env, "", "", "upgraded", entries, nil); err != nil {
				t.Fatal(err)
			}
			if calls != 2 {
				t.Fatalf("installation upgrade reused stale version: %d probes", calls)
			}
			if scope.stopped != 2 {
				t.Fatalf("attempt cleanup count=%d", scope.stopped)
			}
		})
	}
}

func TestNativeBackendFailsClosedWhenResourcePreflightFails(t *testing.T) {
	d := newSandboxTestDaemon(t, "bwrap")
	d.nativeScope = &fakeNativeScope{err: errors.New("memory controller unavailable")}
	d.nativeResolver = sandbox.NewNativeRuntimeResolver(func(context.Context, string, string) (string, error) { return "fixture", nil })
	exe := filepath.Join(t.TempDir(), "cli")
	_ = os.WriteFile(exe, []byte("#!/bin/sh\n"), 0700)
	_, err := d.sandboxedBackend("opencode", agent.Config{ExecutablePath: exe}, newSandboxTestEnv(t), "", "", "attempt", nil, nil)
	if !errors.Is(err, errSandboxUnavailable) || !strings.Contains(err.Error(), "memory controller") {
		t.Fatalf("preflight did not fail closed: %v", err)
	}
}

func TestNativeAttemptTimingUsesNamedIntervalsAndTags(t *testing.T) {
	var out bytes.Buffer
	now := time.Now()
	timing := newAttemptTiming(slog.New(slog.NewJSONHandler(&out, nil)), "task", "attempt", "cursor", "bwrap", func() time.Time { return now })
	marks := []struct {
		point string
		ms    int64
	}{{"repo_started", 10}, {"repo_ready", 45}, {"runtime_started", 50}, {"runtime_ready", 75}, {"environment_started", 80}, {"environment_ready", 100}, {"sandbox_spawn", 120}, {"worker_ready", 170}, {"cli_started", 190}, {"first_output", 250}, {"finished", 300}}
	for _, mark := range marks {
		now = now.Add(time.Duration(mark.ms) * time.Millisecond)
		timing.Mark(mark.point)
	}
	decoder := json.NewDecoder(&out)
	got := map[string]int64{}
	for {
		var entry map[string]any
		if err := decoder.Decode(&entry); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		for _, tag := range []string{"task_id", "attempt_id", "provider", "backend"} {
			if entry[tag] == nil {
				t.Errorf("missing %s", tag)
			}
		}
		for _, name := range []string{"repo_prepare_ms", "runtime_resolve_ms", "environment_prepare_ms", "sandbox_launch_ms", "cli_start_ms", "first_output_ms", "turn_total_ms"} {
			if value, ok := entry[name].(float64); ok {
				got[name] = int64(value)
			}
		}
	}
	for name, want := range map[string]int64{"repo_prepare_ms": 45, "runtime_resolve_ms": 75, "environment_prepare_ms": 100, "sandbox_launch_ms": 170, "cli_start_ms": 190, "first_output_ms": 250, "turn_total_ms": 1390} {
		if got[name] != want {
			t.Errorf("%s=%d, want %d", name, got[name], want)
		}
	}
}

func TestNativeProductionBoundaryFakeWorker(t *testing.T) {
	if os.Getenv("MULTICA_BWRAP_SMOKE") != "1" {
		t.Skip("set MULTICA_BWRAP_SMOKE=1 for production native kernel probe")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, key := range nativeSelectorKeys {
		t.Setenv(key, "")
	}
	d := &Daemon{logger: newDiscardLogger(), cfg: Config{SandboxEnabled: true, TaskSandboxBackend: "bwrap", WorkspacesRoot: filepath.Join(home, "tasks"), DockerMemoryBytes: 256 << 20, DockerPIDsLimit: 32, DockerNanoCPUs: 500000000}}
	if err := os.MkdirAll(d.cfg.WorkspacesRoot, 0700); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(home, "install", "bin", "opencode")
	if err := os.MkdirAll(filepath.Dir(exe), 0700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(exe, []byte("#!/bin/sh\nprintf '2.1.4\\n'\n"), 0700)
	worker := filepath.Join(t.TempDir(), "worker")
	script := `#!/bin/sh
set -eu
read manifest
printf '%s\n' '{"type":"worker_ready"}'
test ! -e "$HOME/.ssh/id_test"
printf artifact > ./native-artifact
printf shared > "$HOME/.local/share/opencode/native-profile-artifact"
printf '%s\n' '{"type":"cli_started"}' '{"type":"result","result":{"Status":"completed","SessionID":"native-fake"}}'
`
	_ = os.WriteFile(worker, []byte(script), 0700)
	d.cfg.SandboxSelfPath = worker
	secret := filepath.Join(home, ".ssh", "id_test")
	_ = os.MkdirAll(filepath.Dir(secret), 0700)
	_ = os.WriteFile(secret, []byte("forbidden"), 0600)
	env := newSandboxTestEnv(t)
	// The workdir is below the original home, so mount order must preserve it.
	env.WorkDir = filepath.Join(d.cfg.WorkspacesRoot, "task", "workdir")
	env.RootDir = filepath.Dir(env.WorkDir)
	env.MulticaConfigRoot = filepath.Join(env.RootDir, "config")
	for _, path := range []string{env.WorkDir, env.MulticaConfigRoot} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	backend, err := d.sandboxedBackend("opencode", agent.Config{ExecutablePath: exe, TaskID: "fake-task"}, env, "", "", "fake-production", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	session, err := backend.Execute(t.Context(), "hello", agent.ExecOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for range session.Messages {
	}
	result := <-session.Result
	if result.Status != "completed" {
		t.Fatalf("native fake worker failed: %+v", result)
	}
	for path, want := range map[string]string{filepath.Join(env.WorkDir, "native-artifact"): "artifact", filepath.Join(home, ".local/share/opencode/native-profile-artifact"): "shared"} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != want {
			t.Fatalf("artifact %s=%q, %v", path, data, err)
		}
	}
}

func TestNativeAgentEntryHealsWithoutUnboundedHostVersionProbe(t *testing.T) {
	d := newSandboxTestDaemon(t, "bwrap")
	exe := filepath.Join(t.TempDir(), "new-codex")
	marker := filepath.Join(t.TempDir(), "unbounded-probe")
	t.Setenv("NATIVE_VERSION_HOST_PROBE", marker)
	_ = os.WriteFile(exe, []byte("#!/bin/sh\nprintf called > \"$NATIVE_VERSION_HOST_PROBE\"\n"), 0700)
	calls := 0
	d.nativeResolver = sandbox.NewNativeRuntimeResolver(func(context.Context, string, string) (string, error) { calls++; return "0.163.0", nil })
	entry := AgentEntry{Path: filepath.Join(t.TempDir(), "deleted-release"), Command: exe}
	for range 2 {
		resolved, version, profile, err := d.resolveNativeAgentEntry(t.Context(), "codex", entry)
		if err != nil {
			t.Fatal(err)
		}
		if resolved.Path != exe || version != "0.163.0" || profile == nil {
			t.Fatalf("native upgrade resolution lost: %+v, %s, %+v", resolved, version, profile)
		}
	}
	if calls != 1 {
		t.Fatalf("warm native resolution re-probed version: %d", calls)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("native entry resolution executed a CLI outside its isolated detector")
	}
}

func TestNativeRunTaskPreservesOwnerAuthAndTaskCacheManifest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, key := range nativeSelectorKeys {
		t.Setenv(key, "")
	}
	cache := &fakePrepareCache{}
	d, root, _ := newDockerTaskDaemon(t, cache)
	d.cfg.TaskSandboxBackend = "bwrap"
	d.nativeScope = &fakeNativeScope{}
	calls := 0
	d.nativeResolver = sandbox.NewNativeRuntimeResolver(func(context.Context, string, string) (string, error) { calls++; return "0.163.0", nil })
	d.cfg.SandboxSelfPath = d.cfg.Agents["codex"].Path
	manifestRecord := filepath.Join(t.TempDir(), "manifest")
	t.Setenv("NATIVE_MANIFEST", manifestRecord)
	bwrap := filepath.Join(t.TempDir(), "bwrap")
	script := `#!/bin/sh
read line
printf '%s\n' "$line" > "$NATIVE_MANIFEST"
printf '%s\n' '{"type":"worker_ready"}' '{"type":"cli_started"}' '{"type":"message","message":{"Type":"text","Content":"done"}}' '{"type":"result","result":{"Status":"completed","Output":"done"}}'
`
	_ = os.WriteFile(bwrap, []byte(script), 0700)
	d.cfg.BwrapPath = bwrap
	original := filepath.Join(home, ".codex", "config.toml")
	_ = os.MkdirAll(filepath.Dir(original), 0700)
	_ = os.WriteFile(original, []byte("# original owner config\n"), 0600)
	auth := filepath.Join(home, ".codex", "auth.json")
	_ = os.WriteFile(auth, []byte("original auth sentinel"), 0600)
	before, _ := os.Stat(auth)
	bare := createBareRepoDir(t, filepath.Join(root, ".repos", "ws-1", "test-user", "fixture.git"))
	cache.prepared = []repocache.PreparedRepo{{URL: "https://example.com/fixture", BarePath: bare, CommitSHA: fakeCommitSHA}}
	for _, id := range []string{"native-task-1", "native-task-2"} {
		task := dockerTask(id, []RepoData{{URL: "https://example.com/fixture"}})
		task.Agent.ThinkingLevel = "high"
		task.Agent.CustomEnv = map[string]string{"HOME": "/rerunning-user", "CODEX_HOME": "/rerunning-user/.codex"}
		result, err := d.runTask(t.Context(), task, "codex", 0, newDiscardLogger())
		if err != nil {
			t.Fatal(err)
		}
		if result.Status != "completed" {
			t.Fatalf("task failed: %+v", result)
		}
		for _, path := range []string{"home", "codex-home", "opencode-credentials.json"} {
			if _, err := os.Stat(filepath.Join(result.EnvRoot, path)); !os.IsNotExist(err) {
				t.Fatalf("native task copied provider state: %s", path)
			}
		}
		data, _ := os.ReadFile(manifestRecord)
		manifest, err := sandbox.ReadManifest(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if !manifest.Exec.NativeProfile || manifest.Config.Env["HOME"] != home || manifest.Config.Env["CODEX_HOME"] != filepath.Dir(auth) || manifest.Config.Env["MULTICA_TOKEN"] != task.AuthToken || manifest.Config.Env["TMPDIR"] != "/tmp" {
			t.Fatalf("task/profile selection lost: %+v", manifest.Config.Env)
		}
		if got := readManifestRepos(t, filepath.Join(result.EnvRoot, workercheckout.ManifestFileName)); len(got) != 1 || got[0].CachePath != bare {
			t.Fatalf("native task repo manifest: %+v", got)
		}
	}
	after, _ := os.Stat(auth)
	data, _ := os.ReadFile(auth)
	if !os.SameFile(before, after) || string(data) != "original auth sentinel" {
		t.Fatal("native task changed owner auth")
	}
	config, _ := os.ReadFile(original)
	if string(config) != "# original owner config\n" {
		t.Fatal("daemon wrote task settings into shared config")
	}
	if calls != 1 || cache.prepareCount() != 2 || len(cache.recordedDependents()) != 2 {
		t.Fatalf("native warm/cache invariants: probes=%d prepares=%d dependents=%d", calls, cache.prepareCount(), len(cache.recordedDependents()))
	}
}

func TestNativeMcodeLeaseBlocksTheSecondWorkerUntilCleanup(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	releaseFile := filepath.Join(t.TempDir(), "release")
	t.Setenv("NATIVE_LEASE_RELEASE", releaseFile)
	script := `read _
printf '%s\n' '{"type":"worker_ready"}'
while [ ! -f "$NATIVE_LEASE_RELEASE" ]; do sleep 0.01; done
printf '%s\n' '{"type":"result","result":{"Status":"completed"}}'
`
	ready := make(chan struct{})
	firstWorker := &sandbox.IPCBackend{Provider: "mcode", Launch: func() (*exec.Cmd, error) { return exec.Command("/bin/sh", "-c", script), nil }, OnWorkerReady: func() { close(ready) }}
	secondWorker := &sandbox.IPCBackend{Provider: "mcode", Launch: func() (*exec.Cmd, error) { return exec.Command("/bin/sh", "-c", script), nil }}
	profile := sandbox.NativeRuntime{ProfileLimit: 1, ProfileKey: strings.Repeat("e", 64)}
	first, err := (&nativeAttemptBackend{worker: firstWorker, profile: profile}).Execute(t.Context(), "first", agent.ExecOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer os.WriteFile(releaseFile, []byte("release"), 0600)
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("first worker did not become ready")
	}
	type started struct {
		session *agent.Session
		err     error
	}
	second := make(chan started, 1)
	go func() {
		session, err := (&nativeAttemptBackend{worker: secondWorker, profile: profile}).Execute(t.Context(), "second", agent.ExecOptions{})
		second <- started{session, err}
	}()
	select {
	case result := <-second:
		t.Fatalf("second worker bypassed native profile lease: %v", result.err)
	case <-time.After(40 * time.Millisecond):
	}
	if err := os.WriteFile(releaseFile, []byte("release"), 0600); err != nil {
		t.Fatal(err)
	}
	for range first.Messages {
	}
	if result := <-first.Result; result.Status != "completed" {
		t.Fatalf("first: %+v", result)
	}
	select {
	case result := <-second:
		if result.err != nil {
			t.Fatal(result.err)
		}
		for range result.session.Messages {
		}
		if final := <-result.session.Result; final.Status != "completed" {
			t.Fatalf("second: %+v", final)
		}
	case <-time.After(time.Second):
		t.Fatal("profile lease remained held after cleanup")
	}
}
