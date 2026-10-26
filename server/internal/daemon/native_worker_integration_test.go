//go:build agentintegration && linux

package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/daemon/execenv"
	"github.com/multica-ai/multica/server/pkg/agent"
)

func realNativeSmokeInputs(t *testing.T) (string, string) {
	t.Helper()
	if os.Getenv("MULTICA_RUN_REAL_AGENT_SMOKE") != "1" {
		t.Skip("set MULTICA_RUN_REAL_AGENT_SMOKE=1 to allow real CLI and account access")
	}
	home := os.Getenv("MULTICA_REAL_AGENT_HOME")
	worker := os.Getenv("MULTICA_NATIVE_SMOKE_WORKER")
	if !filepath.IsAbs(home) || !filepath.IsAbs(worker) {
		t.Fatal("explicit MULTICA_REAL_AGENT_HOME and MULTICA_NATIVE_SMOKE_WORKER absolute paths are required")
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if info, err := os.Stat(worker); err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		t.Fatal("native smoke worker must be the built Multica CLI executable")
	}
	return home, worker
}

func newRealNativeSmokeDaemon(root, worker string) *Daemon {
	return &Daemon{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), cfg: Config{SandboxEnabled: true, TaskSandboxBackend: "bwrap", WorkspacesRoot: root, SandboxSelfPath: worker, DockerMemoryBytes: 2 << 30, DockerPIDsLimit: 512, DockerNanoCPUs: 2e9}}
}

func TestNativeCoexistenceBarrierRequiresActiveTools(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	barrier := newNativeToolBarrier(ctx, false)
	defer barrier.server.Close()
	defer cancel()
	results := make(chan int, 3)
	request := func(name string) {
		go func() {
			response, err := http.Get(barrier.server.URL + "/" + name)
			if err != nil {
				results <- 0
				return
			}
			_ = response.Body.Close()
			results <- response.StatusCode
		}()
	}
	request("worker-a")
	request("worker-b")
	deadline := time.Now().Add(3 * time.Second)
	for barrier.activeCount() < 2 {
		if time.Now().After(deadline) {
			t.Fatal("tool requests did not reach the barrier")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-results:
		t.Fatal("barrier accepted sequential execution without the host")
	case <-time.After(30 * time.Millisecond):
	}
	request("host")
	for range 3 {
		select {
		case status := <-results:
			if status != http.StatusOK {
				t.Fatalf("overlap barrier status=%d", status)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent tools did not leave the barrier")
		}
	}
	if !barrier.reached() {
		t.Fatal("successful tool responses did not establish overlap")
	}
}

type nativeToolBarrier struct {
	server   *httptest.Server
	mu       sync.Mutex
	active   map[string]*http.Request
	done     chan struct{}
	complete bool
}

func newNativeToolBarrier(ctx context.Context, serialWorkers bool) *nativeToolBarrier {
	b := &nativeToolBarrier{active: map[string]*http.Request{}, done: make(chan struct{})}
	b.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name != "host" && name != "worker-a" && name != "worker-b" {
			http.Error(w, "unknown participant", http.StatusBadRequest)
			return
		}
		b.mu.Lock()
		b.active[name] = r
		host, workers := false, 0
		for name, request := range b.active {
			if request.Context().Err() != nil {
				continue
			}
			if name == "host" {
				host = true
			} else {
				workers++
			}
		}
		if !b.complete && host && (workers == 2 || serialWorkers && workers >= 1) {
			b.complete = true
			close(b.done)
		}
		b.mu.Unlock()
		defer func() {
			b.mu.Lock()
			if b.active[name] == r {
				delete(b.active, name)
			}
			b.mu.Unlock()
		}()
		select {
		case <-b.done:
			_, _ = w.Write([]byte("overlap-proven"))
		case <-r.Context().Done():
		case <-ctx.Done():
			http.Error(w, "overlap was not established", http.StatusRequestTimeout)
		}
	}))
	return b
}

func (b *nativeToolBarrier) activeCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.active)
}

func (b *nativeToolBarrier) reached() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.complete
}

func TestRealNativeTaskAfterWorkerFailure(t *testing.T) {
	_, worker := realNativeSmokeInputs(t)
	for _, provider := range []string{"codex", "cursor", "opencode"} {
		t.Run(provider, func(t *testing.T) {
			binary := provider
			if provider == "cursor" {
				binary = "cursor-agent"
			}
			executable, err := exec.LookPath(binary)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			d := newRealNativeSmokeDaemon(root, worker)
			runtime, _, err := d.nativeRuntime(t.Context(), provider, executable)
			if err != nil {
				t.Fatal(err)
			}
			env, err := execenv.Prepare(execenv.PrepareParams{WorkspacesRoot: root, WorkspaceID: "native-failure", TaskID: provider, Provider: provider, NativeProfile: &execenv.NativeProfile{Home: runtime.Home, Env: runtime.Env}}, d.logger)
			if err != nil {
				t.Fatal(err)
			}
			env.ReleaseLock()
			config := agent.Config{ExecutablePath: executable, CLIVersion: runtime.Version, Env: runtime.Env, Logger: d.logger, BuiltinRuntime: true}
			backend, err := d.sandboxedBackend(provider, config, env, "", "", "failed-worker-"+provider, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			native := backend.(*nativeAttemptBackend)
			// Resolve the real profile normally, then fail the adapter inside the
			// actual worker. No installed executable or shared state is changed.
			native.worker.Config.ExecutablePath = filepath.Join(env.WorkDir, "missing-native-smoke-cli")
			ready := false
			native.worker.OnWorkerReady = func() { ready = true }
			session, err := backend.Execute(t.Context(), "This CLI cannot start.", agent.ExecOptions{Cwd: env.WorkDir, Timeout: 15 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			_, failed := collectSandboxSession(t.Context(), t, session)
			if !ready || failed.Status != "failed" || failed.Error == "" {
				t.Fatalf("worker failure was not exercised: ready=%v status=%s error=%s", ready, failed.Status, failed.Error)
			}
			if err := os.WriteFile(filepath.Join(env.WorkDir, "input.txt"), []byte("after-worker-failure"), 0600); err != nil {
				t.Fatal(err)
			}
			backend, err = d.sandboxedBackend(provider, config, env, "", "", "after-failure-"+provider, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
			defer cancel()
			session, err = backend.Execute(ctx, "Use a shell tool to copy input.txt exactly to output.txt, then say done. Do not call external services or Multica commands.", agent.ExecOptions{Cwd: env.WorkDir, Model: os.Getenv("MULTICA_SMOKE_MODEL_" + strings.ToUpper(provider)), Timeout: 160 * time.Second, IsolatedToolBoundary: true})
			if err != nil {
				t.Fatal(err)
			}
			messages, result := collectSandboxSession(ctx, t, session)
			tools := 0
			for _, message := range messages {
				if message.Type == agent.MessageToolUse {
					tools++
				}
			}
			data, readErr := os.ReadFile(filepath.Join(env.WorkDir, "output.txt"))
			if result.Status != "completed" || result.SessionID == "" || tools == 0 || readErr != nil || string(data) != "after-worker-failure" {
				t.Fatalf("fresh task after failed worker: status=%s tools=%d read=%v error=%s", result.Status, tools, readErr, result.Error)
			}
			t.Logf("worker failed after readiness; next task artifact verified session=%s", result.SessionID)
		})
	}
}

// TestRealProviderNativeWorkers uses the production resolver, preparation,
// launcher, worker protocol and provider adapters. Every remembered canary is
// removed from the workspace before resume, and checked through a tool artifact.
func TestRealProviderNativeWorkers(t *testing.T) {
	_, worker := realNativeSmokeInputs(t)
	for _, provider := range []string{"codex", "cursor", "opencode"} {
		t.Run(provider, func(t *testing.T) {
			binary := provider
			if provider == "cursor" {
				binary = "cursor-agent"
			}
			executable, err := exec.LookPath(binary)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			d := newRealNativeSmokeDaemon(root, worker)
			runtime, _, err := d.nativeRuntime(t.Context(), provider, executable)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("provider=%s version=%s", provider, runtime.Version)
			selected := &execenv.NativeProfile{Home: runtime.Home, Env: runtime.Env}
			task := execenv.TaskContextForEnv{AgentID: "native-smoke-agent", AgentName: "Native Smoke"}
			env, err := execenv.Prepare(execenv.PrepareParams{WorkspacesRoot: root, WorkspaceID: "native-smoke", TaskID: "fresh-" + provider, Provider: provider, NativeProfile: selected, Task: task}, d.logger)
			if err != nil {
				t.Fatal(err)
			}
			env.ReleaseLock()
			random := make([]byte, 16)
			if _, err := rand.Read(random); err != nil {
				t.Fatal(err)
			}
			canary := "native-" + hex.EncodeToString(random)
			if err := os.WriteFile(filepath.Join(env.WorkDir, "input.txt"), []byte(canary), 0600); err != nil {
				t.Fatal(err)
			}
			prior := ""
			rounds := []string{"fresh", "resume", "restart", "after_failure", "provider_change"}
			for _, round := range rounds {
				if round == "restart" {
					d = newRealNativeSmokeDaemon(root, worker)
				}
				if round == "after_failure" {
					ctx, cancel := context.WithCancel(t.Context())
					cancel()
					backend, err := d.sandboxedBackend(provider, agent.Config{ExecutablePath: executable, TaskID: "native-smoke"}, env, "", "", fmt.Sprintf("native-%s-canceled", provider), nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					session, launchErr := backend.Execute(ctx, "This canceled task must not run tools.", agent.ExecOptions{Cwd: env.WorkDir, Timeout: time.Second})
					if launchErr == nil {
						_, result := collectSandboxSession(t.Context(), t, session)
						if result.Status == "completed" {
							t.Fatal("pre-canceled attempt was completed")
						}
					}
					prior = ""
				}
				if round == "provider_change" {
					other := "cursor"
					if provider == "cursor" {
						other = "codex"
					}
					otherExe, err := exec.LookPath(map[string]string{"cursor": "cursor-agent", "codex": "codex"}[other])
					if err != nil {
						t.Fatal(err)
					}
					otherRuntime, _, err := d.nativeRuntime(t.Context(), other, otherExe)
					if err != nil {
						t.Fatal(err)
					}
					switched := execenv.Reuse(execenv.ReuseParams{WorkspacesRoot: root, WorkDir: env.WorkDir, Provider: other, NativeProfile: &execenv.NativeProfile{Home: otherRuntime.Home, Env: otherRuntime.Env}, Task: task}, d.logger)
					if switched == nil {
						t.Fatal("provider change preparation failed")
					}
					switchInput := filepath.Join(env.WorkDir, "switch-input.txt")
					if err := os.WriteFile(switchInput, []byte("provider-switch"), 0600); err != nil {
						t.Fatal(err)
					}
					otherBackend, err := d.sandboxedBackend(other, agent.Config{ExecutablePath: otherExe, TaskID: "native-switch", Env: otherRuntime.Env, Logger: d.logger, BuiltinRuntime: true}, switched, "", "", fmt.Sprintf("native-switch-%s-%d", provider, time.Now().UnixNano()), nil, nil)
					if err != nil {
						t.Fatal(err)
					}
					switchCtx, switchCancel := context.WithTimeout(t.Context(), 180*time.Second)
					switchSession, err := otherBackend.Execute(switchCtx, "Use a shell tool to copy switch-input.txt exactly to switch-output.txt, then say done. Do not call external services or Multica commands.", agent.ExecOptions{Cwd: switched.WorkDir, Model: os.Getenv("MULTICA_SMOKE_MODEL_" + strings.ToUpper(other)), Timeout: 160 * time.Second, IsolatedToolBoundary: true})
					if err != nil {
						switchCancel()
						t.Fatal(err)
					}
					_, switchResult := collectSandboxSession(switchCtx, t, switchSession)
					switchCancel()
					switchData, switchErr := os.ReadFile(filepath.Join(switched.WorkDir, "switch-output.txt"))
					if switchResult.Status != "completed" || switchErr != nil || string(switchData) != "provider-switch" || switchResult.SessionID == "" {
						t.Fatalf("switch to %s failed: status=%s read=%v error=%s", other, switchResult.Status, switchErr, switchResult.Error)
					}
					_ = os.Remove(switchInput)
					_ = os.Remove(filepath.Join(switched.WorkDir, "switch-output.txt"))
					prior = ""
				}
				if round != "fresh" {
					env = execenv.Reuse(execenv.ReuseParams{WorkspacesRoot: root, WorkDir: env.WorkDir, Provider: provider, NativeProfile: selected, ResumeSessionID: prior, Task: task}, d.logger)
					if env == nil {
						t.Fatal("native reuse failed")
					}
				}
				name := "output-" + round + ".txt"
				prompt := "Use a shell tool to write the exact original canary bytes from our earlier conversation to " + name + " in the current workspace. Use printf '%s' so the file contains no trailing newline. Do not read old session files. Do not call external services or Multica commands. Then say done."
				if prior == "" {
					if err := os.WriteFile(filepath.Join(env.WorkDir, "input.txt"), []byte(canary), 0600); err != nil {
						t.Fatal(err)
					}
					prompt = "First use a shell tool to run cat input.txt so its literal text appears in the tool output. Then copy its exact bytes into " + name + " in the current workspace. Remember that literal text for a later turn. Do not call external services or Multica commands. Then say done."
				}
				backend, err := d.sandboxedBackend(provider, agent.Config{ExecutablePath: executable, TaskID: "native-smoke", Env: selected.Env, Logger: d.logger, BuiltinRuntime: true}, env, "", "", fmt.Sprintf("native-%s-%s-%d", provider, round, time.Now().UnixNano()), nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
				session, err := backend.Execute(ctx, prompt, agent.ExecOptions{Cwd: env.WorkDir, Model: os.Getenv("MULTICA_SMOKE_MODEL_" + strings.ToUpper(provider)), Timeout: 160 * time.Second, ResumeSessionID: prior, ResumeExpected: prior != "", IsolatedToolBoundary: true})
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				messages, result := collectSandboxSession(ctx, t, session)
				cancel()
				if result.Status != "completed" {
					t.Fatalf("%s: status=%s error=%s", round, result.Status, result.Error)
				}
				content, err := os.ReadFile(filepath.Join(env.WorkDir, name))
				if err != nil || string(content) != canary {
					t.Fatalf("%s: remembered tool artifact mismatch: read=%v got=%.120q want=%q", round, err, content, canary)
				}
				tools := 0
				for _, message := range messages {
					if message.Type == agent.MessageToolUse {
						tools++
					}
				}
				if tools == 0 || result.SessionID == "" {
					t.Fatalf("%s: tools=%d session=%q", round, tools, result.SessionID)
				}
				if prior != "" && (result.SessionID != prior || result.ResumeRejected) {
					t.Fatalf("%s: continuity lost: before=%s after=%s rejected=%v", round, prior, result.SessionID, result.ResumeRejected)
				}
				prior = result.SessionID
				_ = os.Remove(filepath.Join(env.WorkDir, "input.txt"))
				_ = os.Remove(filepath.Join(env.WorkDir, name))
				t.Logf("%s: artifact verified tools=%d session=%s", round, tools, prior)
			}
		})
	}
}

func TestRealNativeOpenCodeHostWorkerContinuity(t *testing.T) {
	_, worker := realNativeSmokeInputs(t)
	executable, err := exec.LookPath("opencode")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	d := newRealNativeSmokeDaemon(root, worker)
	runtime, _, err := d.nativeRuntime(t.Context(), "opencode", executable)
	if err != nil {
		t.Fatal(err)
	}
	selected := &execenv.NativeProfile{Home: runtime.Home, Env: runtime.Env}
	env, err := execenv.Prepare(execenv.PrepareParams{WorkspacesRoot: root, WorkspaceID: "native-bridge", TaskID: "opencode", Provider: "opencode", NativeProfile: selected}, d.logger)
	if err != nil {
		t.Fatal(err)
	}
	env.ReleaseLock()
	canary := fmt.Sprintf("bridge-%d", time.Now().UnixNano())
	_ = os.WriteFile(filepath.Join(env.WorkDir, "input.txt"), []byte(canary), 0600)
	prior := ""
	for _, kind := range []string{"host_fresh", "host_resume", "worker_resume", "host_after_worker"} {
		config := agent.Config{ExecutablePath: executable, CLIVersion: runtime.Version, Env: runtime.Env, Logger: d.logger, BuiltinRuntime: true, TaskID: "native-bridge"}
		var backend agent.Backend
		if kind == "worker_resume" {
			backend, err = d.sandboxedBackend("opencode", config, env, "", "", "opencode-bridge", nil, nil)
		} else {
			backend, err = agent.ResolveBackend("opencode", config)
		}
		if err != nil {
			t.Fatal(err)
		}
		prompt := "Use a shell tool to write the original canary from our earlier conversation to output.txt. Do not read session files. Then say done."
		if prior == "" {
			prompt = "Use a shell tool to read input.txt so its bytes appear in the tool output, then write those exact bytes to output.txt. Remember the bytes for a later turn. Then say done."
		}
		ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
		session, err := backend.Execute(ctx, prompt, agent.ExecOptions{NativeProfile: true, Cwd: env.WorkDir, Model: os.Getenv("MULTICA_SMOKE_MODEL_OPENCODE"), Timeout: 160 * time.Second, ResumeSessionID: prior, ResumeExpected: prior != "", IsolatedToolBoundary: true})
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		messages, result := collectSandboxSession(ctx, t, session)
		cancel()
		if result.Status != "completed" {
			t.Fatalf("%s baseline: status=%s error=%s", kind, result.Status, result.Error)
		}
		data, err := os.ReadFile(filepath.Join(env.WorkDir, "output.txt"))
		if err != nil || string(data) != canary {
			t.Fatalf("%s artifact mismatch: %v; output=%.768s", kind, err, result.Output)
		}
		tools := 0
		for _, message := range messages {
			if message.Type == agent.MessageToolUse {
				tools++
			}
		}
		if tools == 0 || result.SessionID == "" || (prior != "" && (prior != result.SessionID || result.ResumeRejected)) {
			t.Fatalf("%s continuity failed: before=%s after=%s tools=%d", kind, prior, result.SessionID, tools)
		}
		prior = result.SessionID
		_ = os.Remove(filepath.Join(env.WorkDir, "input.txt"))
		_ = os.Remove(filepath.Join(env.WorkDir, "output.txt"))
		t.Logf("%s artifact verified session=%s", kind, prior)
	}
}

func TestRealNativeProfileHostAndTwoWorkers(t *testing.T) {
	_, worker := realNativeSmokeInputs(t)
	for _, provider := range []string{"codex", "cursor", "opencode"} {
		t.Run(provider, func(t *testing.T) {
			binary := provider
			if provider == "cursor" {
				binary = "cursor-agent"
			}
			executable, err := exec.LookPath(binary)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			d := newRealNativeSmokeDaemon(root, worker)
			runtime, _, err := d.nativeRuntime(t.Context(), provider, executable)
			if err != nil {
				t.Fatal(err)
			}
			selected := &execenv.NativeProfile{Home: runtime.Home, Env: runtime.Env}
			barrierCtx, stopBarrier := context.WithCancel(t.Context())
			barrier := newNativeToolBarrier(barrierCtx, false)
			defer barrier.server.Close()
			defer stopBarrier()
			type run struct {
				name    string
				env     *execenv.Environment
				backend agent.Backend
				result  agent.Result
				tools   int
				err     error
			}
			runs := make([]run, 3)
			for i, name := range []string{"worker-a", "worker-b", "host"} {
				env, err := execenv.Prepare(execenv.PrepareParams{WorkspacesRoot: root, WorkspaceID: "native-concurrent", TaskID: provider + "-" + name, Provider: provider, NativeProfile: selected}, d.logger)
				if err != nil {
					t.Fatal(err)
				}
				env.ReleaseLock()
				_ = os.WriteFile(filepath.Join(env.WorkDir, "input.txt"), []byte(provider+"-"+name), 0600)
				config := agent.Config{ExecutablePath: executable, CLIVersion: runtime.Version, CodexVersion: runtime.Version, Env: runtime.Env, Logger: d.logger, BuiltinRuntime: true, TaskID: provider + "-" + name}
				var backend agent.Backend
				if name == "host" {
					backend, err = agent.ResolveBackend(provider, config)
				} else {
					backend, err = d.sandboxedBackend(provider, config, env, "", "", fmt.Sprintf("native-concurrent-%s-%s-%d", provider, name, time.Now().UnixNano()), nil, nil)
				}
				if err != nil {
					t.Fatal(err)
				}
				runs[i] = run{name: name, env: env, backend: backend}
			}
			begin := make(chan struct{})
			var wg sync.WaitGroup
			for i := range runs {
				wg.Add(1)
				go func(r *run) {
					defer wg.Done()
					<-begin
					ctx, cancel := context.WithTimeout(t.Context(), 240*time.Second)
					defer cancel()
					prompt := "Use a shell tool to run synchronously: curl -fsS --max-time 150 '" + barrier.server.URL + "/" + r.name + "' && cp input.txt output.txt. Wait for the command to finish, then say done. This local endpoint is the test barrier; do not use other network services or Multica commands."

					session, err := r.backend.Execute(ctx, prompt, agent.ExecOptions{NativeProfile: true, Cwd: r.env.WorkDir, Model: os.Getenv("MULTICA_SMOKE_MODEL_" + strings.ToUpper(provider)), Timeout: 220 * time.Second, IsolatedToolBoundary: true})
					if err != nil {
						r.err = err
						return
					}
					for session.Messages != nil || session.Result != nil {
						select {
						case message, ok := <-session.Messages:
							if !ok {
								session.Messages = nil
							} else if message.Type == agent.MessageToolUse {
								r.tools++
							}
						case result, ok := <-session.Result:
							if !ok {
								session.Result = nil
								continue
							}
							r.result = result
							return
						case <-ctx.Done():
							r.err = ctx.Err()
							return
						}
					}
				}(&runs[i])
			}
			close(begin)
			wg.Wait()
			if !barrier.reached() {
				t.Error("host and workers never reached the tool barrier concurrently")
			}
			for _, r := range runs {
				if r.err != nil || r.result.Status != "completed" {
					t.Errorf("%s: status=%s error=%v provider_error=%s", r.name, r.result.Status, r.err, r.result.Error)
					continue
				}
				data, err := os.ReadFile(filepath.Join(r.env.WorkDir, "output.txt"))
				if err != nil || string(data) != provider+"-"+r.name || r.tools == 0 || r.result.SessionID == "" {
					t.Errorf("%s artifact/session mismatch: read=%v tools=%d session=%s", r.name, err, r.tools, r.result.SessionID)
				} else {
					t.Logf("%s: artifact verified tools=%d session=%s", r.name, r.tools, r.result.SessionID)
				}
			}
		})
	}
}
