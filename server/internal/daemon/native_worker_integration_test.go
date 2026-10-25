//go:build agentintegration && linux

package daemon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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
	for _, provider := range []string{"codex", "cursor", "opencode", "mcode"} {
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
				prompt := "Use a shell tool to write the exact original canary bytes from our earlier conversation to " + name + " in the current workspace. Do not read old session files. Do not call external services or Multica commands. Then say done."
				if prior == "" {
					if err := os.WriteFile(filepath.Join(env.WorkDir, "input.txt"), []byte(canary), 0600); err != nil {
						t.Fatal(err)
					}
					prompt = "Use a shell tool to read input.txt and copy its exact bytes into " + name + " in the current workspace. Remember those bytes for a later turn. Do not call external services or Multica commands. Then say done."
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
					t.Fatalf("%s: remembered tool artifact mismatch: %v", round, err)
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
	for _, provider := range []string{"codex", "cursor", "opencode", "mcode"} {
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
			type run struct {
				name          string
				env           *execenv.Environment
				backend       agent.Backend
				start, finish time.Time
				result        agent.Result
				tools         int
				err           error
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
					if provider != "mcode" {
						backend, err = agent.ResolveBackend(provider, config)
					}
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
					if provider == "mcode" && r.name == "host" {
						r.result, r.tools, r.err = runRealNativeMcodeHostExec(ctx, executable, r.env.WorkDir, runtime.Env)
						r.finish = time.Now()
						return
					}
					session, err := r.backend.Execute(ctx, "Use a shell tool to copy input.txt exactly to output.txt in this workspace. Do not call external services or Multica commands. Then say done.", agent.ExecOptions{NativeProfile: true, Cwd: r.env.WorkDir, Model: os.Getenv("MULTICA_SMOKE_MODEL_" + strings.ToUpper(provider)), Timeout: 220 * time.Second, IsolatedToolBoundary: true, OnCLIStarted: func() { r.start = time.Now() }})
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
							r.finish = time.Now()
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

func TestRealNativeMcodeRefresh(t *testing.T) {
	if os.Getenv("MULTICA_RUN_REAL_AGENT_SMOKE") != "1" || os.Getenv("MULTICA_SMOKE_MCODE_REFRESH") != "1" {
		t.Skip("real OAuth refresh requires both explicit smoke opt-ins")
	}
	_, worker := realNativeSmokeInputs(t)
	executable, err := exec.LookPath("mcode")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	d := newRealNativeSmokeDaemon(root, worker)
	runtime, _, err := d.nativeRuntime(t.Context(), "mcode", executable)
	if err != nil {
		t.Fatal(err)
	}
	selected := &execenv.NativeProfile{Home: runtime.Home, Env: runtime.Env}
	prepare := func(id string) *execenv.Environment {
		t.Helper()
		env, err := execenv.Prepare(execenv.PrepareParams{WorkspacesRoot: root, WorkspaceID: "native-refresh", TaskID: id, Provider: "mcode", NativeProfile: selected}, d.logger)
		if err != nil {
			t.Fatal(err)
		}
		env.ReleaseLock()
		return env
	}
	env := prepare("session")
	canary := fmt.Sprintf("refresh-%d", time.Now().UnixNano())
	_ = os.WriteFile(filepath.Join(env.WorkDir, "input.txt"), []byte(canary), 0600)
	turn := func(prior, prompt, artifact string) agent.Result {
		t.Helper()
		backend, err := d.sandboxedBackend("mcode", agent.Config{ExecutablePath: executable, TaskID: "native-refresh", Env: runtime.Env, Logger: d.logger}, env, "", "", fmt.Sprintf("native-refresh-turn-%d", time.Now().UnixNano()), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 180*time.Second)
		defer cancel()
		session, err := backend.Execute(ctx, prompt, agent.ExecOptions{Cwd: env.WorkDir, Timeout: 160 * time.Second, ResumeSessionID: prior, ResumeExpected: prior != "", IsolatedToolBoundary: true})
		if err != nil {
			t.Fatal(err)
		}
		messages, result := collectSandboxSession(ctx, t, session)
		if result.Status != "completed" {
			t.Fatalf("refresh continuity: status=%s error=%s", result.Status, result.Error)
		}
		data, err := os.ReadFile(filepath.Join(env.WorkDir, artifact))
		tools := 0
		for _, message := range messages {
			if message.Type == agent.MessageToolUse {
				tools++
			}
		}
		if err != nil || string(data) != canary || tools == 0 || result.SessionID == "" || (prior != "" && (result.SessionID != prior || result.ResumeRejected)) {
			t.Fatalf("refresh continuity artifact/session failed: read=%v tools=%d before=%s after=%s", err, tools, prior, result.SessionID)
		}
		return result
	}
	fresh := turn("", "Use a shell tool to read input.txt so its bytes appear in the tool output, then write those exact bytes to before.txt. Remember the bytes for a later turn. Then say done.", "before.txt")
	_ = os.Remove(filepath.Join(env.WorkDir, "input.txt"))
	_ = os.Remove(filepath.Join(env.WorkDir, "before.txt"))
	canonical, err := filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	prefix := filepath.Dir(filepath.Dir(canonical))
	probe := `import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const out=process.env.NATIVE_REFRESH_OUT;
try {
 const prefix=process.env.NATIVE_MCODE_PREFIX;
 const release=(await fs.readFile(path.join(prefix,'current'),'utf8')).trim();
 const chunks=path.join(prefix,'releases',release,'lib/node_modules/@minimax-ai/code/chunks');
 let file;
 for(const name of await fs.readdir(chunks)){
  if(name.endsWith('.js')&&(await fs.readFile(path.join(chunks,name),'utf8')).includes('Shared MCode OAuth requires all three public OAuth endpoints')){file=path.join(chunks,name);break;}
 }
 if(!file)throw new Error('OAuth module unavailable');
 const mod=await import(pathToFileURL(file));
 const Manager=Object.values(mod).find(value=>typeof value==='function'&&typeof value.prototype?.getAccessToken==='function'&&typeof value.prototype?.login==='function');
 const dataDir=process.env.MINIMAX_DATA_DIR;
 const preferences=JSON.parse(await fs.readFile(path.join(dataDir,'preferences/mcode-region.json'),'utf8'));
 const region=preferences.regions.prod;
 if(region!=='cn'&&region!=='en')throw new Error('OAuth region missing');
 const ns=mod.b({dataDir,buildEnv:'prod',region});
 const manager=new Manager({namespace:ns,credentialStore:mod.m({authHome:ns.namespaceHome}),oauthClient:new mod.e(mod.f(process.env,ns)),initialize:()=>mod.c(ns)});
 const before=await manager.getStatus();
 await fs.writeFile(out+'.ready','ready');
 for(let i=0; i<3000; i++){try{await fs.stat(out+'.go');break;}catch{await new Promise(resolve=>setTimeout(resolve,10));}}
 await manager.getAccessToken({requiredScopes:['agent.default'],minValidityMs:86400000});
 const after=await manager.getStatus();
 await fs.writeFile(out,JSON.stringify({status:after.status,before:before.generation,after:after.generation}));
 process.exit(0);
} catch(error){console.error('Native OAuth probe failed: '+(error.code??error.name));process.exit(1);}
`
	nativeEnv := prepare("refresh-worker")
	hostDir := t.TempDir()
	nativeScript := filepath.Join(nativeEnv.WorkDir, "refresh.mjs")
	hostScript := filepath.Join(hostDir, "refresh.mjs")
	_ = os.WriteFile(nativeScript, []byte(probe), 0600)
	_ = os.WriteFile(hostScript, []byte(probe), 0600)
	nativeOut := filepath.Join(nativeEnv.WorkDir, "refresh.json")
	hostOut := filepath.Join(hostDir, "refresh.json")
	nativeVars := maps.Clone(runtime.Env)
	nativeVars["NODE_OPTIONS"] = "--import=" + nativeScript
	nativeVars["NATIVE_MCODE_PREFIX"] = prefix
	nativeVars["NATIVE_REFRESH_OUT"] = nativeOut
	backend, err := d.sandboxedBackend("mcode", agent.Config{ExecutablePath: executable, TaskID: "native-auth-probe", Env: nativeVars, Logger: d.logger}, nativeEnv, "", "", fmt.Sprintf("native-auth-probe-%d", time.Now().UnixNano()), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	// The preload uses MCode's original interpreter and public OAuth manager,
	// then exits before ACP initialization. Its artifact, not the ACP outcome,
	// proves refresh; the real resumed model turn below proves continuity.
	nativeSession, err := backend.Execute(ctx, "OAuth refresh probe", agent.ExecOptions{Cwd: nativeEnv.WorkDir, Timeout: 55 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	host := exec.CommandContext(ctx, executable, "--version")
	host.Dir = hostDir
	host.Env = append(os.Environ(), "NODE_OPTIONS=--import="+hostScript, "MINIMAX_DATA_DIR="+runtime.Env["MINIMAX_DATA_DIR"], "MAVIS_DATA_DIR="+runtime.Env["MAVIS_DATA_DIR"], "NATIVE_MCODE_PREFIX="+prefix, "NATIVE_REFRESH_OUT="+hostOut)
	var hostError bytes.Buffer
	host.Stderr = &hostError
	if err := host.Start(); err != nil {
		t.Fatal(err)
	}
	defer host.Process.Kill()
	for _, out := range []string{nativeOut, hostOut} {
		deadline := time.Now().Add(30 * time.Second)
		ready := false
		for time.Now().Before(deadline) {
			if _, err := os.Stat(out + ".ready"); err == nil {
				ready = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !ready {
			t.Fatalf("OAuth refresh participant did not reach barrier: %s", filepath.Base(out))
		}
	}
	for _, out := range []string{nativeOut, hostOut} {
		if err := os.WriteFile(out+".go", []byte("go"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := host.Wait(); err != nil {
		t.Fatalf("native host OAuth refresh failed: %v: %s", err, hostError.String())
	}
	_, _ = collectSandboxSession(ctx, t, nativeSession)
	for _, out := range []string{nativeOut, hostOut} {
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		var status struct {
			Status        string `json:"status"`
			Before, After int64
		}
		if err := json.Unmarshal(data, &status); err != nil {
			t.Fatal(err)
		}
		if status.Status != "authenticated" || status.After <= status.Before {
			t.Fatalf("native OAuth generation did not rotate: %+v", status)
		}
		t.Logf("OAuth refresh authenticated generation=%d->%d", status.Before, status.After)
	}
	resumed := turn(fresh.SessionID, "Use a shell tool to write the original remembered canary from our earlier conversation to after.txt. Do not read session files. Then say done.", "after.txt")
	t.Logf("refresh continuity artifact verified session=%s", resumed.SessionID)
}

// The host counterpart uses MCode's normal headless CLI, rather than starting
// another ACP client with Multica's application identity outside the sandbox.
func runRealNativeMcodeHostExec(ctx context.Context, executable, cwd string, env map[string]string) (agent.Result, int, error) {
	prompt := "Use a shell tool to copy input.txt exactly to output.txt in this workspace. Do not call external services or Multica commands. Then say done."
	cmd := exec.CommandContext(ctx, executable, "exec", "--cwd", cwd, "--permission", "full", "--output-format", "stream-json", "--timeout", "220s", "--input", "-")
	cmd.Dir = cwd
	cmd.Stdin = strings.NewReader(prompt)
	cmd.Env = os.Environ()
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard
	err := cmd.Run()
	result := agent.Result{Status: "failed"}
	seen := map[string]bool{}
	scanner := bufio.NewScanner(&stdout)
	scanner.Buffer(make([]byte, 64<<10), 8<<20)
	var visit func(any)
	visit = func(value any) {
		switch object := value.(type) {
		case map[string]any:
			if object["type"] == "tool_call" {
				if id, ok := object["id"].(string); ok && id != "" {
					seen[id] = true
				}
			}
			if object["type"] == "exec.result" {
				if id, ok := object["sessionId"].(string); ok {
					result.SessionID = id
				}
				if object["status"] == "succeeded" {
					result.Status = "completed"
				} else if status, ok := object["status"].(string); ok {
					result.Error = "mcode exec status: " + status
				}
			}
			for _, child := range object {
				visit(child)
			}
		case []any:
			for _, child := range object {
				visit(child)
			}
		}
	}
	for scanner.Scan() {
		var frame any
		if json.Unmarshal(scanner.Bytes(), &frame) == nil {
			visit(frame)
		}
	}
	if err != nil {
		result.Status = "failed"
		result.Error = fmt.Sprintf("mcode exec exited: %v", err)
	}
	if scanner.Err() != nil {
		return result, len(seen), scanner.Err()
	}
	return result, len(seen), err
}
