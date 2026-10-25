//go:build agentintegration

package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/daemon/execenv"
	"github.com/multica-ai/multica/server/internal/daemon/sandbox"
	"github.com/multica-ai/multica/server/pkg/agent"
)

// TestRealProviderDockerWorkers exercises the production home preparation,
// launcher, worker protocol, and authenticated tool execution together.
// Run after building multica/task-worker:local, with
// MULTICA_RUN_REAL_AGENT_SMOKE=1 MULTICA_REAL_AGENT_HOME="$HOME".
func TestRealProviderDockerWorkers(t *testing.T) {
	if os.Getenv("MULTICA_RUN_REAL_AGENT_SMOKE") != "1" {
		t.Skip("set MULTICA_RUN_REAL_AGENT_SMOKE=1 to allow real CLI and account access")
	}
	// TestMain isolates HOME for default tests. Real smoke runs must explicitly
	// identify the account home to seed, after the opt-in gate above.
	realHome := os.Getenv("MULTICA_REAL_AGENT_HOME")
	if !filepath.IsAbs(realHome) {
		t.Fatal("MULTICA_REAL_AGENT_HOME must identify the authenticated user's absolute home")
	}
	t.Setenv("HOME", realHome)
	t.Setenv("USERPROFILE", realHome)
	for _, provider := range []string{"codex", "cursor", "opencode", "mcode"} {
		t.Run(provider, func(t *testing.T) {
			binary := provider
			if provider == "cursor" {
				binary = "cursor-agent"
			}
			path, err := exec.LookPath(binary)
			if err != nil {
				t.Fatal(err)
			}
			versionBytes, err := exec.Command(path, "--version").CombinedOutput()
			if err != nil {
				t.Fatalf("version: %v: %s", err, versionBytes)
			}
			version := strings.TrimSpace(string(versionBytes))
			t.Logf("%s: %s", provider, version)
			root := t.TempDir()
			openCodeBin := ""
			if provider == "opencode" {
				openCodeBin = path
			}
			logger := slog.Default()
			task := execenv.TaskContextForEnv{AgentID: "smoke-agent", AgentName: "Smoke"}
			env, err := execenv.Prepare(execenv.PrepareParams{
				WorkspacesRoot: root, WorkspaceID: "worker-smoke", TaskID: "smoke-" + provider,
				Provider: provider, OpenCodeBin: openCodeBin, CodexVersion: version, IsolatedToolBoundary: true, Task: task,
			}, logger)
			if err != nil {
				t.Fatal(err)
			}
			daemon := &Daemon{logger: logger, cfg: Config{
				SandboxEnabled: true, TaskSandboxBackend: "docker", WorkspacesRoot: root,
				DockerTaskImage: realWorkerSmokeImage(),
			}}
			var priorSession string
			rounds := []string{"fresh", "resume", "switch"}
			if provider == "opencode" {
				rounds = []string{"fresh", "resume", "reauth", "switch"}
			}
			if provider == "mcode" && os.Getenv("MULTICA_SMOKE_MCODE_REFRESH") == "1" {
				rounds = []string{"fresh", "resume", "refresh", "switch"}
			}
			for _, round := range rounds {
				if round == "refresh" {
					forceRealMcodeWorkerAuthRefresh(t, path, env)
				}
				if round == "reauth" {
					// Remove only the disposable worker credentials, keeping session history.
					db := filepath.Join(env.RootDir, "home", ".local", "share", "opencode", "opencode.db")
					cmd := exec.Command("python3", "-c", "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('DELETE FROM credential'); c.commit(); c.close()", db)
					if err := cmd.Run(); err != nil {
						t.Fatalf("remove disposable worker credentials: %v", err)
					}
				}
				if round == "switch" {
					otherProvider := "cursor"
					if provider == "cursor" {
						otherProvider = "codex"
					}
					env, err = execenv.Prepare(execenv.PrepareParams{
						WorkspacesRoot: root, WorkspaceID: "worker-smoke", TaskID: "switch-" + provider,
						Provider: otherProvider, IsolatedToolBoundary: true, Task: task,
					}, logger)
					if err != nil {
						t.Fatal(err)
					}
					priorSession = ""
				}
				if round != "fresh" {
					env = execenv.Reuse(execenv.ReuseParams{
						WorkspacesRoot: root, WorkDir: env.WorkDir, Provider: provider,
						CodexVersion: version, OpenCodeBin: openCodeBin, ResumeSessionID: priorSession,
						IsolatedToolBoundary: true, Task: task,
					}, logger)
					if env == nil {
						t.Fatal("Reuse returned nil")
					}
				}
				marker := fmt.Sprintf("worker-%s-%s-%d", provider, round, time.Now().UnixNano())
				if err := os.WriteFile(filepath.Join(env.WorkDir, "input.txt"), []byte(marker), 0o600); err != nil {
					t.Fatal(err)
				}
				agentEnv := map[string]string{}
				if env.CodexHome != "" {
					agentEnv["CODEX_HOME"] = env.CodexHome
				}
				if env.CursorDataDir != "" {
					agentEnv["CURSOR_DATA_DIR"] = env.CursorDataDir
				}
				backend, err := daemon.sandboxedBackend(provider, agent.Config{
					ExecutablePath: path, CLIVersion: version, BuiltinRuntime: provider == "opencode",
					TaskID: "smoke-" + provider, Env: agentEnv, Logger: logger,
				}, env, "", "", fmt.Sprintf("smoke-%s-%s-%d", provider, round, time.Now().UnixNano()), nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
				t.Cleanup(cancel)
				prompt := "Use a shell tool to read input.txt and copy its exact bytes to output-" + round + ".txt in the current workspace. Then reply with the contents. Do not call external services or Multica commands."
				session, err := backend.Execute(ctx, prompt, agent.ExecOptions{
					Cwd: env.WorkDir, Model: os.Getenv("MULTICA_SMOKE_MODEL_" + strings.ToUpper(provider)),
					Timeout: 220 * time.Second, IsolatedToolBoundary: true, ResumeSessionID: priorSession,
				})
				if err != nil {
					cancel()
					t.Fatal(err)
				}
				messages, result := collectSandboxSession(ctx, t, session)
				cancel()
				if result.Status != "completed" {
					if provider == "mcode" {
						_ = filepath.WalkDir(filepath.Join(env.RootDir, "home", ".minimax"), func(path string, entry os.DirEntry, err error) error {
							if err == nil && (entry.Name() == "auth-state.json" || entry.Name() == "mcode-region.json") {
								data, _ := os.ReadFile(path)
								var state map[string]any
								_ = json.Unmarshal(data, &state)
								t.Logf("MCode state %s: region=%v buildEnv=%v status=%v store=%v regions=%v", path, state["region"], state["buildEnv"], state["status"], state["storeKind"], state["regions"])
							}
							return nil
						})
					}
					t.Fatalf("%s failed: status=%s error=%s", round, result.Status, result.Error)
				}
				data, err := os.ReadFile(filepath.Join(env.WorkDir, "output-"+round+".txt"))
				if err != nil || string(data) != marker {
					for _, message := range messages {
						if message.Type == agent.MessageToolUse || message.Type == agent.MessageToolResult || message.Type == agent.MessageError {
							t.Logf("tool: type=%s name=%s output=%s content=%s", message.Type, message.Tool, message.Output, message.Content)
						}
					}
					t.Fatalf("%s tool artifact mismatch: read=%v content=%q final=%q", round, err, data, result.Output)
				}
				if !strings.Contains(result.Output, marker) {
					t.Fatalf("%s final response did not contain the tool result: %q", round, result.Output)
				}
				tools := 0
				for _, message := range messages {
					if message.Type == agent.MessageToolUse {
						tools++
					}
				}
				if tools == 0 || result.SessionID == "" {
					t.Fatalf("%s missing observable tools/session: tools=%d session=%q", round, tools, result.SessionID)
				}
				if (round == "resume" || round == "reauth" || round == "refresh") && result.SessionID != priorSession {
					t.Fatalf("resume lost its session: before=%s after=%s", priorSession, result.SessionID)
				}
				priorSession = result.SessionID
				t.Logf("%s %s: completed, tools=%d, artifact verified, session=%s", provider, round, tools, priorSession)
			}
		})
	}
}

// This opt-in probe invokes the installed MCode OAuth implementation inside a
// worker. It rotates the existing login's tokens without fabricating expiry or
// copying secrets, then the next native ACP run must resume the same session.
func forceRealMcodeWorkerAuthRefresh(t *testing.T, executable string, env *execenv.Environment) {
	t.Helper()
	if os.Getenv("MULTICA_RUN_REAL_AGENT_SMOKE") != "1" || os.Getenv("MULTICA_SMOKE_MCODE_REFRESH") != "1" {
		t.Fatal("real OAuth refresh requires both explicit opt-ins")
	}
	_, runtimeBinds, handled, err := sandbox.DockerMcodeContainerAgentBind(executable, filepath.Join(env.RootDir, "mcode-refresh-launcher"))
	if err != nil || !handled {
		t.Fatalf("MCode runtime mount: handled=%t err=%v", handled, err)
	}
	authBinds, authEnv, err := sandbox.DockerMcodeAuthBinds(filepath.Join(env.RootDir, "home"), env.McodeDataDir)
	if err != nil {
		t.Fatal(err)
	}
	containerEnv := sandbox.ContainerEnv(authEnv)
	probe := `import fs from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
try {
 const release=(await fs.readFile('/usr/local/current','utf8')).trim();
 const chunks=path.join('/usr/local/releases',release,'lib/node_modules/@minimax-ai/code/chunks');
 let file;
 for(const name of await fs.readdir(chunks)) {
  if(name.endsWith('.js') && (await fs.readFile(path.join(chunks,name),'utf8')).includes('Shared MCode OAuth requires all three public OAuth endpoints')) {file=path.join(chunks,name);break;}
 }
 if(!file)throw new Error('OAuth module not found');
 const mod=await import(pathToFileURL(file));
 const Manager=Object.values(mod).find(v=>typeof v==='function' && typeof v.prototype?.getAccessToken==='function' && typeof v.prototype?.login==='function');
 const dataDir=process.env.MINIMAX_DATA_DIR;
 const pref=JSON.parse(await fs.readFile(path.join(dataDir,'preferences/mcode-region.json'),'utf8'));
 const region=pref.regions.prod;
 if(region!=='cn' && region!=='en')throw new Error('OAuth region preference is missing');
 const ns=mod.b({dataDir,buildEnv:'prod',region});
 const manager=new Manager({namespace:ns,credentialStore:mod.m({authHome:ns.namespaceHome}),oauthClient:new mod.e(mod.f(process.env,ns)),initialize:()=>mod.c(ns)});
 const before=await manager.getStatus();
 await manager.getAccessToken({requiredScopes:['agent.default'],minValidityMs:86400000});
 const after=await manager.getStatus();
 console.log(JSON.stringify({status:after.status,before:before.generation,after:after.generation}));
} catch(e) {console.error('OAuth refresh probe failed: '+(e.code??e.name));process.exitCode=1;}`
	args, err := sandbox.BuildDockerRunArgs(sandbox.DockerRunSpec{
		DockerPath: "docker", Image: realWorkerSmokeImage(), User: fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		Env: containerEnv, Binds: append(runtimeBinds, authBinds...),
	}, "node", "--input-type=module", "-e", probe)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	type probeOutput struct {
		data []byte
		err  error
	}
	completed := make(chan probeOutput, 2)
	for range 2 {
		go func() {
			data, err := exec.CommandContext(ctx, "docker", args...).Output()
			completed <- probeOutput{data, err}
		}()
	}
	for range 2 {
		output := <-completed
		if output.err != nil {
			t.Fatalf("native MCode OAuth refresh inside concurrent worker: %v", output.err)
		}
		var result struct {
			Status string `json:"status"`
			Before int    `json:"before"`
			After  int    `json:"after"`
		}
		if err := json.Unmarshal(output.data, &result); err != nil {
			t.Fatal("OAuth refresh returned an invalid summary")
		}
		if result.Status != "authenticated" || result.After <= result.Before {
			t.Fatalf("OAuth refresh did not advance authenticated generation: %+v", result)
		}
		t.Logf("concurrent worker OAuth refresh: generation %d -> %d, status %s", result.Before, result.After, result.Status)
	}
}

// This handshake probe does not create a model session or require a usable
// OAuth token. It covers startup migrations with the CLI installed on the host.
func TestRealMcodeDockerInitialize(t *testing.T) {
	if os.Getenv("MULTICA_RUN_REAL_AGENT_SMOKE") != "1" {
		t.Skip("real agent CLI access requires explicit opt-in")
	}
	realHome := os.Getenv("MULTICA_REAL_AGENT_HOME")
	if !filepath.IsAbs(realHome) {
		t.Fatal("MULTICA_REAL_AGENT_HOME must be absolute")
	}
	t.Setenv("HOME", realHome)
	executable, err := exec.LookPath("mcode")
	if err != nil {
		t.Fatal(err)
	}
	env, err := execenv.Prepare(execenv.PrepareParams{
		WorkspacesRoot: t.TempDir(), WorkspaceID: "worker-smoke", TaskID: "mcode-initialize", Provider: "mcode", IsolatedToolBoundary: true,
	}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(env.RootDir, "home")
	containerCLI, runtimeBinds, handled, err := sandbox.DockerMcodeContainerAgentBind(executable, filepath.Join(env.RootDir, "mcode-launcher"))
	if err != nil || !handled {
		t.Fatalf("MCode installation mount: handled=%t err=%v", handled, err)
	}
	authBinds, authEnv, err := sandbox.DockerMcodeAuthBinds(home, env.McodeDataDir)
	if err != nil {
		t.Fatal(err)
	}
	binds := append([]string{sandbox.DockerBind(home, sandbox.HomePath, "rw"), sandbox.DockerBind(env.WorkDir, sandbox.CheckoutPath, "rw")}, runtimeBinds...)
	binds = append(binds, authBinds...)
	image := realWorkerSmokeImage()
	containerName := sandbox.SanitizeContainerName(fmt.Sprintf("mcode-init-%d", time.Now().UnixNano()))
	args, err := sandbox.BuildDockerRunArgs(sandbox.DockerRunSpec{
		ContainerName: containerName,
		DockerPath:    "docker", Image: image, User: fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), Workdir: sandbox.CheckoutPath,
		Env: sandbox.ContainerEnv(authEnv), Binds: binds,
	}, containerCLI, "acp")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", containerName).Run()
	})
	defer func() { _ = stdin.Close(); cancel(); _ = cmd.Wait() }()
	request := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":1,"clientCapabilities":{"fs":{"readTextFile":true,"writeTextFile":true},"terminal":true},"clientInfo":{"name":"multica-lock-smoke","version":"1"}}}`
	if _, err := io.WriteString(stdin, request+"\n"); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var response struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
		}
		if json.Unmarshal(scanner.Bytes(), &response) == nil && response.ID == 1 && len(response.Result) > 0 {
			t.Log("MCode initialize succeeded with private data directory and writable migration-lock parent")
			return
		}
	}
	_ = cmd.Wait()
	t.Fatalf("MCode initialization failed: migration_lock_error=%t timeout=%t", strings.Contains(stderr.String(), "agent_name_conflict_migration_failed:lock"), ctx.Err() != nil)
}

func realWorkerSmokeImage() string {
	if image := os.Getenv("MULTICA_SMOKE_WORKER_IMAGE"); image != "" {
		return image
	}
	return "multica/task-worker:local"
}
