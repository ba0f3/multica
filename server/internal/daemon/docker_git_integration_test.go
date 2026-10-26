//go:build linux && agentintegration

package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/daemon/sandbox"
	"github.com/multica-ai/multica/server/internal/daemon/workercheckout"
	"github.com/multica-ai/multica/server/pkg/agent"
	"golang.org/x/crypto/ssh"
)

// This probe uses only ephemeral Git keys and a local SSH Git server. It never
// looks up an agent CLI, reads a real account, or writes to a remote repository.
func TestDockerWorkerGitRoundTrip(t *testing.T) {
	if os.Getenv("MULTICA_DOCKER_GIT_SMOKE") != "1" {
		t.Skip("set MULTICA_DOCKER_GIT_SMOKE=1 for the synthetic Docker Git round trip")
	}
	testWorkerGitRoundTrip(t, "docker")
}

func TestNativeWorkerGitRoundTrip(t *testing.T) {
	if os.Getenv("MULTICA_NATIVE_GIT_SMOKE") != "1" {
		t.Skip("set MULTICA_NATIVE_GIT_SMOKE=1 and MULTICA_GIT_SMOKE_WORKER for the synthetic native Git round trip")
	}
	if os.Getenv("MULTICA_GIT_SMOKE_WORKER") == "" {
		t.Fatal("MULTICA_GIT_SMOKE_WORKER must name the built worker")
	}
	testWorkerGitRoundTrip(t, "bwrap")
}

func testWorkerGitRoundTrip(t *testing.T, mode string) {
	var docker string
	var err error
	if mode == "docker" {
		docker, err = exec.LookPath("docker")
		if err != nil {
			t.Fatal(err)
		}
	}
	image := os.Getenv("MULTICA_DOCKER_GIT_IMAGE")
	if image == "" {
		image = sandbox.DefaultDockerTaskImage
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	git := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_AUTHOR_NAME=Git probe", "GIT_AUTHOR_EMAIL=git@example.test", "GIT_COMMITTER_NAME=Git probe", "GIT_COMMITTER_EMAIL=git@example.test")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %s: %v", args, out, err)
		}
		return strings.TrimSpace(string(out))
	}
	// Cache targets retain their host path. Keep this fixture outside the
	// container's /tmp bind, as in a normal home-based workspace cache.
	cacheRoot, err := os.MkdirTemp("/var/tmp", "git-cache-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(cacheRoot) })
	remote, seed, cache := filepath.Join(t.TempDir(), "remote.git"), t.TempDir(), filepath.Join(cacheRoot, "cache.git")
	git("", "init", "--bare", "-q", remote)
	git(seed, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(seed, "base.txt"), []byte("base"), 0600); err != nil {
		t.Fatal(err)
	}
	git(seed, "add", "base.txt")
	git(seed, "commit", "-qm", "base")
	base := git(seed, "rev-parse", "HEAD")
	git(seed, "push", "-q", remote, "HEAD:refs/heads/main")
	git("", "clone", "--bare", "-q", remote, cache)
	git(cache, "update-ref", "refs/remotes/origin/main", base)
	// This commit is deliberately absent from the mounted cache.
	if err := os.WriteFile(filepath.Join(seed, "pulled.txt"), []byte("fresh remote"), 0600); err != nil {
		t.Fatal(err)
	}
	git(seed, "add", "pulled.txt")
	git(seed, "commit", "-qm", "remote update")
	git(seed, "push", "-q", remote, "HEAD:refs/heads/main")
	_, private, err := generateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	address, hostKey := syntheticGitSSHServer(t, ctx, remote, signer)
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	known := "[127.0.0.1]:" + port + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostKey))) + "\n"
	if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte(known), 0600); err != nil {
		t.Fatal(err)
	}
	server := fakeGitSigningServer(t, signer)
	profile := gitAgentTestProfile(t)
	d := newGitAgentTestDaemon(t, server.URL, profile)
	d.cfg.SandboxEnabled, d.cfg.TaskSandboxBackend, d.cfg.DockerCLIPath, d.cfg.DockerTaskImage, d.cfg.DockerNetworkMode = true, "docker", docker, image, "host"
	task := gitAgentTestTask()
	task.ID, task.GitSigningDaemonToken = "docker-git", "mdt_synthetic"
	task.Repos = []RepoData{{URL: "https://127.0.0.1/repo.git"}}
	var portNumber int
	if _, err := fmt.Sscan(port, &portNumber); err != nil {
		t.Fatal(err)
	}
	task.GitIdentities = []GitIdentityBinding{{ProviderID: "synthetic", Host: "127.0.0.1", Port: portNumber}}
	socket, stop := d.startGitAgentSocket(ctx, task, profile, "git-roundtrip")
	defer stop()
	if socket == "" {
		t.Fatal("synthetic signing socket missing")
	}
	env := newSandboxTestEnv(t)
	values, err := taskWorkerGitEnvironment(task, socket, env)
	if err != nil {
		t.Fatal(err)
	}
	values["MULTICA_TASK_CONFIG_ROOT"] = env.MulticaConfigRoot
	values["MULTICA_TASK_ID"], values["MULTICA_AGENT_NAME"] = task.ID, "Git probe"
	values["MULTICA_ISOLATED_TOOL_BOUNDARY"], values["MULTICA_HOST_REPO_CHECKOUT"] = "1", "disabled"
	entry := workercheckout.Entry{URL: task.Repos[0].URL, CachePath: cache, CommitSHA: base}
	if err := workercheckout.WriteManifest(filepath.Join(env.RootDir, workercheckout.ManifestFileName), workercheckout.Manifest{Repos: []workercheckout.Entry{entry}}); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(t.TempDir(), "codex")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nprintf '0.163.0\\n'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	var worker *sandbox.IPCBackend
	if mode == "docker" {
		backend, err := d.dockerBackend("codex", agent.Config{ExecutablePath: exe, Env: values}, env, socket, "git-roundtrip", []workercheckout.Entry{entry}, nil)
		if err != nil {
			t.Fatal(err)
		}
		worker = backend.(*sandbox.IPCBackend)
	} else {
		d.cfg.TaskSandboxBackend, d.cfg.SandboxSelfPath = "bwrap", os.Getenv("MULTICA_GIT_SMOKE_WORKER")
		d.cfg.DockerMemoryBytes, d.cfg.DockerPIDsLimit, d.cfg.DockerNanoCPUs = 2<<30, 512, 2e9
		backend, err := d.bwrapBackend("codex", agent.Config{ExecutablePath: exe, Env: values}, env, profile, socket, fmt.Sprintf("git-%d", time.Now().UnixNano()), []workercheckout.Entry{entry}, nil)
		if err != nil {
			t.Fatal(err)
		}
		native := backend.(*nativeAttemptBackend)
		copy := *native.worker
		cleanup, err := native.prepare(&copy)
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		worker = &copy
	}
	defer worker.StopAttempt()
	launch, err := worker.Launch()
	if err != nil {
		t.Fatal(err)
	}
	// Keep the production user's mounts, environment, and security flags; use
	// Git directly so model behavior cannot make the transport test pass.
	script := `set -euo pipefail
test -n "$(id -un)"
checkout=$(multica repo checkout https://127.0.0.1/repo.git)
cd "$checkout"
test "$(git rev-parse HEAD)" = '` + base + `'
git pull --ff-only origin main
test "$(cat pulled.txt)" = 'fresh remote'
printf 'worker push' > pushed.txt
git add pushed.txt
git -c user.name='Git probe' -c user.email=git@example.test commit -qm 'worker push'
git push origin HEAD:refs/heads/worker-result
mkdir ../ref-check
cd ../ref-check
checkout=$(multica repo checkout https://127.0.0.1/repo.git --ref worker-result)
test "$(cat "$checkout/pushed.txt")" = 'worker push'
`
	args := append([]string{}, launch.Args[1:len(launch.Args)-2]...)
	if mode == "bwrap" {
		args = append(args, "/usr/bin/env")
		for key, value := range worker.Config.Env {
			args = append(args, key+"="+value)
		}
	}
	args = append(args, "bash", "-c", script)
	cmd := exec.CommandContext(ctx, launch.Path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s Git round trip: %v\n%s", mode, err, out)
	}
	if got := git(remote, "show", "refs/heads/worker-result:pushed.txt"); got != "worker push" {
		t.Fatal("pushed artifact missing")
	}
	if got := git(cache, "rev-parse", "refs/remotes/origin/main"); got != base {
		t.Fatal("read-only cache ref changed")
	}
	t.Logf("backend=%s uid=%d checkout from cache, pull uncached commit, signed SSH push verified; cache unchanged", mode, os.Getuid())
}

func syntheticGitSSHServer(t *testing.T, ctx context.Context, repo string, client ssh.Signer) (string, ssh.PublicKey) {
	t.Helper()
	_, private, err := generateEd25519Key()
	if err != nil {
		t.Fatal(err)
	}
	host, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if string(key.Marshal()) != string(client.PublicKey().Marshal()) {
			return nil, fmt.Errorf("unexpected task key")
		}
		return &ssh.Permissions{}, nil
	}}
	config.AddHostKey(host)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var clients sync.Map
	var workers sync.WaitGroup
	done := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
		clients.Range(func(key, _ any) bool { _ = key.(net.Conn).Close(); return true })
		workers.Wait()
	})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			clients.Store(conn, true)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer clients.Delete(conn)
				defer conn.Close()
				sc, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(requests)
				for request := range channels {
					if request.ChannelType() != "session" {
						_ = request.Reject(ssh.UnknownChannelType, "session only")
						continue
					}
					channel, requests, err := request.Accept()
					if err != nil {
						continue
					}
					for request := range requests {
						var command struct{ Command string }
						if request.Type != "exec" || ssh.Unmarshal(request.Payload, &command) != nil {
							_ = request.Reply(false, nil)
							continue
						}
						program := ""
						for _, candidate := range []string{"git-upload-pack", "git-receive-pack"} {
							if command.Command == candidate+" '/repo.git'" {
								program = candidate
							}
						}
						if program == "" {
							_ = request.Reply(false, nil)
							break
						}
						_ = request.Reply(true, nil)
						cmd := exec.CommandContext(ctx, program, repo)
						cmd.Stdin, cmd.Stdout, cmd.Stderr = channel, channel, channel.Stderr()
						status := uint32(0)
						if err := cmd.Run(); err != nil {
							status = 1
						}
						_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
						break
					}
					_ = channel.Close()
				}
			}()
		}
	}()
	return listener.Addr().String(), host.PublicKey()
}
