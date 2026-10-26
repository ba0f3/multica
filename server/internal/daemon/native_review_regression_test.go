//go:build linux

package daemon

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/daemon/execenv"
	"github.com/multica-ai/multica/server/pkg/agent"
)

func nativeReviewFixture(t *testing.T, provider, body string) (*Daemon, *execenv.Environment, string) {
	t.Helper()
	if os.Getenv("MULTICA_BWRAP_SMOKE") != "1" {
		t.Skip("set MULTICA_BWRAP_SMOKE=1 for fake-account native regression probes")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, key := range nativeSelectorKeys {
		t.Setenv(key, "")
	}
	d := &Daemon{logger: newDiscardLogger(), cfg: Config{SandboxEnabled: true, TaskSandboxBackend: "bwrap", WorkspacesRoot: filepath.Join(home, "tasks"), DockerMemoryBytes: 2 << 30, DockerPIDsLimit: 512, DockerNanoCPUs: 2e9}}
	exe := filepath.Join(home, ".local", "bin", provider)
	if err := os.MkdirAll(filepath.Dir(exe), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nprintf '9.0.0\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	worker := filepath.Join(t.TempDir(), "worker")
	script := "#!/usr/bin/python3\nimport json, os, sys, subprocess\nm = json.loads(sys.stdin.readline())\nos.environ.update(m['config']['env'])\nprint(json.dumps({'type':'worker_ready'}), flush=True)\n" + body + "\nprint(json.dumps({'type':'result','result':{'Status':'completed'}}), flush=True)\n"
	if err := os.WriteFile(worker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	d.cfg.SandboxSelfPath = worker
	return d, newSandboxTestEnv(t), exe
}

func runNativeReviewWorker(t *testing.T, d *Daemon, env *execenv.Environment, provider, exe, prompt string) {
	t.Helper()
	backend, err := d.sandboxedBackend(provider, agent.Config{ExecutablePath: exe}, env, "", "", "native-review", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	session, err := backend.Execute(ctx, prompt, agent.ExecOptions{Cwd: env.WorkDir})
	if err != nil {
		t.Fatal(err)
	}
	for range session.Messages {
	}
	result := <-session.Result
	if result.Status != "completed" {
		t.Fatalf("native regression worker: status=%s error=%s", result.Status, result.Error)
	}
}

func TestNativeStandaloneHostViewKeepsOtherProfilesReadOnly(t *testing.T) {
	d, env, exe := nativeReviewFixture(t, "codex", `import errno
path = os.path.join(os.environ['HOME'], '.local/share/opencode/auth.json')
assert open(path).read() == 'other-provider-secret'
try:
    open(path, 'w')
except OSError as error:
    assert error.errno == errno.EROFS
else:
    raise AssertionError('the unrelated provider profile is writable')
assert subprocess.check_output([m['config']['executable_path'], '--version']).strip() == b'9.0.0'`)
	secret := filepath.Join(os.Getenv("HOME"), ".local", "share", "opencode", "auth.json")
	if err := os.MkdirAll(filepath.Dir(secret), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("other-provider-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	runNativeReviewWorker(t, d, env, "codex", exe, "check the boundary")
	data, err := os.ReadFile(secret)
	if err != nil || string(data) != "other-provider-secret" {
		t.Fatalf("host provider state changed: %q, %v", data, err)
	}
}

func TestNativeUniversalSkillAndProviderLinkRemainVisible(t *testing.T) {
	d, env, exe := nativeReviewFixture(t, "codex", `root = os.environ['HOME']
assert open(os.path.join(root, '.agents/skills/shared/SKILL.md')).read() == 'universal-skill'
assert open(os.path.join(os.environ['CODEX_HOME'], 'skills/linked/SKILL.md')).read() == 'universal-skill'
try:
    open(os.path.join(root, '.agents/skills/shared/SKILL.md'), 'w')
except OSError as error:
    import errno
    assert error.errno in [errno.EROFS, errno.EACCES, errno.EPERM]
else:
    raise AssertionError('universal inputs are writable')`)
	home := os.Getenv("HOME")
	universal := filepath.Join(home, ".agents", "skills", "shared")
	provider := filepath.Join(home, ".codex", "skills")
	for _, dir := range []string{universal, provider} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(universal, "SKILL.md"), []byte("universal-skill"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(universal, filepath.Join(provider, "linked")); err != nil {
		t.Fatal(err)
	}
	runNativeReviewWorker(t, d, env, "codex", exe, "read authorized native instructions")
}

func TestNativeWorkerCachesSupportOfflineBuildTools(t *testing.T) {
	for _, tool := range []string{"npm", "go"} {
		t.Run(tool, func(t *testing.T) {
			body := ""
			if tool == "npm" {
				if _, err := os.Stat("/usr/bin/npm"); err != nil {
					t.Skip("system npm is required for the offline package probe")
				}
				body = `os.mkdir('app')
open('/tmp/user-npmrc', 'w').close()
open('/tmp/global-npmrc', 'w').close()
subprocess.run(['/usr/bin/npm', 'install', os.path.abspath('fixture.tgz'), '--prefix', os.path.abspath('app'), '--userconfig', '/tmp/user-npmrc', '--globalconfig', '/tmp/global-npmrc', '--ignore-scripts', '--offline', '--no-audit', '--no-fund'], check=True, stdout=sys.stderr)
assert os.path.isfile('app/node_modules/native-cache-fixture/package.json')`
			} else {
				if _, err := exec.LookPath("go"); err != nil {
					t.Skip("Go is required for the dependency-free build probe")
				}
				body = `subprocess.run(['go', 'build', '-o', 'hello', 'hello.go'], check=True)
assert os.path.isfile('hello')`
			}
			d, env, exe := nativeReviewFixture(t, "opencode", body)
			if tool == "npm" {
				var buffer bytes.Buffer
				gzipWriter := gzip.NewWriter(&buffer)
				tarWriter := tar.NewWriter(gzipWriter)
				data := []byte(`{"name":"native-cache-fixture","version":"1.0.0"}`)
				if err := tarWriter.WriteHeader(&tar.Header{Name: "package/package.json", Mode: 0600, Size: int64(len(data))}); err != nil {
					t.Fatal(err)
				}
				_, _ = tarWriter.Write(data)
				_ = tarWriter.Close()
				_ = gzipWriter.Close()
				if err := os.WriteFile(filepath.Join(env.WorkDir, "fixture.tgz"), buffer.Bytes(), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(filepath.Join(env.WorkDir, "hello.go"), []byte("package main\nfunc main() {}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			runNativeReviewWorker(t, d, env, "opencode", exe, "build only local fixture inputs")
			for _, path := range []string{filepath.Join(os.Getenv("HOME"), ".npm"), filepath.Join(os.Getenv("HOME"), ".cache", "go-build"), filepath.Join(os.Getenv("HOME"), "go")} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Errorf("tool changed host-home cache %s: %v", path, err)
				}
			}
		})
	}
}

func TestNativeOriginalEnvInterpreterProbeAndWorker(t *testing.T) {
	d, env, exe := nativeReviewFixture(t, "opencode", `assert subprocess.check_output([m['config']['executable_path'], '--version']).strip().decode() == m['prompt']`)
	if err := os.WriteFile(exe, []byte("#!/usr/bin/env node\n// interpreted by the selected fake Node\n"), 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(os.Getenv("HOME"), "nodes")
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(bin, "node")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	for _, version := range []string{"2.1.4", "2.2.0"} {
		node := filepath.Join(root, "node-"+version)
		if err := os.WriteFile(node, []byte("#!/bin/sh\nprintf '"+version+"\\n'\n"), 0700); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(link)
		if err := os.Symlink(node, link); err != nil {
			t.Fatal(err)
		}
		runtime, _, err := d.nativeRuntime(t.Context(), "opencode", exe)
		if err != nil || runtime.Version != version {
			t.Fatalf("original interpreter probe after upgrade: version=%s expected=%s err=%v", runtime.Version, version, err)
		}
		runNativeReviewWorker(t, d, env, "opencode", exe, version)
	}
}

func TestNativeWorkerReceivesPrivateCA(t *testing.T) {
	d, env, exe := nativeReviewFixture(t, "opencode", `import urllib.request
with urllib.request.urlopen(m['prompt'], timeout=10) as response:
    assert response.read() == b'private-ca-artifact'
for key in ['GIT_SSL_CAINFO', 'SSL_CERT_FILE', 'CURL_CA_BUNDLE', 'NODE_EXTRA_CA_CERTS', 'REQUESTS_CA_BUNDLE']:
    assert os.path.isfile(os.environ[key])
try:
    open(os.environ['SSL_CERT_FILE'], 'a').write('forbidden')
except OSError as error:
    import errno
    assert error.errno in [errno.EROFS, errno.EACCES, errno.EPERM]
else:
    raise AssertionError('CA bundle is writable')`)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("private-ca-artifact")) }))
	defer server.Close()
	env.WorkerCABundlePath = filepath.Join(env.RootDir, "worker-ca.pem")
	if err := os.WriteFile(env.WorkerCABundlePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	runNativeReviewWorker(t, d, env, "opencode", exe, server.URL)
}

func TestNativeAttemptStorageIsRemovedAndOutputRetained(t *testing.T) {
	for _, mode := range []string{"result", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			body := `open('/tmp/temporary-sentinel', 'wb').write(b'x' * 1048576)
open('/workspace/output/durable-output', 'w').write('keep')`
			if mode == "cancel" {
				body += "\nimport time\ntime.sleep(60)"
			}
			d, env, exe := nativeReviewFixture(t, "opencode", body)
			backend, err := d.sandboxedBackend("opencode", agent.Config{ExecutablePath: exe}, env, "", "", "native-storage-"+mode, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			session, err := backend.Execute(ctx, "write private state", agent.ExecOptions{Cwd: env.WorkDir})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "cancel" {
				deadline := time.Now().Add(5 * time.Second)
				for {
					files, _ := filepath.Glob(filepath.Join(env.RootDir, "native-attempt-*", "tmp", "temporary-sentinel"))
					if len(files) > 0 {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("worker did not write its private temporary file")
					}
					time.Sleep(10 * time.Millisecond)
				}
				cancel()
			}
			for range session.Messages {
			}
			<-session.Result
			if roots, _ := filepath.Glob(filepath.Join(env.RootDir, "native-attempt-*")); len(roots) != 0 {
				t.Fatalf("attempt temporary state survived completion: %v", roots)
			}
			found := false
			_ = filepath.WalkDir(env.RootDir, func(path string, entry os.DirEntry, err error) error {
				if err == nil && !entry.IsDir() && entry.Name() == "durable-output" {
					data, _ := os.ReadFile(path)
					found = string(data) == "keep"
				}
				return nil
			})
			if !found {
				t.Fatal("attempt cleanup removed durable output")
			}
		})
	}
}

func TestNativePreparationFailureDoesNotRetainAttemptStorage(t *testing.T) {
	d, env, exe := nativeReviewFixture(t, "opencode", "pass")
	backend, err := d.sandboxedBackend("opencode", agent.Config{ExecutablePath: exe}, env, "", filepath.Join(env.RootDir, "missing-agent.sock"), "native-prepare-failed", nil, nil)
	if err == nil {
		_, err = backend.Execute(t.Context(), "must fail preparation", agent.ExecOptions{})
	}
	if err == nil || !strings.Contains(err.Error(), "accessible") {
		t.Fatalf("missing signing socket was not rejected: %v", err)
	}
	if roots, _ := filepath.Glob(filepath.Join(env.RootDir, "native-attempt-*")); len(roots) != 0 {
		t.Fatalf("failed preparation leaked private state: %v", roots)
	}
}
