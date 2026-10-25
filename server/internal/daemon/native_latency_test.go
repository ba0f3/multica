//go:build linux

package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/pkg/agent"
)

// This probe uses test-created scripts and a private fake profile. It never
// resolves an installed provider or reads the current user's agent account.
func TestNativeWarmWorkerLaunchLatency(t *testing.T) {
	if os.Getenv("MULTICA_BWRAP_SMOKE") != "1" {
		t.Skip("set MULTICA_BWRAP_SMOKE=1 for 100 production-launcher kernel probes")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, key := range nativeSelectorKeys {
		t.Setenv(key, "")
	}
	d := &Daemon{logger: newDiscardLogger(), cfg: Config{SandboxEnabled: true, TaskSandboxBackend: "bwrap", WorkspacesRoot: filepath.Join(home, "tasks"), DockerMemoryBytes: 256 << 20, DockerPIDsLimit: 32, DockerNanoCPUs: 500000000}}
	exe := filepath.Join(home, "installation", "bin", "opencode")
	if err := os.MkdirAll(filepath.Dir(exe), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nprintf '2.1.4\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	worker := filepath.Join(home, "fake-worker")
	script := `#!/bin/sh
set -eu
read manifest
printf '%s\n' '{"type":"worker_ready"}'
printf 'native-latency-artifact' > ./artifact
printf '%s\n' '{"type":"result","result":{"Status":"completed"}}'
`
	if err := os.WriteFile(worker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	d.cfg.SandboxSelfPath = worker
	env := newSandboxTestEnv(t)
	var samples []time.Duration
	// The first attempt primes resolver, resource preflight and worker pages.
	for i := range 101 {
		attempt := fmt.Sprintf("native-latency-%d-%d", os.Getpid(), i)
		backend, err := d.sandboxedBackend("opencode", agent.Config{ExecutablePath: exe, TaskID: attempt}, env, "", "", attempt, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		native := backend.(*nativeAttemptBackend)
		var started time.Time
		var elapsed time.Duration
		native.onSpawn = func() { started = time.Now() }
		native.worker.OnWorkerReady = func() { elapsed = time.Since(started) }
		session, err := backend.Execute(t.Context(), "fake worker", agent.ExecOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for range session.Messages {
		}
		result := <-session.Result
		if result.Status != "completed" || elapsed <= 0 {
			t.Fatalf("attempt %d status=%s readiness=%s error=%s", i, result.Status, elapsed, result.Error)
		}
		artifact := filepath.Join(env.WorkDir, "artifact")
		data, err := os.ReadFile(artifact)
		if err != nil || string(data) != "native-latency-artifact" {
			t.Fatalf("attempt %d artifact=%q read=%v", i, data, err)
		}
		if err := os.Remove(artifact); err != nil {
			t.Fatal(err)
		}
		state, err := exec.Command("systemctl", "--user", "show", "multica-"+attempt+".scope", "--property=ActiveState", "--value").CombinedOutput()
		value := strings.TrimSpace(string(state))
		if value == "active" || value == "activating" || value == "deactivating" || (err != nil && value != "" && !strings.Contains(value, "not found")) {
			t.Fatalf("attempt %d scope survived completion: %q, %v", i, value, err)
		}
		if i > 0 {
			samples = append(samples, elapsed)
		}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	p95 := samples[94]
	t.Logf("warm attempts=%d sandbox_launch p50=%s p95=%s max=%s", len(samples), samples[49], p95, samples[99])
	if p95 > 250*time.Millisecond {
		t.Fatalf("warm worker-ready p95 %s exceeds 250ms", p95)
	}
}
