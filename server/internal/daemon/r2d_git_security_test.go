package daemon

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/pkg/protocol"
)

func TestProtectedGitRejectedBeforeRunnerOrPreparation(t *testing.T) {
	for _, version := range []string{"r2d-git-security-v1", "unknown-future-version"} {
		t.Run(version, func(t *testing.T) {
			var runnerCalled atomic.Bool
			var failures atomic.Int64
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/fail") {
					failures.Add(1)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			defer srv.Close()
			d := &Daemon{client: NewClient(srv.URL), logger: slog.New(slog.NewTextHandler(io.Discard, nil)), workspaces: make(map[string]*workspaceState), runtimeIndex: map[string]Runtime{"rt": {ID: "rt", Provider: "claude"}}, activeEnvRoots: make(map[string]int), cancelPollInterval: time.Hour}
			d.runner = taskRunnerFunc(func(context.Context, Task, string, int, *slog.Logger) (TaskResult, error) {
				runnerCalled.Store(true)
				return TaskResult{Status: "completed"}, nil
			})
			var task Task
			wire := `{"id":"task","workspace_id":"ws","runtime_id":"rt","agent_id":"agent","agent":{"id":"agent"},"required_git_security":"` + version + `"}`
			if err := json.Unmarshal([]byte(wire), &task); err != nil {
				t.Fatal(err)
			}
			d.handleTask(context.Background(), task, 0)
			if runnerCalled.Load() {
				t.Fatal("protected request reached ambient runner")
			}
			if failures.Load() != 1 {
				t.Fatalf("failure callbacks = %d, want 1", failures.Load())
			}
		})
	}
}

func TestProtectedGitNotAdvertisedAndDirectRunRefused(t *testing.T) {
	for _, capabilities := range []string{daemonClientCapabilities(), daemonHTTPClientCapabilities()} {
		for _, capability := range strings.Split(capabilities, ",") {
			if capability == protocol.DaemonCapabilityR2DGitSecurityV1 {
				t.Fatal("ambient daemon advertised protected execution support")
			}
		}
	}
	d := &Daemon{}
	_, err := d.runTask(context.Background(), Task{RequiredGitSecurity: protocol.DaemonCapabilityR2DGitSecurityV1}, "missing-fake-cli", 0, slog.Default())
	if err != errProtectedGitUnsupported {
		t.Fatalf("direct run reached preparation: %v", err)
	}
	if reason := taskRunFailureReason(err); reason != "runtime_access_denied" {
		t.Fatalf("failure reason = %q", reason)
	}
}
