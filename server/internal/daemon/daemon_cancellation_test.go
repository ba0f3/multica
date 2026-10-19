package daemon

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/multica-ai/multica/server/pkg/agent"
)

func TestExecuteAndDrain_ReadyResultKeepsUpstreamCancellation(t *testing.T) {
	d := newTestDaemon(t)
	for _, authoritative := range []bool{false, true} {
		name := "cancellation_result"
		if authoritative {
			name = "observed_provider_failure"
		}
		t.Run(name, func(t *testing.T) {
			// A backend can finish cancellation before Execute hands back its
			// session. Both select cases must classify the same ready result.
			for i := 0; i < 64; i++ {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				messages := make(chan agent.Message)
				close(messages)
				results := make(chan agent.Result, 1)
				result := agent.Result{Status: "aborted", Error: "execution cancelled"}
				if authoritative {
					result = agent.Result{Status: "failed", Error: "provider rejected request"}
				}
				results <- result
				close(results)
				backend := sessionBackend{session: &agent.Session{
					Messages: messages, Result: results,
					TerminalObserved: func() bool { return authoritative },
				}}
				got, _, err := d.executeAndDrain(ctx, backend, "p", agent.ExecOptions{}, slog.Default(), "ready-cancel", "", new(atomic.Int32))
				if err != nil {
					t.Fatalf("executeAndDrain: %v", err)
				}
				if authoritative {
					if got.Status != result.Status || got.Error != result.Error {
						t.Fatalf("iteration %d: observed provider result changed: %+v", i, got)
					}
				} else if got.Status != "cancelled" || !strings.Contains(got.Error, "task cancelled by upstream context") {
					t.Fatalf("iteration %d: %+v, want upstream cancellation", i, got)
				}
			}
		})
	}
}
