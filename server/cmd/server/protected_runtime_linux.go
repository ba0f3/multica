//go:build linux

package main

import (
	"context"
	"fmt"
	"github.com/multica-ai/multica/server/internal/handler"
	"github.com/multica-ai/multica/server/internal/service"
)

// Operator configuration is deliberately absent until the real rollout gate.
// Startup exercises the same nil/disabled constructor as synthetic acceptance;
// no environment variable can opt this server into protected execution.
func startProtectedRuntime(ctx context.Context, h *handler.Handler) (func(), error) {
	worker, err := service.NewProtectedWorker(ctx, h.GitSecurity, nil)
	if err != nil {
		return nil, err
	}
	if worker != nil {
		_ = worker.Close()
		return nil, fmt.Errorf("protected runtime unexpectedly constructed")
	}
	return func() {}, nil
}
