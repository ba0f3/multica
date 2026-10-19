//go:build linux

// protected-agent is an image entrypoint, not a host daemon or public CLI.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/multica-ai/multica/server/internal/r2dgit"
)

func run(ctx context.Context, args []string) (code int) {
	if enableChildReaper() != nil {
		return 1
	}
	defer func() {
		if drainAdoptedChildren(time.Second) != nil {
			code = 1
		}
	}()
	path := "/opt/multica/runtime.json"
	if len(args) != 0 {
		if len(args) != 2 || args[0] != "--config" {
			return 2
		}
		path = args[1]
	}
	config, err := r2dgit.ReadProtectedEntrypointConfig(path)
	if err != nil {
		return 2
	}
	if err := r2dgit.RunProtectedEntrypoint(ctx, config); err != nil {
		return 1
	}
	return 0
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:])
	stop()
	if code != 0 {
		fmt.Fprintln(os.Stderr, "protected_workload_unavailable")
	}
	os.Exit(code)
}
