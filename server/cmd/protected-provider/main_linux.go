//go:build linux

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

func run(ctx context.Context, args []string) error {
	path := "/opt/multica/runtime.json"
	if len(args) == 3 && args[0] == "--multica-protected-v1" && args[1] == "--config" {
		path = args[2]
	} else if len(args) != 1 || args[0] != "--multica-protected-v1" {
		return r2dgit.ErrScope
	}
	c, err := r2dgit.ReadProtectedEntrypointConfig(path)
	if err != nil {
		return err
	}
	ctx, stop := context.WithTimeout(ctx, 25*time.Second)
	defer stop()
	return r2dgit.RunResponsesProvider(ctx, c.SocketPath, os.Stdin, os.Stdout)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:])
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "protected_provider_unavailable")
		os.Exit(1)
	}
}
