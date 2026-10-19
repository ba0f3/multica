//go:build !linux

package main

import (
	"context"
	"github.com/multica-ai/multica/server/internal/handler"
)

func startProtectedRuntime(context.Context, *handler.Handler) (func(), error) { return func() {}, nil }
