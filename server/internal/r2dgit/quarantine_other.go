//go:build !linux

package r2dgit

import (
	"context"
	"os/exec"
)

func quarantineCommand(context.Context, string, ...string) (*exec.Cmd, error) { return nil, ErrRuntime }
