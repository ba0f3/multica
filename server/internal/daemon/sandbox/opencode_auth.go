package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const OpenCodeCredentialsPath = "/run/multica/opencode-credentials.json"
const OpenCodeCredentialsEnv = "MULTICA_OPENCODE_CREDENTIALS_FILE"

func importWorkerOpenCodeCredentials(ctx context.Context, manifest Manifest) error {
	path := manifest.Config.Env[OpenCodeCredentialsEnv]
	if manifest.Provider != "opencode" || path == "" {
		return nil
	}
	input, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open worker OpenCode credentials: %w", err)
	}
	defer input.Close()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, manifest.Config.ExecutablePath, "auth", "import", "--standalone")
	cmd.WaitDelay = 2 * time.Second
	cmd.Stdin = input
	cmd.Env = os.Environ()
	for key, value := range manifest.Config.Env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	// Auth output may contain secrets. Only report the operation's outcome.
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("import OpenCode credentials in worker failed; check OpenCode login on the daemon host (timeout=%t)", ctx.Err() != nil)
	}
	return nil
}
