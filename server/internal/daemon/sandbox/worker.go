package sandbox

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"

	"github.com/multica-ai/multica/server/pkg/agent"
)

// ConfigFromAgent maps the daemon's backend config into the serializable form.
//
// The logger is deliberately not carried: the worker builds its own, writing
// to its stderr, because a *slog.Logger is a live object and cannot travel
// across the process boundary.
func ConfigFromAgent(cfg agent.Config) Config {
	return Config{
		ExecutablePath: cfg.ExecutablePath,
		LaunchPrefix:   append([]string(nil), cfg.LaunchPrefix...),
		CLIVersion:     cfg.CLIVersion,
		Env:            cfg.Env,
		TaskID:         cfg.TaskID,
		AttemptID:      cfg.AttemptID,
		RuntimeID:      cfg.RuntimeID,
		DaemonVersion:  cfg.DaemonVersion,
		CodexVersion:   cfg.CodexVersion,
		BuiltinRuntime: cfg.BuiltinRuntime,
	}
}

// RunWorker is the hidden entrypoint that runs inside the sandbox.
//
// It reads one manifest from stdin, runs the provider backend, and streams the
// transcript and the final result to stdout as frames. Every byte of the agent
// environment arrived in the manifest, so nothing about the task is visible in
// the process table.
func RunWorker(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	manifest, err := ReadManifest(stdin)
	if err != nil {
		return err
	}
	return runManifest(ctx, manifest, stdout, slog.New(slog.NewTextHandler(os.Stderr, nil)))
}

func runManifest(ctx context.Context, manifest Manifest, out io.Writer, logger *slog.Logger) error {
	backend, err := agent.ResolveBackend(manifest.Provider, agent.Config{
		ExecutablePath: manifest.Config.ExecutablePath,
		LaunchPrefix:   manifest.Config.LaunchPrefix,
		CLIVersion:     manifest.Config.CLIVersion,
		Env:            manifest.Config.Env,
		Logger:         logger,
		TaskID:         manifest.Config.TaskID,
		RuntimeID:      manifest.Config.RuntimeID,
		DaemonVersion:  manifest.Config.DaemonVersion,
		CodexVersion:   manifest.Config.CodexVersion,
		BuiltinRuntime: manifest.Config.BuiltinRuntime,
	})
	if err != nil {
		return WriteFrame(out, Frame{Type: FrameError, Error: "create agent backend: " + err.Error()})
	}

	session, err := backend.Execute(ctx, manifest.Prompt, manifest.Exec.ExecOptions())
	if err != nil {
		return WriteFrame(out, Frame{Type: FrameError, Error: err.Error()})
	}
	if session == nil || session.Result == nil {
		return WriteFrame(out, Frame{Type: FrameError, Error: "the backend returned no session"})
	}
	return streamWorkerSession(ctx, os.Stdin, out, session)
}

// errNoResult reports a worker that exited without reporting an outcome.
var errNoResult = errors.New("sandbox: the worker exited without a result")
