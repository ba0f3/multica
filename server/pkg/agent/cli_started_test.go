package agent

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestCLIStartedFourProvidersReportSuccessfulSpawnOnly(t *testing.T) {
	for _, provider := range []string{"codex", "cursor", "opencode", "mcode"} {
		for _, valid := range []bool{false, true} {
			t.Run(provider+map[bool]string{true: "/started", false: "/failed"}[valid], func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "fake-cli")
				script := "#!/missing/interpreter\n"
				if valid {
					script = "#!/bin/sh\ncat >/dev/null\nexit 0\n"
				}
				if err := os.WriteFile(path, []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
				cfg := Config{ExecutablePath: path, CLIVersion: "2.1.4", CodexVersion: "0.163.0", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
				backend, err := New(provider, cfg)
				if err != nil {
					t.Fatal(err)
				}
				var calls atomic.Int32
				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				session, _ := backend.Execute(ctx, "hello", ExecOptions{Cwd: t.TempDir(), OnCLIStarted: func() { calls.Add(1) }})
				if session != nil {
					for range session.Messages {
					}
					<-session.Result
				}
				want := int32(0)
				if valid {
					want = 1
				}
				if got := calls.Load(); got != want {
					t.Fatalf("CLI spawn callbacks=%d, want %d", got, want)
				}
			})
		}
	}
}
