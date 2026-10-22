package agent

import (
	"errors"
	"testing"
)

func TestEnforceOpenCodeIsolatedLaunch(t *testing.T) {
	t.Run("rejects external server", func(t *testing.T) {
		_, err := enforceOpenCodeIsolatedLaunch([]string{"run", "--server", "http://127.0.0.1:1"}, true)
		if !errors.Is(err, ErrOpenCodeIsolatedExternalServer) {
			t.Fatalf("expected ErrOpenCodeIsolatedExternalServer, got %v", err)
		}
	})

	t.Run("injects standalone for v2", func(t *testing.T) {
		args, err := enforceOpenCodeIsolatedLaunch([]string{"run", "--format", "json"}, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, standalone := opencodeConnectionFromArgs(args); !standalone {
			t.Fatalf("expected --standalone in %v", args)
		}
	})

	t.Run("leaves v1 argv unchanged", func(t *testing.T) {
		in := []string{"run", "--format", "json"}
		args, err := enforceOpenCodeIsolatedLaunch(in, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(args) != len(in) {
			t.Fatalf("v1 args changed: %v", args)
		}
	})

	t.Run("preserves existing standalone", func(t *testing.T) {
		args, err := enforceOpenCodeIsolatedLaunch([]string{"run", "--standalone"}, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(args) != 2 {
			t.Fatalf("expected no duplicate standalone flag: %v", args)
		}
	})
}
