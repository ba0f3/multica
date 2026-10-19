package main

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/multica-ai/multica/server/internal/r2dgit"
	"github.com/multica-ai/multica/server/internal/sourceguard"
	"os"
)

// Install before any relay, scheduler, analytics drain or legacy integration.
// A protected instance cannot boot the legacy worker graph. The selected
// protected deployment still requires separate explicit operator composition.
func sourceAuthority(pool *pgxpool.Pool, guard *r2dgit.RestoreGuard) *r2dgit.Service {
	// Route-only constructors have no data or worker graph. They must not
	// replace an already installed process policy with a typed nil pool.
	if pool == nil {
		return r2dgit.NewService(nil, nil)
	}
	s := r2dgit.NewService(pool, pool)
	if guard == nil {
		directory := os.Getenv("MULTICA_GIT_SOURCE_GUARD_DIR")
		expected := directory != ""
		if !expected {
			directory = "/var/lib/multica/git-source-guard"
		}
		guard = r2dgit.LoadSourceRestoreGuard(pool, directory, expected)
	}
	s.Store.Restore = guard
	sourceguard.Install(func(ctx context.Context) error {
		blocked, err := s.ReaderlessSourceBlocked(ctx)
		if err != nil {
			return err
		}
		if blocked {
			return sourceguard.ErrUnavailable
		}
		return nil
	})
	return s
}
